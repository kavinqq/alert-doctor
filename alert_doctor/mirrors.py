"""Read-only snapshots of each configured repo's deploy_ref, switched atomically per SHA.

The source is the user's own clone: `git fetch` moves only remote-tracking refs and
`git archive` reads objects, so the working tree, current branch and uncommitted changes
are never touched, and nothing is cloned or registered as a worktree there.

Layout under `mirrors_dir`:
  <id>/<sha>/         exported tree (chmod a-w), never modified once published
  <id>/current        symlink to the newest `<sha>`; swapped with os.replace
"""
from __future__ import annotations

import fcntl
import io
import logging
import os
import re
import shutil
import stat
import subprocess
import tarfile
import time
from contextlib import contextmanager

log = logging.getLogger(__name__)

KEEP_CHECKOUTS = 3
_SHA_DIR = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_TMP_PREFIX = ".tmp-"
STAGING_GRACE_SECONDS = 3600


def _git(run, *args: str, timeout: int = 600) -> str:
    done = run(["git", *args], capture_output=True, text=True, timeout=timeout)
    if done.returncode != 0:
        raise RuntimeError(f"git {args[0] if args[0] != '-C' else args[2]} 失敗:{(done.stderr or '')[-300:]}")
    return done.stdout


def _set_writable(path: str) -> None:
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                os.chmod(full, os.stat(full).st_mode | stat.S_IWUSR)
    os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)


def _set_read_only(path: str) -> None:
    mask = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                os.chmod(full, os.stat(full).st_mode & mask)
    os.chmod(path, os.stat(path).st_mode & mask)


def _remove_tree(path: str) -> None:
    if not os.path.lexists(path):
        return
    _set_writable(path)
    shutil.rmtree(path, ignore_errors=True)


def _fetch(repo, run) -> None:
    # Offline (VPN down) is not fatal: the last fetched refs are still a valid snapshot.
    try:
        _git(run, "-C", repo.path, "fetch", "--quiet", "origin")
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        log.warning("fetch failed for %s, using existing refs: %s", repo.id, exc)


def _export(repo, sha: str, dest: str, run) -> None:
    done = run(["git", "-C", repo.path, "archive", "--format=tar", sha],
               capture_output=True, timeout=600)
    if done.returncode != 0:
        err = done.stderr.decode(errors="replace") if isinstance(done.stderr, bytes) else done.stderr
        raise RuntimeError(f"git archive 失敗:{(err or '')[-300:]}")
    with tarfile.open(fileobj=io.BytesIO(done.stdout), mode="r:") as tar:
        tar.extractall(dest, filter="data")


def _publish_snapshot(repo, repo_dir: str, sha: str, run) -> str:
    target = os.path.join(repo_dir, sha)
    if os.path.isdir(target):
        # A crash between rename and chmod would leave a writable tree; re-applying is idempotent.
        _set_read_only(target)
        return target
    os.makedirs(repo_dir, exist_ok=True)
    staging = os.path.join(repo_dir, f"{_TMP_PREFIX}{sha[:12]}-{os.getpid()}")
    _remove_tree(staging)
    try:
        os.makedirs(staging)
        _export(repo, sha, staging, run)
        _set_read_only(staging)
        os.rename(staging, target)
    except BaseException:
        _remove_tree(staging)
        raise
    return target


def _switch_current(repo_dir: str, sha: str) -> None:
    link = os.path.join(repo_dir, "current")
    staging = os.path.join(repo_dir, f"{_TMP_PREFIX}link-{os.getpid()}")
    if os.path.lexists(staging):
        os.remove(staging)
    os.symlink(sha, staging)
    os.replace(staging, link)


def _prune_old(repo_dir: str, keep_sha: str) -> None:
    candidates = [n for n in os.listdir(repo_dir)
                  if _SHA_DIR.match(n) and os.path.isdir(os.path.join(repo_dir, n))]
    candidates.sort(key=lambda n: (os.stat(os.path.join(repo_dir, n)).st_mtime, n), reverse=True)
    keep = set(candidates[:KEEP_CHECKOUTS]) | {keep_sha}
    for name in candidates:
        if name not in keep:
            _remove_tree(os.path.join(repo_dir, name))
    # The per-repo lock already serialises our own refreshes; the age guard protects a
    # staging dir from an older build that did not take the lock.
    cutoff = time.time() - STAGING_GRACE_SECONDS
    for name in os.listdir(repo_dir):
        path = os.path.join(repo_dir, name)
        if (name.startswith(_TMP_PREFIX) and name != f"{_TMP_PREFIX}link-{os.getpid()}"
                and os.lstat(path).st_mtime < cutoff):
            _remove_tree(path)


@contextmanager
def _repo_lock(mirrors_dir: str, repo_id: str):
    """The analyzer loop and the CLI may refresh the same repo at once."""
    os.makedirs(mirrors_dir, exist_ok=True)
    with open(os.path.join(mirrors_dir, f"{repo_id}.lock"), "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _refresh(repo, mirrors_dir: str, run) -> tuple[tuple[str, str] | None, str, str]:
    """(checkout before, path, sha), all observed under the repo lock."""
    mirrors_dir = os.path.abspath(mirrors_dir)
    with _repo_lock(mirrors_dir, repo.id):
        before = current(repo.id, mirrors_dir)
        repo_dir = os.path.join(mirrors_dir, repo.id)
        _fetch(repo, run)
        sha = _git(run, "-C", repo.path, "rev-parse", "--verify",
                   f"{repo.deploy_ref}^{{commit}}").strip()
        target = _publish_snapshot(repo, repo_dir, sha, run)
        _switch_current(repo_dir, sha)
        _prune_old(repo_dir, sha)
        return before, target, sha


def refresh(repo, mirrors_dir: str, run=subprocess.run) -> tuple[str, str]:
    """Fetch `repo`, publish a read-only snapshot of its deploy_ref, return (path, sha).

    Readers holding an older `<sha>` path keep a complete tree; only the `current`
    symlink moves, and it moves atomically. Refreshes of one repo are serialised
    across processes by `<mirrors_dir>/<id>.lock`.
    """
    _, target, sha = _refresh(repo, mirrors_dir, run)
    return target, sha


def current(repo_id: str, mirrors_dir: str) -> tuple[str, str] | None:
    link = os.path.join(os.path.abspath(mirrors_dir), repo_id, "current")
    if not os.path.islink(link):
        return None
    target = os.readlink(link)
    path = os.path.join(os.path.dirname(link), target)
    if not os.path.isdir(path):
        return None
    return path, os.path.basename(target)


def refresh_all(cfg, run=subprocess.run, on_change=None) -> dict[str, tuple[str, str]]:
    """Refresh every repo; one failing repo does not stop the others.

    `on_change(repo_id, old_sha, new_sha)` runs when a repo's published SHA moved (not on
    its first checkout); its failure is logged and does not undo the refresh.
    """
    results = {}
    for repo in cfg.repos.values():
        try:
            before, path, sha = _refresh(repo, cfg.mirrors_dir, run)
            results[repo.id] = (path, sha)
        except Exception as exc:
            log.error("mirror refresh failed for %s: %s", repo.id, exc)
            continue
        new_sha = results[repo.id][1]
        if on_change is not None and before is not None and before[1] != new_sha:
            try:
                on_change(repo.id, before[1], new_sha)
            except Exception as exc:
                log.error("SHA 變更處理失敗 %s: %s", repo.id, exc)
    return results
