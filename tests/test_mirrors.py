import fcntl
import io
import os
import tarfile
import stat
import time
import tempfile
import unittest
from types import SimpleNamespace

from alert_doctor import mirrors
from alert_doctor.config import Config, ChannelSpec, RepoSpec

SHA1 = "a" * 40
SHA2 = "b" * 40


def _writable(path):
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                os.chmod(full, os.stat(full).st_mode | stat.S_IWUSR)
    if os.path.exists(path):
        os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)


def _tar_bytes():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = b"x = 1\n"
        info = tarfile.TarInfo("sub/f.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeGit:
    """Stands in for `git` run against the user's local repo."""

    def __init__(self, sha=SHA1, fail_on=None):
        self.sha, self.fail_on, self.calls = sha, fail_on, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        joined = " ".join(cmd)
        if self.fail_on and self.fail_on in joined:
            return SimpleNamespace(returncode=1, stdout="", stderr="boom")
        out = ""
        if "rev-parse" in joined:
            out = self.sha + "\n"
        elif "archive" in cmd:
            return SimpleNamespace(returncode=0, stdout=_tar_bytes(), stderr=b"")
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    def cmds(self, needle):
        return [c for c in self.calls if needle in " ".join(c)]


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: _writable(self.tmp.name))
        self.dir = os.path.join(self.tmp.name, "mirrors")
        self.repo = RepoSpec("r", "/src/r", "origin/HEAD")

    def test_snapshots_from_the_local_repo_without_cloning_or_worktrees(self):
        git = FakeGit()
        path, sha = mirrors.refresh(self.repo, self.dir, git)
        self.assertEqual(sha, SHA1)
        self.assertEqual(path, os.path.join(self.dir, "r", SHA1))
        self.assertEqual(git.calls[0], ["git", "-C", "/src/r", "fetch", "--quiet", "origin"])
        self.assertEqual(git.cmds("archive")[0], ["git", "-C", "/src/r", "archive", "--format=tar", SHA1])
        for forbidden in ("clone", "worktree", "checkout", "reset", "stash"):
            self.assertEqual(git.cmds(forbidden), [], forbidden)

    def test_fetch_failure_still_snapshots_known_refs(self):
        git = FakeGit(fail_on="fetch")
        path, sha = mirrors.refresh(self.repo, self.dir, git)
        self.assertEqual(sha, SHA1)
        self.assertTrue(os.path.exists(os.path.join(path, "sub", "f.py")))

    def test_deploy_ref_mapping(self):
        for ref in ("origin/HEAD", "origin/master", "v1.2"):
            git = FakeGit()
            mirrors.refresh(RepoSpec("r", "/src/r", ref), self.dir, git)
            self.assertEqual(git.cmds("rev-parse")[0][-1], f"{ref}^{{commit}}")

    def test_checkout_is_read_only_and_current_points_to_it(self):
        path, sha = mirrors.refresh(self.repo, self.dir, FakeGit())
        self.assertEqual(mirrors.current("r", self.dir), (path, SHA1))
        if os.geteuid() != 0:
            with self.assertRaises(PermissionError):
                open(os.path.join(path, "sub", "new.py"), "w")
            with self.assertRaises(PermissionError):
                open(os.path.join(path, "sub", "f.py"), "w")
            with self.assertRaises(PermissionError):
                open(os.path.join(path, "new.py"), "w")
        with open(os.path.join(path, "sub", "f.py")) as f:
            self.assertEqual(f.read(), "x = 1\n")

    def test_switch_is_atomic_and_old_checkout_stays_intact(self):
        git = FakeGit(SHA1)
        old_path, _ = mirrors.refresh(self.repo, self.dir, git)
        git.sha = SHA2
        new_path, _ = mirrors.refresh(self.repo, self.dir, git)
        self.assertEqual(mirrors.current("r", self.dir), (new_path, SHA2))
        self.assertTrue(os.path.exists(os.path.join(old_path, "sub", "f.py")))
        leftovers = [n for n in os.listdir(os.path.join(self.dir, "r")) if n.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_same_sha_does_not_recreate_checkout(self):
        git = FakeGit()
        mirrors.refresh(self.repo, self.dir, git)
        mirrors.refresh(self.repo, self.dir, git)
        self.assertEqual(len(git.cmds("archive")), 1)

    def test_keeps_only_three_newest_old_checkouts_and_deletes_read_only_dirs(self):
        git = FakeGit()
        shas = [c * 40 for c in "12345"]
        for i, sha in enumerate(shas):
            git.sha = sha
            mirrors.refresh(self.repo, self.dir, git)
            os.utime(os.path.join(self.dir, "r", sha), (1000 + i, 1000 + i))
        git.sha = shas[-1]
        mirrors.refresh(self.repo, self.dir, git)
        left = sorted(n for n in os.listdir(os.path.join(self.dir, "r")) if n != "current")
        self.assertEqual(left, sorted(shas[-3:]))

    def test_git_failure_leaves_current_untouched_and_no_staging(self):
        git = FakeGit(SHA1)
        path, _ = mirrors.refresh(self.repo, self.dir, git)
        failing = FakeGit(SHA2, fail_on="archive")
        with self.assertRaises(RuntimeError):
            mirrors.refresh(self.repo, self.dir, failing)
        self.assertEqual(mirrors.current("r", self.dir), (path, SHA1))

    def test_current_missing_returns_none(self):
        self.assertIsNone(mirrors.current("r", self.dir))
        os.makedirs(os.path.join(self.dir, "r"))
        os.symlink(SHA1, os.path.join(self.dir, "r", "current"))
        self.assertIsNone(mirrors.current("r", self.dir))


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: _writable(self.tmp.name))
        self.dir = os.path.join(self.tmp.name, "mirrors")
        self.repo = RepoSpec("r", "/src/r", "origin/HEAD")

    def test_refresh_holds_per_repo_lock_while_working(self):
        lock_path = os.path.join(self.dir, "r.lock")
        held = []
        inner = FakeGit()

        def git(cmd, **kw):
            if "rev-parse" in " ".join(cmd):
                with open(lock_path, "a") as f:
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        held.append(False)
                    except BlockingIOError:
                        held.append(True)
            return inner(cmd, **kw)
        mirrors.refresh(self.repo, self.dir, git)
        self.assertEqual(held, [True])
        with open(lock_path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_prune_keeps_young_staging_dirs_of_other_processes(self):
        git = FakeGit()
        repo_dir = os.path.join(self.dir, "r")
        os.makedirs(repo_dir)
        young = os.path.join(repo_dir, ".tmp-young-99999")
        old = os.path.join(repo_dir, ".tmp-old-99998")
        os.makedirs(young)
        os.makedirs(old)
        two_hours_ago = time.time() - 7200
        os.utime(old, (two_hours_ago, two_hours_ago))
        mirrors.refresh(self.repo, self.dir, git)
        self.assertTrue(os.path.isdir(young))
        self.assertFalse(os.path.exists(old))


class RefreshAllTests(unittest.TestCase):
    def test_one_failure_does_not_block_others(self):
        with tempfile.TemporaryDirectory() as d:
            self.addCleanup(lambda: _writable(d))
            cfg = Config(workspace_url="https://x", channels=(ChannelSpec("C", "n", ("s",)),),
                         mirrors_dir=d,
                         repos={"bad": RepoSpec("bad", "/src/bad"), "ok": RepoSpec("ok", "/src/ok")})

            def run(cmd, **kw):
                if "/src/bad" in cmd:
                    return SimpleNamespace(returncode=1, stdout="", stderr="nope")
                return FakeGit()(cmd, **kw)

            result = mirrors.refresh_all(cfg, run)
        self.assertEqual(list(result), ["ok"])


    def test_on_change_only_when_sha_moves(self):
        with tempfile.TemporaryDirectory() as d:
            self.addCleanup(lambda: _writable(d))
            cfg = Config(workspace_url="https://x", channels=(ChannelSpec("C", "n", ("s",)),),
                         mirrors_dir=d, repos={"r": RepoSpec("r", "/src/r")})
            git = FakeGit(SHA1)
            changes = []
            on_change = lambda *a: changes.append(a)  # noqa: E731
            mirrors.refresh_all(cfg, git, on_change=on_change)
            mirrors.refresh_all(cfg, git, on_change=on_change)
            git.sha = SHA2
            mirrors.refresh_all(cfg, git, on_change=on_change)
        self.assertEqual(changes, [("r", SHA1, SHA2)])

    def test_on_change_failure_does_not_break_refresh(self):
        with tempfile.TemporaryDirectory() as d:
            self.addCleanup(lambda: _writable(d))
            cfg = Config(workspace_url="https://x", channels=(ChannelSpec("C", "n", ("s",)),),
                         mirrors_dir=d, repos={"r": RepoSpec("r", "/src/r")})
            git = FakeGit(SHA1)
            mirrors.refresh_all(cfg, git)
            git.sha = SHA2

            def boom(*a):
                raise RuntimeError("db locked")
            with self.assertLogs("alert_doctor.mirrors", "ERROR"):
                result = mirrors.refresh_all(cfg, git, on_change=boom)
        self.assertEqual(result["r"][1], SHA2)


if __name__ == "__main__":
    unittest.main()
