from __future__ import annotations

import fcntl
import glob
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alert_doctor import autorules, known, known_store, mentions, mirrors, purge, replies, schema
from alert_doctor.checks import lookup_check
from alert_doctor.models import SEVERITY_REACTION, CheckSpec, Incident, ParsedAlert, Reaction

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = PROJECT_ROOT / "prompts" / "analyze.md"
DEFAULT_SNAPSHOT_PATH = "watchdog_snapshot/tasks.json"
# A first report stuck longer than this (outbox failing, pre-v3 incident) must not hold the
# analyzer queue hostage: claim_incident always hands back the lowest pending id.
REPORT_WAIT_SECONDS = 300
REPORT_RETRY_SECONDS = 30
CLI_DIRS = ("~/.local/bin", "/usr/local/bin", "/opt/homebrew/bin")
TAIPEI = timezone(timedelta(hours=8))
CATEGORIES = {"noise", "transient", "code_bug", "infra", "external_dependency", "config", "unknown"}
SEVERITIES = {"low", "medium", "high", "critical"}
ESCALATION_CONFIDENCE = 0.6
LOOP_SECONDS = 30
NO_REPO_NOTE = "(沒有可讀的 repo checkout;不可引用 code 類證據)"
UNHEALTHY_CATEGORIES = {"code_bug", "infra", "config", "external_dependency"}
UNKNOWN_SYSTEM = "unknown"
MIRROR_REFRESH_SECONDS = 600
ELK_RESULTS_FILE = "elk_results.txt"
# Section headers cmd_elk_query writes into ELK_RESULTS_FILE.
ELK_QUERY_HEADER = "$ elk-query"
ELK_FAILED_HEADER = "# failed:"
ELK_QUERY_COMMAND = f"{sys.executable} -m alert_doctor elk-query"
BASE_TOOLS = "Read,Grep,Glob,Write"
# Prefix rule: claude may run only this command (any arguments) through Bash.
ELK_QUERY_TOOL = f"Bash({ELK_QUERY_COMMAND}:*)"
MAX_FIX_ITEMS = 3
RUN_DIR_ENV = "ALERT_DOCTOR_RUN_DIR"
FIX_ITEM_CHARS = 60
# The prompt asks for FIX_ITEM_CHARS, but a concrete step naming a file and class easily runs
# past it; failing the whole verdict over length threw away correct analyses, so only items
# beyond FIX_ITEM_HARD_CHARS are touched, and those are trimmed rather than rejected.
FIX_ITEM_HARD_CHARS = 120
ACTION_TARGET_CHARS = 20
ACTIONS = ("fix_code", "fix_check", "ops", "observe", "vendor", "investigate")
ACTION_CATEGORIES = {
    "fix_code": ("code_bug", "config"),
    "fix_check": ("noise",),
    "ops": ("infra", "config"),
    "observe": ("transient", "noise", "infra"),
    "vendor": ("external_dependency",),
    "investigate": ("unknown", "infra"),
}
ACTIONS_NEEDING_STEPS = ("fix_code", "fix_check", "ops", "investigate")
# A direction that asks someone to change code, a check, a host, or chase a vendor must
# rest on something the reader can verify: a cited code line or a real ELK log line.
ACTIONS_NEEDING_SUPPORT = ("fix_code", "fix_check", "ops", "vendor")
ACTIONS_NEEDING_HUMAN = ("ops", "vendor", "investigate")
INVESTIGATE_MAX_CONFIDENCE = 0.6
_FILLER = re.compile(r"[\s。.,,、!!::;;~…]+")
# Whole items that tell the on-call engineer nothing they did not already know.
VAGUE_FIXES = frozenset(_FILLER.sub("", f).lower() for f in (
    "查 log", "查看 log", "查 elk", "確認問題", "確認原因", "持續觀察", "再觀察", "觀察",
    "請相關人員確認", "請相關人員處理", "人工確認", "人工處理", "通知相關人員", "進一步調查"))
# A dropped log line is a hallucination we can repair by deleting it, not a reason to
# re-run on the escalation model or to force human review: such problems carry this prefix
# and should_escalate / _finalize ignore them.
LOG_PROBLEM = "logs 查無出處"
FIX_TRIMMED = "fix 過長已截斷"
# Optional or surplus parts that can be dropped without changing the verdict's judgement.
DROPPED = "已刪除多餘欄位"
REPAIRED_PREFIXES = (LOG_PROBLEM, FIX_TRIMMED, DROPPED)
MAX_CODE_EVIDENCE = 3
VALIDATION_FEEDBACK = """

## 上一次輸出沒有通過驗證

請修正以下問題後重新寫出 verdict.json(其餘判斷若無誤可沿用):
{problems}
"""


class VerdictInvalid(ValueError):
    """The verdict still fails validation after the feedback re-run; retrying the same
    incident would only reproduce it, so it fails at once."""
_LEADING_TS = re.compile(
    r"^\s*\[?(?:\d{4}[-/])?\d{1,2}[-/]\d{1,2}[T ]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?\]?\s*\|?\s*")


def refresh_mirrors(cfg, store, now: float, refresh_all=None) -> dict[str, tuple[str, str]]:
    """Refresh every repo checkout; a repo whose SHA moved invalidates the active auto rules
    of fingerprints raised by systems built from that repo (their code just changed)."""
    def on_change(repo_id: str, old_sha: str, new_sha: str) -> None:
        systems = [key for key, spec in cfg.systems.items() if repo_id in spec.repos]
        reason = f"repo {repo_id} SHA 變更 {old_sha[:8]}→{new_sha[:8]}"
        changed = autorules.invalidate_for_systems(store, systems, reason, now)
        if changed:
            log.info("%s:%d 條 active 自動規則失效", reason, len(changed))
    results = (refresh_all or mirrors.refresh_all)(cfg, on_change=on_change)
    for repo_id in results:
        try:
            store.beat(f"mirror:{repo_id}", now)
        except Exception as exc:
            log.warning("mirror heartbeat for %s failed: %s", repo_id, exc)
    return results


class NotLaunched(RuntimeError):
    """The claude process never started, so the run must not count against the budget."""


class LeaseLost(RuntimeError):
    """Another analyzer re-claimed the incident while this one was working."""


def resolve_cli(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for d in CLI_DIRS:
        candidate = os.path.join(os.path.expanduser(d), name)
        if os.path.exists(candidate):
            return candidate
    raise FileNotFoundError(f"找不到 '{name}' CLI(已搜尋 PATH 與 {CLI_DIRS})")


def build_context(incident: Incident, alert_example: ParsedAlert | None,
                  evidence: dict | None, check: CheckSpec | None,
                  repos: dict[str, dict], *, start_systems: tuple[str, ...] = (),
                  topology: str = "", task: dict | None = None,
                  check_script_path: str | None = None,
                  known_background: list | None = None) -> dict:
    """`repos` maps repo id to {"path", "sha", "system"}; `task` is the watchdog schedule
    (label/cron/kwargs) that raised the alert, `check_script_path` its check script,
    `known_background` the `known.background` entries relevant to the incident."""
    example = None
    if alert_example is not None:
        example = {
            "check_title": alert_example.check_title,
            "check_code": alert_example.check_code,
            "task_id": alert_example.task_id,
            "level": alert_example.level,
            "result_message": alert_example.result_message,
            "extra": alert_example.extra,
            "truncated": alert_example.truncated,
        }
    return {
        "incident": {
            "id": incident.id,
            "check_title": incident.check_title,
            "check_code": incident.check_code,
            "count": incident.count,
            "first_epoch": incident.first_epoch,
            "last_epoch": incident.last_epoch,
        },
        "channel": incident.channel,
        "start_systems": list(start_systems),
        "alert": example,
        "evidence": evidence,
        "check": None if check is None else {
            "system": check.system, "repo": check.repo,
            "deploy_ref": check.deploy_ref, "never_silence": check.never_silence,
        },
        "repos": repos,
        "shas": {rid: info["sha"] for rid, info in repos.items()},
        "topology": topology,
        "co_erroring": evidence.get("candidates") if isinstance(evidence, dict) else None,
        "attachments": evidence.get("attachments") if isinstance(evidence, dict) else None,
        "task": task,
        "check_script_path": check_script_path,
        "known_background": list(known_background or []),
    }


def task_summary(task) -> dict:
    """The snapshot exporter already stripped credentials from kwargs."""
    return {key: getattr(task, key, None)
            for key in ("id", "label", "cron", "kwargs", "check_code", "check_title")}


def find_check_script(snapshot_dir: str, check_code: str | None) -> str | None:
    if not check_code:
        return None
    found = sorted(glob.glob(os.path.join(
        snapshot_dir, "check_scripts", f"*_{glob.escape(check_code)}.py")))
    return found[0] if found else None


def _claude_env(run_dir: str) -> dict[str, str]:
    """The elk-query rule runs `-m alert_doctor` from the run dir, so the repo root must be
    importable there; `RUN_DIR_ENV` pins where elk-query records results, because the
    model often `cd`s elsewhere first and a cwd-relative file would then be lost."""
    env = dict(os.environ)
    paths = [str(PROJECT_ROOT)] + [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(paths))
    env[RUN_DIR_ENV] = run_dir
    return env


def run_claude(model: str, prompt: str, cwd: str, add_dirs: list[str], timeout: int,
               run=subprocess.run) -> dict:
    """Run one headless session in `cwd` and return the `verdict.json` it wrote there.

    No `--bare`: that would switch a subscription login to metered API billing.
    """
    try:
        cli = resolve_cli("claude")
    except FileNotFoundError as exc:
        raise NotLaunched(str(exc)) from exc
    cmd = [cli, "-p", prompt, "--model", model, "--allowedTools", BASE_TOOLS, ELK_QUERY_TOOL]
    for d in add_dirs:
        cmd += ["--add-dir", d]
    cmd += ["--output-format", "json"]
    try:
        done = run(cmd, cwd=cwd, capture_output=True, text=True,
                   stdin=subprocess.DEVNULL, timeout=timeout, env=_claude_env(os.path.abspath(cwd)))
    except OSError as exc:
        raise NotLaunched(f"無法啟動 claude:{exc}") from exc
    if done.returncode != 0:
        raise RuntimeError(f"claude 失敗 rc={done.returncode}:{(done.stderr or '')[-300:]}")
    try:
        if json.loads(done.stdout).get("is_error"):
            raise RuntimeError(f"claude 回報錯誤:{done.stdout[:300]}")
    except json.JSONDecodeError:
        pass
    path = Path(cwd) / "verdict.json"
    if not path.exists():
        raise RuntimeError("claude 結束但沒有寫出 verdict.json")
    try:
        verdict = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"verdict.json 不是合法 JSON:{exc}") from exc
    if not isinstance(verdict, dict):
        raise RuntimeError("verdict.json 不是 JSON 物件")
    return verdict


def _relative_to_repo(file: str, repo_root: str) -> str:
    """Map an absolute path inside the repo checkout (symlinks resolved) to a relative one."""
    if file.startswith("./"):
        file = file[2:]
    if os.path.isabs(file):
        root = os.path.realpath(repo_root)
        real = os.path.realpath(file)
        if real.startswith(root + os.sep):
            return os.path.relpath(real, root)
    return file


_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _resolve_key(data, key: str) -> bool:
    node = data
    for name, index in _PATH_TOKEN.findall(key):
        try:
            node = node[int(index)] if index else node[name]
        except (KeyError, IndexError, TypeError):
            return False
    return True


def _is_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _check_citation(item, repos: dict[str, str], evidence: dict | None) -> str | None:
    if not isinstance(item, dict):
        return f"evidence 項目格式錯誤:{item!r}"
    kind = item.get("type")
    if kind == "code":
        repo, file, line = item.get("repo"), item.get("file"), item.get("line")
        if (not isinstance(repo, str) or not isinstance(file, str)
                or not isinstance(line, int) or isinstance(line, bool)):
            return f"code 引用缺少 repo/file/line:{item!r}"
        if repo not in repos:
            return f"引用的 repo 不存在或沒有 checkout:{repo!r}"
        root = os.path.realpath(repos[repo])
        path = os.path.realpath(os.path.join(root, file))
        if os.path.isabs(file) or not path.startswith(root + os.sep) or not os.path.isfile(path):
            return f"引用的檔案不存在:{file}"
        with open(path, "rb") as f:
            total = sum(1 for _ in f)
        if not 1 <= line <= total:
            return f"引用的行號不存在:{file}:{line}(共 {total} 行)"
        return None
    if kind == "elk":
        key = item.get("key")
        if not isinstance(key, str) or evidence is None or not _resolve_key(evidence, key):
            return f"引用的 ELK key 不在證據包:{key!r}"
        return None
    return f"未知的 evidence type:{kind!r}"


def _squash(text: str) -> str:
    return " ".join(text.split())


def _log_key(line: str) -> str:
    return _squash(_LEADING_TS.sub("", line, count=1))


def _returned_lines(run_dir: str | None) -> set[str]:
    """Normalised output lines of the queries that succeeded in this run.

    Only `elk_results.txt` counts: the evidence-pack samples are field dicts, not lines, so
    nothing could be matched against them as a whole line. Comment lines (`# …`) and the
    output of failed queries (error text, not logs) are skipped.
    """
    if not run_dir:
        return set()
    try:
        text = Path(run_dir, ELK_RESULTS_FILE).read_text(errors="replace")
    except OSError:
        return set()
    found, in_query = set(), False
    for line in text.splitlines():
        if line.startswith(ELK_QUERY_HEADER):
            in_query = True
        elif line.startswith(ELK_FAILED_HEADER):
            in_query = False
        elif in_query and not line.startswith("#"):
            key = _log_key(line)
            if key:
                found.add(key)
    return found


def _check_logs(v: dict, run_dir: str | None) -> list[str]:
    """Drop, in place, every `logs` line that is not, as a whole line, in what ELK returned.

    Only the leading timestamp and whitespace are normalised; the stored line stays raw.
    """
    if "logs" not in v:
        return []
    logs = v["logs"]
    if not isinstance(logs, list):
        v["logs"] = []
        return [f"{LOG_PROBLEM}:logs 必須是字串陣列"]
    returned = _returned_lines(run_dir)
    kept, problems = [], []
    for line in logs:
        key = _log_key(line) if isinstance(line, str) else ""
        if key and key in returned:
            kept.append(line)
        else:
            problems.append(f"{LOG_PROBLEM}:{str(line)[:80]!r}")
    v["logs"] = kept
    return problems


def _blocking(problems: list[str]) -> list[str]:
    return [p for p in problems if not p.startswith(REPAIRED_PREFIXES)]


def _is_vague(item: str) -> bool:
    return _FILLER.sub("", item).lower() in VAGUE_FIXES


def _check_fixes(fixes, action) -> list[str]:
    if not isinstance(fixes, list) or not all(isinstance(f, str) and f.strip() for f in fixes):
        return [f"fix 必須是最多 {MAX_FIX_ITEMS} 項非空字串的陣列"]
    problems = []
    if not fixes and action in ACTIONS_NEEDING_STEPS:
        problems.append(f"action={action} 時 fix 至少要 1 項具體步驟")
    if len(fixes) > MAX_FIX_ITEMS:
        problems.append(f"{DROPPED}:fix 只保留前 {MAX_FIX_ITEMS} 項(原 {len(fixes)} 項)")
        del fixes[MAX_FIX_ITEMS:]
    for i, f in enumerate(fixes):
        if _is_vague(f):
            problems.append(f"fix 不能只寫空泛的「{f.strip()}」,要寫可以直接動手的步驟")
        elif len(f.strip()) > FIX_ITEM_HARD_CHARS:
            fixes[i] = f.strip()[:FIX_ITEM_HARD_CHARS - 1] + "…"
            problems.append(f"{FIX_TRIMMED}:{f[:30]!r}…")
    return problems


def _has_code_evidence(v: dict) -> bool:
    items = v.get("evidence")
    return isinstance(items, list) and any(
        isinstance(i, dict) and i.get("type") == "code" for i in items)


def _check_action(v: dict, *, human_forced: bool = False) -> list[str]:
    """The action/category/needs_human/confidence matrix. `human_forced` is set when
    _finalize itself raised needs_human, which an `observe` verdict must then tolerate."""
    action = v.get("action")
    if action not in ACTIONS:
        return [f"action 必須是 {'/'.join(ACTIONS)} 之一:{action!r}"]
    problems = []
    category = v.get("category")
    if category not in ACTION_CATEGORIES[action]:
        problems.append(f"action={action} 時 category 必須是 "
                        f"{'/'.join(ACTION_CATEGORIES[action])}:{category!r}")
    needs_human = v.get("needs_human")
    if action == "observe" and needs_human is True and not human_forced:
        problems.append("action=observe 表示不需後續處置,needs_human 必須是 false")
    if action in ACTIONS_NEEDING_HUMAN and needs_human is False:
        problems.append(f"action={action} 時 needs_human 必須是 true")
    conf = v.get("confidence")
    if action == "investigate" and _is_number(conf) and conf > INVESTIGATE_MAX_CONFIDENCE:
        problems.append(f"action=investigate 表示無法判定,confidence 不能高於 {INVESTIGATE_MAX_CONFIDENCE}")
    target = v.get("action_target")
    if action == "vendor":
        if not isinstance(target, str) or not target.strip():
            problems.append("action=vendor 時 action_target 必須填外部單位名稱")
        elif len(target.strip()) > ACTION_TARGET_CHARS:
            problems.append(f"action_target 最多 {ACTION_TARGET_CHARS} 字:{target!r}")
    elif target not in (None, ""):
        v["action_target"] = None
        problems.append(f"{DROPPED}:action_target 只有 action=vendor 時可以填:{target!r}")
    if action == "fix_code" and not _has_code_evidence(v):
        problems.append("action=fix_code 至少要引用 1 項 code 類 evidence")
    elif (action in ACTIONS_NEEDING_SUPPORT and not _has_code_evidence(v)
            and not (isinstance(v.get("logs"), list) and v["logs"])):
        problems.append(f"action={action} 至少要有 1 項 code 類 evidence 或 1 行真實 log")
    return problems


def validate_verdict(v: dict, repos: dict[str, str], evidence: dict | None,
                     run_dir: str | None = None, *, human_forced: bool = False) -> list[str]:
    """Return the list of problems; empty means the verdict passes.

    `repos` maps repo id to its checkout path; `run_dir` holds the `elk_results.txt` the
    session's ELK queries wrote. `human_forced` relaxes only the observe/needs_human rule
    (see _check_action). Side effects: code citations whose `file` is an absolute path
    inside that repo's checkout (or starts with `./`) are rewritten in place to
    repo-relative paths, and `logs` lines not found as a whole line in `elk_results.txt`
    are removed (reported with the LOG_PROBLEM prefix); `fix` items longer than
    FIX_ITEM_HARD_CHARS are trimmed (reported with the FIX_TRIMMED prefix).
    """
    problems = []
    if v.get("category") not in CATEGORIES:
        problems.append(f"category 不合法:{v.get('category')!r}")
    if v.get("severity") not in SEVERITIES:
        problems.append(f"severity 不合法:{v.get('severity')!r}")
    conf = v.get("confidence")
    if not _is_number(conf) or not 0 <= conf <= 1:
        problems.append(f"confidence 必須是 0 到 1 的數字:{conf!r}")
    for key in ("cause", "impact", "project"):
        if not isinstance(v.get(key), str) or not v[key].strip():
            problems.append(f"{key} 缺少或為空")
    problems += _check_fixes(v.get("fix", []), v.get("action"))
    if "remark" in v and not isinstance(v["remark"], str):
        del v["remark"]
        problems.append(f"{DROPPED}:remark 不是字串")
    problems += _check_logs(v, run_dir)
    fix = v.get("fix_in_system")
    if not isinstance(fix, str) or not fix.strip():
        problems.append("fix_in_system 缺少或為空(填 system key 或 \"unknown\")")
    if not isinstance(v.get("needs_human"), bool):
        problems.append("needs_human 必須是布林值")
    items = v.get("evidence")
    if not isinstance(items, list):
        problems.append("evidence 必須是陣列")
        return problems + _check_action(v, human_forced=human_forced)
    code_items = [i for i in items if isinstance(i, dict) and i.get("type") == "code"]
    if len(code_items) > MAX_CODE_EVIDENCE:
        surplus = {id(i) for i in code_items[MAX_CODE_EVIDENCE:]}
        items[:] = [i for i in items if id(i) not in surplus]
        problems.append(f"{DROPPED}:code evidence 只保留前 {MAX_CODE_EVIDENCE} 項")
    for item in items:
        if (isinstance(item, dict) and item.get("type") == "code"
                and isinstance(item.get("file"), str) and item.get("repo") in repos):
            item["file"] = _relative_to_repo(item["file"], repos[item["repo"]])
        problem = _check_citation(item, repos, evidence)
        if problem:
            problems.append(problem)
    return problems + _check_action(v, human_forced=human_forced)


def should_escalate(v: dict, problems: list[str], check: CheckSpec | None,
                    systems=None) -> bool:
    """`systems` is the set of configured system keys; None skips the fix_in_system check.

    Problems carrying a REPAIRED_PREFIXES prefix do not count: they were already repaired
    in place, and a stronger model would not make ELK return more.
    """
    conf = v.get("confidence")
    fix = v.get("fix_in_system")
    unknown_target = (systems is not None and isinstance(fix, str)
                      and fix != UNKNOWN_SYSTEM and fix not in systems)
    # Action-matrix violations (category/action mismatch, vague or missing steps, no
    # supporting evidence) are blocking on purpose: unlike a bad citation, _finalize cannot
    # repair them by deletion, so the one escalation re-run is their only chance to be fixed
    # before the incident goes to the retry path.
    return bool(
        _blocking(problems)
        or unknown_target
        or not _is_number(conf) or conf < ESCALATION_CONFIDENCE
        or (check is not None and check.never_silence)
        or (v.get("category") == "code_bug" and v.get("needs_human"))
    )


def _alert_label(task: dict | None, alert: ParsedAlert | None, claimed: Incident) -> str:
    """Same precedence as watchdog.alert_label: the schedule's label, else the check title."""
    return ((task or {}).get("label") or (alert.check_title if alert is not None else "")
            or claimed.check_title or "")


def _repo_listing(repo_paths: dict[str, str]) -> str:
    if not repo_paths:
        return NO_REPO_NOTE
    return "\n".join(f"  - `{rid}`:{path}" for rid, path in repo_paths.items())


def build_prompt(repo_paths: dict[str, str]) -> str:
    return (PROMPT_PATH.read_text().replace("__REPOS__", _repo_listing(repo_paths))
            .replace("__ELK_QUERY__", ELK_QUERY_COMMAND))


def _day_bounds(now: float) -> tuple[float, float]:
    local = datetime.fromtimestamp(now, TAIPEI)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


class Analyzer:
    """Claims pending incidents and queues a cited analysis for the publisher.

    Nothing is posted here: the conclusion goes to the outbox as `analysis` in the
    incident's primary report thread, one `link` per other channel, and `failure` notices.
    Reactions ride along as payload `reactions_on_root` / `remove_on_root`, which the
    publisher applies to that channel's report root alert. `slack` is only used to resolve
    owner mentions (`alert_doctor.slack_io` in production).
    """

    def __init__(self, cfg, store, slack, bot_token: str, checks: dict,
                 clock=time.time, runner=run_claude, current=mirrors.current,
                 refresh=mirrors.refresh, refresh_all=mirrors.refresh_all,
                 snapshot_path: str | None = None, snapshot_loader=None, archive=None,
                 known_entries=None, source_bot_token: str | None = None):
        """`snapshot_loader(path)` defaults to `watchdog.load_snapshot`; `archive` to an
        `archive.Archive` on `cfg.archive_db_path`. Both are optional at runtime.
        `known_entries` (a list or source) defaults to `cfg.known_path`, re-read on change.
        `source_bot_token` (Rocket Message Bot) enables green purge; None keeps posting."""
        self.cfg, self.store, self.slack = cfg, store, slack
        self.bot_token, self.checks = bot_token, checks
        self.source_bot_token = source_bot_token
        self.clock, self.runner = clock, runner
        self.current, self.refresh, self.refresh_all = current, refresh, refresh_all
        self.owner = f"{socket.gethostname()}:{os.getpid()}"
        path = snapshot_path or getattr(cfg, "watchdog_snapshot_path", None) or DEFAULT_SNAPSHOT_PATH
        self.snapshot_path = str(path if os.path.isabs(path) else PROJECT_ROOT / path)
        self.snapshot_loader = snapshot_loader
        self._archive = archive
        self._archive_opened = archive is not None
        self._known = known.as_source(
            known_entries if known_entries is not None else getattr(cfg, "known_path", ""))
        schema.ensure_all(store)
        known_store.ensure_schema(store)

    def run_once(self) -> bool:
        """Process at most one incident; True if one was claimed and handled.

        Returns False when the incident went back to the queue untouched: over the daily
        budget with no reusable verdict, or its first report is not on Slack yet.
        """
        claimed = self.store.claim_incident(self.owner, self.clock())
        if claimed is None:
            return False
        try:
            if self._process(claimed) == "deferred":
                return False
        except LeaseLost as exc:
            log.warning("incident %s: %s", claimed.id, exc)
        except VerdictInvalid as exc:
            log.warning("incident %s: %s", claimed.id, exc)
            error = f"{type(exc).__name__}: {exc}"[:500]
            self.store.fail_analysis(claimed.id, error, final=True)
            self._announce_final_failure(claimed, error)
        except Exception as exc:
            log.exception("incident %s analysis failed", claimed.id)
            error = f"{type(exc).__name__}: {exc}"[:500]
            self.store.fail_analysis(claimed.id, error)
            self._announce_final_failure(claimed, error)
        return True

    def _report_for(self, claimed: Incident, *, wait: bool = True) -> dict | None:
        """{"channel", "root_ts"} of the thread the analysis belongs in, None to wait.

        The publisher posts into the primary report, which only exists once the first
        report reached Slack. After REPORT_WAIT_SECONDS the anchor alert is used instead.
        """
        primary = self.store.primary_report(claimed.id)
        if primary is not None:
            return {"channel": primary["channel"], "root_ts": primary["root_ts"]}
        fallback = self._fallback_report(claimed)
        if not wait:
            return fallback
        now = self.clock()
        since = self._wait_started(claimed)
        if now - since < REPORT_WAIT_SECONDS:
            return None
        log.warning("incident %s 等了 %d 秒仍沒有首則回報,改貼在原告警串",
                    claimed.id, int(now - since))
        return fallback

    def _wait_started(self, claimed: Incident) -> float:
        """Persisted, so a restart does not reset the wait. A re-analysis of an old incident
        counts from its request, not from its first alert."""
        rows = self.store.read("SELECT requested_epoch FROM incidents WHERE id=?", (claimed.id,))
        requested = rows[0][0] if rows else None
        return requested if requested is not None else claimed.first_epoch

    def _enqueue(self, claimed: Incident, report: dict, kind: str, priority: int, text: str,
                 *, add=(), remove=(), dedupe_key: str | None = None) -> None:
        payload = {"text": text}
        if add:
            payload["reactions_on_root"] = list(add)
        if remove:
            payload["remove_on_root"] = list(remove)
        self.store.enqueue_reply(
            incident_id=claimed.id, channel=report["channel"], kind=kind, priority=priority,
            due_epoch=self.clock(), payload=payload, thread_ts=report["root_ts"],
            dedupe_key=dedupe_key)

    def _announce_final_failure(self, claimed: Incident, error: str) -> None:
        current = self.store.get_incident(claimed.id)
        if current is None or current.analysis_state != "failed":
            return
        summary = " ".join(error.split())[:200]
        text = f"⚠️ 自動分析失敗({summary}),請人工查看"
        try:
            check = self._check_for(self.store.first_message(claimed.id), claimed)
            tag = " ".join(self._mentions(self._source(claimed), check))
            self._enqueue(claimed, self._report_for(claimed, wait=False), "failure", 1,
                          f"{text} {tag}" if tag else text,
                          add=[Reaction.NEEDS_HUMAN], remove=[Reaction.ANALYZING],
                          dedupe_key=f"failure:{claimed.id}")
        except Exception as exc:
            log.warning("failure notice for incident %s failed: %s", claimed.id, exc)

    def _notify_over_budget(self, claimed: Incident, report: dict, run_dir: str) -> None:
        marker = Path(run_dir, "budget_notified")
        if marker.exists():
            return
        try:
            self._enqueue(claimed, report, "failure", 2, replies.over_budget(self.cfg.model),
                          dedupe_key=f"budget:{claimed.id}")
            os.makedirs(run_dir, exist_ok=True)
            marker.touch()
        except Exception as exc:
            log.warning("over-budget notice for incident %s failed: %s", claimed.id, exc)

    def _process(self, claimed: Incident) -> str | None:
        """Return "deferred" when the incident was handed back to the queue unanalysed."""
        report = self._report_for(claimed)
        if report is None:
            self.store.defer_analysis(claimed.id, not_before=self.clock() + REPORT_RETRY_SECONDS)
            return "deferred"
        now = self.clock()
        alert = self.store.first_message(claimed.id)
        check = self._check_for(alert, claimed)
        # An auto-rule sample exists to re-check the rule; reusing the verdict it was learned from defeats that.
        sampled = autorules.sample_rule(self.store, claimed.id) is not None
        reuse = None if sampled or claimed.fresh_requested else self.store.recent_verdict(
            claimed.fingerprint, now, self.cfg.verdict_reuse_hours * 3600)
        if reuse is not None:
            verdict, model, completed = reuse
            task, _ = self._task_context(alert, claimed)
            self._publish(claimed, report, self._render(
                claimed, verdict, _alert_label(task, alert, claimed),
                reused_from=(now - completed) / 3600, check=check,
                truncated=bool(alert and alert.truncated)),
                verdict, model, {}, reused=True)
            return

        run_dir = os.path.abspath(os.path.join(self.cfg.runs_dir, str(claimed.id)))
        if self._over_budget(self.cfg.model):
            self.store.defer_analysis(claimed.id)
            self._notify_over_budget(claimed, report, run_dir)
            return "deferred"

        evidence = self.store.load_evidence(claimed.id)
        os.makedirs(run_dir, exist_ok=True)
        repos = self._checkouts()
        start_systems = self._start_systems(claimed)
        task, script = self._task_context(alert, claimed)
        context = build_context(claimed, alert, evidence, check, repos,
                                start_systems=start_systems,
                                topology=self._render_topology(start_systems),
                                task=task, check_script_path=script,
                                known_background=self._known_background(claimed, alert))
        Path(run_dir, "context.json").write_text(
            json.dumps(context, ensure_ascii=False, indent=2))
        repo_paths = {rid: info["path"] for rid, info in repos.items()}
        verdict, model = self._analyze(claimed, run_dir, repo_paths, evidence, check)
        self._publish(claimed, report, self._render(
            claimed, verdict, _alert_label(task, alert, claimed), check=check,
            truncated=bool(alert and alert.truncated)),
            verdict, model, context["shas"])

    def _known_background(self, claimed: Incident, alert: ParsedAlert | None) -> list:
        """Background only: a broken knowledge base must not block analysis."""
        try:
            source = self._source(claimed)
            found = known.background(self._known.entries(), alert, claimed.first_epoch,
                                     claimed.last_epoch, source)
            key = (known_store.alert_error_key(alert, source_system=source)
                   if alert is not None else None)
            linked = known_store.lookup(self.store, key, claimed.last_epoch)
            if linked is not None:
                found.insert(0, {
                    "id": linked.entry.id, "title": linked.entry.title,
                    "description": linked.entry.description, "action": linked.entry.action,
                    "source": linked.entry.source, "linked_error": True,
                    "linked_by": linked.linked_by, "in_window": False,
                    "overlapping_windows": [], "text_match": True,
                })
            return found
        except Exception as exc:
            log.warning("固定錯誤背景無法產生:%s", exc)
            return []

    def _snapshot_dir(self) -> str | None:
        found = os.path.dirname(self.snapshot_path)
        return found if os.path.isdir(found) else None

    def _task_context(self, alert: ParsedAlert | None,
                      claimed: Incident) -> tuple[dict | None, str | None]:
        """The watchdog schedule and check script behind the alert; a hint, never a blocker."""
        snapshot_dir = self._snapshot_dir()
        if snapshot_dir is None:
            return None, None
        task = None
        try:
            loader = self.snapshot_loader
            if loader is None:
                from alert_doctor.watchdog import load_snapshot as loader
            snapshot = loader(self.snapshot_path)
            if snapshot is not None and alert is not None:
                task = snapshot.task_for_alert(alert)
        except Exception as exc:
            log.warning("watchdog 快照無法使用:%s", exc)
        code = getattr(task, "check_code", None) or claimed.check_code
        if alert is not None:
            code = code or alert.check_code
        return (task_summary(task) if task is not None else None,
                find_check_script(snapshot_dir, code))

    def _checkouts(self) -> dict[str, dict]:
        """Read-only checkout per repo; a repo that cannot be checked out is skipped.

        A missing repo only removes code citations for it, so analysis still goes ahead.
        """
        found = {}
        for repo_id, repo in self.cfg.repos.items():
            try:
                pair = self.current(repo_id, self.cfg.mirrors_dir)
                if pair is None:
                    pair = self.refresh(repo, self.cfg.mirrors_dir)
            except Exception as exc:
                log.warning("repo %s 沒有可用的 checkout:%s", repo_id, exc)
                continue
            found[repo_id] = {"path": pair[0], "sha": pair[1],
                              "system": self._system_of_repo(repo_id)}
        return found

    def _system_of_repo(self, repo_id: str) -> str:
        return next((key for key, spec in self.cfg.systems.items() if repo_id in spec.repos), "")

    def _start_systems(self, claimed: Incident) -> tuple[str, ...]:
        channel = self.cfg.channel(claimed.channel)
        return tuple(channel.systems) if channel else ()

    def _render_topology(self, start_systems: tuple[str, ...]) -> str:
        """Topology is a hint; a missing file or a broken module must not block analysis."""
        try:
            if not os.path.exists(self.cfg.topology_path):
                return ""
            from alert_doctor import topology
            return topology.load_topology(self.cfg.topology_path).render_for_prompt(start_systems)
        except Exception as exc:
            log.warning("topology 無法載入:%s", exc)
            return ""

    def _source(self, claimed: Incident) -> str:
        if claimed.source_system:
            return claimed.source_system
        starts = self._start_systems(claimed)
        return starts[0] if starts else ""

    def _mentions(self, system: str, check: CheckSpec | None = None) -> tuple[str, ...]:
        return mentions.resolve_owners(
            self.slack, self.bot_token, mentions.owners_for(self.cfg, system, check))

    def _render(self, claimed: Incident, verdict: dict, title: str,
                reused_from: float | None = None, check: CheckSpec | None = None,
                truncated: bool = False) -> str:
        source = self._source(claimed)
        fix = verdict.get("fix_in_system") or ""
        fix_owners = ()
        if fix in self.cfg.systems:
            # The check's owners only speak for the alert's own system.
            fix_owners = self._mentions(fix, check if fix == source else None)
        human_owners = self._mentions(source, check) if verdict.get("needs_human") else ()
        cited = [i.get("repo") for i in verdict.get("evidence") or ()
                 if isinstance(i, dict) and i.get("type") == "code"]
        # Older verdicts name no project; replies falls back to the first cited repo.
        project = verdict.get("project") or (cited[0] if cited else None)
        project_system = self._system_of_repo(project) if project in self.cfg.repos else ""
        text = replies.verdict(verdict, reused_from, title=title, source_system=source,
                               project_system=project_system, owners=fix_owners,
                               human_owners=human_owners)
        return f"{text}\n{replies.TRUNCATED_NOTE}" if truncated else text

    def _analyze(self, claimed, run_dir, repo_paths, evidence, check) -> tuple[dict, str]:
        prompt = build_prompt(repo_paths)
        add_dirs = list(repo_paths.values())
        snapshot_dir = self._snapshot_dir()
        if snapshot_dir is not None:
            add_dirs.append(snapshot_dir)
        verdict, problems = self._invoke(self.cfg.model, prompt, run_dir, add_dirs, repo_paths, evidence)
        model = self.cfg.model
        if should_escalate(verdict, problems, check, self.cfg.systems):
            if self._over_budget(self.cfg.escalation_model):
                log.warning("incident %s: escalation skipped, %s over budget",
                            claimed.id, self.cfg.escalation_model)
            else:
                blocking = _blocking(problems)
                retry_prompt = prompt + VALIDATION_FEEDBACK.format(
                    problems="\n".join(f"- {p}" for p in blocking)) if blocking else prompt
                verdict, problems = self._invoke(
                    self.cfg.escalation_model, retry_prompt, run_dir, add_dirs, repo_paths, evidence)
                model = self.cfg.escalation_model
        return self._finalize(verdict, problems, repo_paths, evidence, run_dir), model

    def _invoke(self, model, prompt, run_dir, add_dirs, repo_paths, evidence):
        stale = Path(run_dir, "verdict.json")
        if stale.exists():
            stale.unlink()
        launched = True
        try:
            verdict = self.runner(model, prompt, run_dir, add_dirs, self.cfg.llm_timeout)
        except NotLaunched:
            launched = False
            raise
        finally:
            if launched:
                self.store.record_llm_call(model, self.clock())
        return verdict, validate_verdict(verdict, repo_paths, evidence, run_dir)

    @staticmethod
    def _finalize(verdict: dict, problems: list[str], repo_paths, evidence, run_dir) -> dict:
        """Drop citations that still fail validation and force human review.

        Unfounded log lines were already removed by validate_verdict and need nothing more.
        Structural problems (missing fields, bad enums, action-matrix violations) cannot be
        repaired, so they raise and the incident is retried rather than posting a
        half-formed analysis.
        """
        if not _blocking(problems):
            return verdict
        kept = [i for i in verdict["evidence"]
                if _check_citation(i, repo_paths, evidence) is None] \
            if isinstance(verdict.get("evidence"), list) else []
        repaired = {**verdict, "evidence": kept, "needs_human": True}
        remaining = _blocking(validate_verdict(repaired, repo_paths, evidence, run_dir,
                                               human_forced=True))
        if remaining:
            raise VerdictInvalid("verdict 驗證失敗:" + ";".join(remaining))
        return repaired

    def _check_for(self, alert, claimed):
        if alert is not None:
            return lookup_check(self.checks, alert)
        return self.checks.get(claimed.check_code or "") or self.checks.get(claimed.check_title)

    def _over_budget(self, model: str) -> bool:
        limit = (self.cfg.daily_limit_escalation if model == self.cfg.escalation_model
                 else self.cfg.daily_limit)
        start, end = _day_bounds(self.clock())
        return self.store.llm_calls_on(model, start, end) >= limit

    def _other_channel_roots(self, claimed: Incident, primary_channel: str) -> list[tuple[str, str]]:
        """(channel, root ts) of every other channel the incident appeared in.

        A channel whose first report is still queued gets its earliest occurrence, which
        is the alert that first report will be threaded on.
        """
        roots: dict[str, str] = {}
        deleted: dict[str, set[str]] = {}

        def alive(channel: str, ts: str) -> bool:
            if channel not in deleted:
                deleted[channel] = self.store.deleted_ts(channel)
            return ts not in deleted[channel]

        for channel, ts in self.store.read(
                "SELECT channel, ts FROM messages WHERE incident_id=? AND channel!=?"
                " ORDER BY epoch, ts", (claimed.id, primary_channel)):
            if alive(channel, ts):
                roots.setdefault(channel, ts)
        for channel, root_ts in self.store.read(
                "SELECT channel, root_ts FROM reports WHERE incident_id=? AND channel!=?",
                (claimed.id, primary_channel)):
            if alive(channel, root_ts):
                roots[channel] = root_ts
        return sorted(roots.items())

    def _fallback_report(self, claimed: Incident) -> dict:
        """The anchor alert, or when green purge deleted it the earliest surviving alert in
        any channel (the anchor's channel first). With none left, root_ts is None and the
        publisher starts a new top-level post rather than dropping the analysis."""
        if claimed.anchor_ts not in self.store.deleted_ts(claimed.channel):
            return {"channel": claimed.channel, "root_ts": claimed.anchor_ts}
        channels = [claimed.channel] + [c for c in self._incident_channels(claimed, claimed.channel)
                                        if c != claimed.channel]
        for channel in channels:
            root = self._surviving_root(claimed.id, channel)
            if root is not None:
                return {"channel": channel, "root_ts": root}
        return {"channel": claimed.channel, "root_ts": None}

    def _surviving_root(self, incident_id: int, channel: str) -> str | None:
        """Earliest alert of the incident in `channel` that green purge has not deleted."""
        deleted = self.store.deleted_ts(channel)
        for (ts,) in self.store.read(
                "SELECT ts FROM messages WHERE incident_id=? AND channel=? AND fragment_of IS NULL"
                " ORDER BY epoch, ts", (incident_id, channel)):
            if ts not in deleted:
                return ts
        return None

    def _purges_green(self, claimed: Incident, verdict: dict) -> bool:
        if not purge.purge_enabled(self.cfg, self.source_bot_token):
            return False
        return purge.is_green(self.store, claimed.id, verdict,
                              never_silence=purge.never_silence_for(self.store, self.checks, claimed.id))

    def _incident_channels(self, claimed: Incident, primary_channel: str) -> list[str]:
        rows = self.store.read(
            "SELECT channel FROM messages WHERE incident_id=?"
            " UNION SELECT channel FROM reports WHERE incident_id=?", (claimed.id, claimed.id))
        return sorted({primary_channel, *(row[0] for row in rows)})

    def _assert_lease(self, claimed: Incident) -> None:
        """Re-claiming bumps `attempts`, so a changed count or state means we lost the lease.

        A sleeping Mac can outlive the lease; whoever re-claimed owns the posting.
        """
        current = self.store.get_incident(claimed.id)
        if (current is None or current.analysis_state != "leased"
                or current.attempts != claimed.attempts):
            raise LeaseLost("lease 已被他人接手或分析已完成,不重複貼文")

    def _publish(self, claimed: Incident, report: dict, text: str, verdict: dict, model: str,
                 shas: dict, *, reused: bool = False) -> None:
        self._assert_lease(claimed)
        if self._purges_green(claimed, verdict):
            # Green: nothing is posted; the collector's Purger deletes the alerts and our
            # replies. The text is kept so a purge that cannot delete can post it after all.
            self.store.complete_analysis_with_purge(
                claimed.id, verdict, model, self.clock(),
                channels=self._incident_channels(claimed, report["channel"]),
                analysis_text=text, reused=reused)
            self._after_complete(claimed, verdict, model, shas)
            return
        done = Reaction.NEEDS_HUMAN if verdict.get("needs_human") else Reaction.DONE
        add, remove = [done], [Reaction.ANALYZING]
        # A re-analysis can overturn "needs a human"; a stale 🙋 would keep paging people.
        if not verdict.get("needs_human") and (claimed.verdict or {}).get("needs_human"):
            remove.append(Reaction.NEEDS_HUMAN)
        chosen = SEVERITY_REACTION.get(verdict.get("severity"))
        if chosen is not None:
            add.append(chosen)
            # Only the severity this analyzer set last time is ours to take back.
            previous = SEVERITY_REACTION.get((claimed.verdict or {}).get("severity"))
            if previous is not None and previous != chosen:
                remove.append(previous)
        self._enqueue(claimed, report, "analysis", 1, text, add=add, remove=remove,
                      dedupe_key=f"analysis:{claimed.id}")
        if report["root_ts"] is None:
            self.store.complete_analysis(claimed.id, verdict, model, self.clock(), reused=reused)
            self._after_complete(claimed, verdict, model, shas)
            return
        link = replies.report_link(self.cfg.permalink(report["channel"], report["root_ts"]))
        for channel, root_ts in self._other_channel_roots(claimed, report["channel"]):
            self._enqueue(claimed, {"channel": channel, "root_ts": root_ts}, "link", 2, link,
                          add=add, remove=remove, dedupe_key=f"link:{claimed.id}:{channel}")
        self.store.complete_analysis(claimed.id, verdict, model, self.clock(), reused=reused)
        self._after_complete(claimed, verdict, model, shas)

    def _after_complete(self, claimed: Incident, verdict: dict, model: str, shas: dict) -> None:
        self._archive_verdict(claimed, verdict, model, shas)
        self._mark_unhealthy(claimed, verdict)
        self._settle_sample(claimed, verdict)

    def _open_archive(self):
        if not self._archive_opened:
            self._archive_opened = True
            path = getattr(self.cfg, "archive_db_path", None)
            if path:
                from alert_doctor.archive import Archive
                self._archive = Archive(path)
        return self._archive

    def _archive_verdict(self, claimed: Incident, verdict: dict, model: str, shas: dict) -> None:
        """The archive is for later study; it must never undo or block an analysis."""
        try:
            archive = self._open_archive()
            if archive is not None:
                incident = self.store.get_incident(claimed.id) or claimed
                archive.record_verdict(incident, verdict, model, shas, self.clock())
        except Exception as exc:
            log.warning("archive.record_verdict failed for incident %s: %s", claimed.id, exc)

    def _settle_sample(self, claimed: Incident, verdict: dict) -> None:
        """A sampled re-check that disagrees with its auto rule takes the rule out of service."""
        try:
            rule_id = autorules.sample_rule(self.store, claimed.id)
            if rule_id is None:
                return
            kind = self.store.read("SELECT kind FROM auto_rules WHERE id=?", (rule_id,))[0][0]
            category = verdict.get("category")
            if kind == "noise":
                agreed = category in autorules.NOISE_CATEGORIES and not verdict.get("needs_human")
            else:
                agreed = category in autorules.REAL_CATEGORIES
            autorules.settle_sample(self.store, claimed.id, agreed)
            if not agreed:
                autorules.invalidate(self.store, claimed.fingerprint,
                                     f"抽樣複查判定 {category},與規則不符", self.clock())
        except Exception as exc:
            log.warning("sample settlement for incident %s failed: %s", claimed.id, exc)

    def refresh_mirrors(self) -> None:
        refresh_mirrors(self.cfg, self.store, self.clock(), self.refresh_all)

    def _mark_unhealthy(self, claimed: Incident, verdict: dict) -> None:
        """The tuner is optional here: a failure must not undo a finished analysis."""
        if verdict.get("category") not in UNHEALTHY_CATEGORIES and not verdict.get("needs_human"):
            return
        try:
            from alert_doctor import tuner
            tuner.mark_unhealthy(self.store, claimed.fingerprint,
                                 claimed.first_epoch, claimed.last_epoch)
        except Exception as exc:
            log.warning("tuner.mark_unhealthy failed for incident %s: %s", claimed.id, exc)

    def run_forever(self, stop) -> None:
        lock_path = f"{self.cfg.db_path}.analyzer.lock"
        lock = open(lock_path, "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log.error("another analyzer holds %s", lock_path)
            raise SystemExit(1)
        try:
            mentions.warm(self.slack, self.bot_token, self.cfg, self.checks)
        except Exception:
            log.exception("owner mention warm-up failed")
        last_mirrors = float("-inf")
        while not stop.is_set():
            self.store.beat("analyzer", self.clock())
            if self.clock() - last_mirrors >= MIRROR_REFRESH_SECONDS:
                last_mirrors = self.clock()
                try:
                    self.refresh_mirrors()
                except Exception:
                    log.exception("mirror refresh failed")
            try:
                busy = self.run_once()
            except Exception:
                log.exception("analyzer loop error")
                busy = False
            if not busy:
                stop.wait(LOOP_SECONDS)
