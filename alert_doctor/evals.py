"""Regression eval: re-run the analysis on frozen real incidents and score the verdict
against hand-verified ground truth.

Nothing here touches the production store, budget counters or Slack.
"""
from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from alert_doctor import analyzer
from alert_doctor.models import CheckSpec

EVALS_DIR = analyzer.PROJECT_ROOT / "evals"
CASES_DIR = EVALS_DIR / "cases"
RUNS_DIR = EVALS_DIR / "runs"
MUST_FIELDS = ("cause", "impact", "fix")
EXPECTED_KEYS = {"action", "category", "needs_human", "must", "bonus", "if_action", "notes"}
_SUCCESS_HEADER = re.compile(rf"^{re.escape(analyzer.ELK_QUERY_HEADER)} ", re.M)
_FAILED_HEADER = re.compile(rf"^{re.escape(analyzer.ELK_FAILED_HEADER)} ", re.M)


@dataclass(frozen=True)
class Case:
    id: str
    context: dict
    expected: dict


def _check_expected(case_id: str, expected) -> None:
    def bad(msg: str):
        raise ValueError(f"evals case {case_id}: expected.json {msg}")
    if not isinstance(expected, dict):
        bad("必須是 JSON 物件")
    unknown = set(expected) - EXPECTED_KEYS
    if unknown:
        bad(f"有未知欄位 {sorted(unknown)}")
    for key in ("action", "category"):
        if not isinstance(expected.get(key), list) or not expected[key]:
            bad(f"{key} 必須是非空陣列")
    for action in expected["action"]:
        if action not in analyzer.ACTIONS:
            bad(f"action {action!r} 不合法")
    if expected.get("needs_human") not in (True, False, None):
        bad("needs_human 必須是 true / false / null")
    musts = [expected.get("must") or {}]
    for action, extra in (expected.get("if_action") or {}).items():
        if action not in analyzer.ACTIONS or not isinstance(extra, dict):
            bad(f"if_action.{action} 不合法")
        if extra.get("needs_human") not in (True, False, None):
            bad(f"if_action.{action}.needs_human 必須是 true / false / null")
        musts.append(extra.get("must") or {})
    patterns = list((expected.get("bonus") or {}).get("any") or [])
    for must in musts:
        for field, items in must.items():
            if field not in MUST_FIELDS or not isinstance(items, list):
                bad(f"must.{field} 不合法(只接受 {MUST_FIELDS} 的 regex 陣列)")
            patterns += items
    for pattern in patterns:
        try:
            re.compile(pattern)
        except (re.error, TypeError) as exc:
            bad(f"regex {pattern!r} 無法編譯:{exc}")


def load_cases(cases_dir: str | Path = CASES_DIR, only: list[str] | None = None) -> list[Case]:
    """Every `<case_id>/` holding context.json + expected.json, sorted by id.

    Raises ValueError for a requested id that does not exist or a malformed expected.json.
    """
    root = Path(cases_dir)
    found = sorted(p.name for p in root.iterdir()
                   if (p / "context.json").is_file() and (p / "expected.json").is_file()) \
        if root.is_dir() else []
    if only:
        missing = [c for c in only if c not in found]
        if missing:
            raise ValueError(f"找不到 eval case:{', '.join(missing)}(可用:{', '.join(found) or '無'})")
        found = [c for c in found if c in only]
    cases = []
    for case_id in found:
        expected = json.loads((root / case_id / "expected.json").read_text(encoding="utf-8"))
        _check_expected(case_id, expected)
        context = json.loads((root / case_id / "context.json").read_text(encoding="utf-8"))
        cases.append(Case(case_id, context, expected))
    return cases


def _field_text(verdict: dict, field: str) -> str:
    value = verdict.get(field)
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    return value if isinstance(value, str) else ""


def score(verdict: dict, expected: dict) -> dict:
    """{"checks": [{"name", "ok", "detail"}], "bonus": [{"pattern", "hit"}], "passed"}.

    `if_action[<verdict action>]` adds its needs_human / must on top of the base ones.
    """
    action = verdict.get("action")
    checks = [
        {"name": "action", "ok": action in expected["action"],
         "detail": f"{action!r} ∈ {expected['action']}"},
        {"name": "category", "ok": verdict.get("category") in expected["category"],
         "detail": f"{verdict.get('category')!r} ∈ {expected['category']}"},
    ]
    extra = (expected.get("if_action") or {}).get(action) or {}
    for want in (expected.get("needs_human"), extra.get("needs_human")):
        if want is not None:
            got = verdict.get("needs_human")
            checks.append({"name": "needs_human", "ok": got is want,
                           "detail": f"{got!r} == {want!r}"})
    for must in (expected.get("must") or {}, extra.get("must") or {}):
        for field, patterns in must.items():
            text = _field_text(verdict, field)
            for pattern in patterns:
                checks.append({"name": f"{field} ~ /{pattern}/",
                               "ok": re.search(pattern, text) is not None, "detail": text})
    whole = json.dumps(verdict, ensure_ascii=False)
    bonus = [{"pattern": p, "hit": re.search(p, whole) is not None}
             for p in (expected.get("bonus") or {}).get("any") or []]
    return {"checks": checks, "bonus": bonus, "passed": all(c["ok"] for c in checks)}


def count_elk_queries(run_dir: str | Path) -> tuple[int, int]:
    """(successful, failed) elk-query calls recorded in the run dir."""
    try:
        text = Path(run_dir, analyzer.ELK_RESULTS_FILE).read_text(errors="replace")
    except OSError:
        return 0, 0
    return len(_SUCCESS_HEADER.findall(text)), len(_FAILED_HEADER.findall(text))


def _check_spec(case: Case) -> CheckSpec | None:
    raw = case.context.get("check")
    if not isinstance(raw, dict):
        return None
    return CheckSpec(key=case.id, system=raw.get("system") or "", repo=raw.get("repo"),
                     deploy_ref=raw.get("deploy_ref") or "origin/HEAD",
                     never_silence=bool(raw.get("never_silence")))


def run_case(case: Case, run_dir: str | Path, *, model: str, escalation_model: str,
             timeout: int, systems=None, snapshot_dir: str | None = None,
             runner=analyzer.run_claude, clock=time.monotonic) -> dict:
    """Prepare the run dir and drive the session(s) the way Analyzer._analyze does, minus
    the budget gate and the store. Returns one report entry (see `run_eval`)."""
    run_dir = os.path.abspath(run_dir)
    os.makedirs(run_dir, exist_ok=True)
    Path(run_dir, "context.json").write_text(
        json.dumps(case.context, ensure_ascii=False, indent=2), encoding="utf-8")
    repo_paths = {rid: info["path"] for rid, info in (case.context.get("repos") or {}).items()}
    evidence = case.context.get("evidence")
    prompt = analyzer.build_prompt(repo_paths)
    add_dirs = list(repo_paths.values())
    if snapshot_dir and os.path.isdir(snapshot_dir):
        add_dirs.append(snapshot_dir)

    result = {"case": case.id, "run_dir": run_dir, "models": [], "escalated": False,
              "verdict": None, "problems": [], "final_model": None, "error": None}
    started = clock()

    def invoke(name: str) -> tuple[dict, list[str]]:
        Path(run_dir, "verdict.json").unlink(missing_ok=True)
        t0 = clock()
        try:
            verdict = runner(name, prompt, run_dir, add_dirs, timeout)
        finally:
            result["models"].append({"model": name, "seconds": round(clock() - t0, 1)})
        Path(run_dir, f"verdict.{name}.json").write_text(
            json.dumps(verdict, ensure_ascii=False, indent=2), encoding="utf-8")
        problems = analyzer.validate_verdict(verdict, repo_paths, evidence, run_dir)
        result["models"][-1].update(problems=problems, verdict=verdict)
        return verdict, problems

    try:
        verdict, problems = invoke(model)
        final_model = model
        if analyzer.should_escalate(verdict, problems, _check_spec(case), systems):
            result["escalated"] = True
            verdict, problems = invoke(escalation_model)
            final_model = escalation_model
        result.update(final_model=final_model, problems=problems, verdict=verdict)
        try:
            result["verdict"] = analyzer.Analyzer._finalize(
                verdict, problems, repo_paths, evidence, run_dir)
        except ValueError as exc:
            result["error"] = str(exc)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["seconds"] = round(clock() - started, 1)
    result["elk_queries"], result["elk_failed"] = count_elk_queries(run_dir)

    if result["verdict"] is None:
        result.update(status="ERROR", checks=[], bonus=[])
        return result
    scored = score(result["verdict"], case.expected)
    scored["checks"].insert(0, {"name": "驗證", "ok": result["error"] is None,
                                "detail": result["error"] or "通過 validate_verdict / _finalize"})
    result.update(checks=scored["checks"], bonus=scored["bonus"],
                  status="PASS" if all(c["ok"] for c in scored["checks"]) else "FAIL")
    return result


def run_eval(cases: list[Case], *, model: str, escalation_model: str, timeout: int,
             systems=None, snapshot_dir: str | None = None, runs: int = 1,
             runs_root: str | Path = RUNS_DIR, runner=analyzer.run_claude,
             now: datetime | None = None, clock=time.monotonic) -> dict:
    """Run every case `runs` times under `runs_root/<timestamp>/` and write report.json there."""
    stamp = (now or datetime.now(analyzer.TAIPEI)).strftime("%Y%m%d-%H%M%S")
    root = Path(runs_root, stamp)
    results = []
    for case in cases:
        for i in range(1, runs + 1):
            name = case.id if runs == 1 else f"{case.id}-{i}"
            entry = run_case(case, root / name, model=model, escalation_model=escalation_model,
                             timeout=timeout, systems=systems, snapshot_dir=snapshot_dir,
                             runner=runner, clock=clock)
            entry["run"] = i
            results.append(entry)
    report = {"timestamp": stamp, "model": model, "escalation_model": escalation_model,
              "runs": runs, "dir": str(root), "results": results,
              "passed": sum(r["status"] == "PASS" for r in results), "total": len(results)}
    root.mkdir(parents=True, exist_ok=True)
    (root / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    return report


def _width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _pad(text: str, width: int) -> str:
    return text + " " * (width - _width(text))


def format_report(report: dict) -> str:
    header = ("案例", "結果", "最終模型", "action", "category", "硬性", "加分", "ELK", "秒")
    rows = []
    for r in report["results"]:
        v = r["verdict"] or {}
        checks, bonus = r["checks"], r["bonus"]
        name = r["case"] if report["runs"] == 1 else f"{r['case']} #{r['run']}"
        model = (r["final_model"] or "-") + (" (升級)" if r["escalated"] else "")
        rows.append((name, r["status"], model, str(v.get("action", "-")),
                     str(v.get("category", "-")),
                     f"{sum(c['ok'] for c in checks)}/{len(checks)}",
                     f"{sum(b['hit'] for b in bonus)}/{len(bonus)}",
                     f"{r['elk_queries']}" + (f"+{r['elk_failed']}失敗" if r["elk_failed"] else ""),
                     f"{r['seconds']:.0f}"))
    widths = [max(_width(row[i]) for row in (header, *rows)) for i in range(len(header))]
    lines = [" | ".join(_pad(c, w) for c, w in zip(row, widths)) for row in (header, *rows)]
    lines.insert(1, "-+-".join("-" * w for w in widths))
    for r in report["results"]:
        failed = [c for c in r["checks"] if not c["ok"]]
        if r["error"] or failed:
            lines.append(f"\n✗ {r['case']}" + (f" #{r['run']}" if report["runs"] > 1 else ""))
            if r["error"]:
                lines.append(f"  錯誤:{r['error']}")
            for c in failed:
                lines.append(f"  {c['name']}:{' '.join(str(c['detail']).split())[:160]}")
    lines.append(f"\n通過 {report['passed']}/{report['total']} · 報告:{report['dir']}/report.json")
    return "\n".join(lines)
