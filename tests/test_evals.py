import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from alert_doctor import __main__ as cli
from alert_doctor import analyzer, evals

LOG_LINE = "10/20 14:54:41 | f0e5236d7194 | T+1交割款不足自動通知結束"
EXPECTED = {
    "action": ["fix_check"],
    "category": ["noise"],
    "needs_human": None,
    "must": {"cause": ["14:54", "40 ?分"], "impact": ["無.*影響"], "fix": ["90|延長"]},
    "bonus": {"any": ["10/16"]},
}


def verdict(**over):
    base = {
        "category": "noise", "severity": "low", "confidence": 0.9,
        "cause": "14:54:41 才寫結束,超過 40 分鐘檢查窗", "impact": "無客戶影響",
        "project": "cms", "action": "fix_check", "fix": ["interval 由 40 改為 90"],
        "logs": [LOG_LINE], "fix_in_system": "unknown", "needs_human": False,
        "evidence": [{"type": "elk", "key": "total"}],
    }
    base.update(over)
    return base


def write_case(root, case_id, expected=EXPECTED, context=None):
    d = Path(root, case_id)
    d.mkdir(parents=True)
    (d / "context.json").write_text(json.dumps(context or {
        "repos": {}, "evidence": {"total": 3}, "check": None}, ensure_ascii=False))
    (d / "expected.json").write_text(json.dumps(expected, ensure_ascii=False))


class FakeRunner:
    """Returns the queued verdicts in order and logs one successful ELK query per call."""

    def __init__(self, *verdicts):
        self.verdicts = list(verdicts)
        self.calls = []

    def __call__(self, model, prompt, cwd, add_dirs, timeout):
        self.calls.append({"model": model, "prompt": prompt, "cwd": cwd, "add_dirs": add_dirs})
        with open(os.path.join(cwd, analyzer.ELK_RESULTS_FILE), "a") as f:
            f.write(f"{analyzer.ELK_QUERY_HEADER} recent x\n{LOG_LINE}\n\n")
        item = self.verdicts.pop(0)
        if isinstance(item, Exception):
            raise item
        return dict(item)


class ScoreTests(unittest.TestCase):
    def test_all_checks_pass(self):
        result = evals.score(verdict(remark="10/16 沒有結束 log"), EXPECTED)
        self.assertTrue(result["passed"])
        self.assertEqual([{"pattern": "10/16", "hit": True}], result["bonus"])

    def test_wrong_action_and_category_fail(self):
        result = evals.score(verdict(action="vendor", category="external_dependency"), EXPECTED)
        failed = {c["name"] for c in result["checks"] if not c["ok"]}
        self.assertEqual({"action", "category"}, failed)
        self.assertFalse(result["passed"])

    def test_each_regex_is_its_own_check(self):
        result = evals.score(verdict(cause="14:54 才結束"), EXPECTED)
        failed = [c["name"] for c in result["checks"] if not c["ok"]]
        self.assertEqual(["cause ~ /40 ?分/"], failed)

    def test_fix_list_is_searched_joined(self):
        ok = evals.score(verdict(fix=["改到 15:30 執行", "窗口延長"]), EXPECTED)
        self.assertTrue(ok["passed"])
        bad = evals.score(verdict(fix=[]), EXPECTED)
        self.assertIn("fix ~ /90|延長/", [c["name"] for c in bad["checks"] if not c["ok"]])

    def test_missing_field_fails_instead_of_raising(self):
        v = verdict()
        del v["impact"]
        self.assertFalse(evals.score(v, EXPECTED)["passed"])

    def test_bonus_miss_does_not_fail(self):
        result = evals.score(verdict(), EXPECTED)
        self.assertTrue(result["passed"])
        self.assertEqual([{"pattern": "10/16", "hit": False}], result["bonus"])

    def test_needs_human_null_is_not_checked(self):
        names = [c["name"] for c in evals.score(verdict(), EXPECTED)["checks"]]
        self.assertNotIn("needs_human", names)

    def test_needs_human_checked_when_set(self):
        expected = {**EXPECTED, "needs_human": True}
        result = evals.score(verdict(needs_human=False), expected)
        self.assertEqual(["needs_human"], [c["name"] for c in result["checks"] if not c["ok"]])

    def test_if_action_applies_only_to_matching_action(self):
        expected = {"action": ["observe", "fix_check"], "category": ["noise", "transient"],
                    "needs_human": None, "must": {},
                    "if_action": {"observe": {"needs_human": False},
                                  "fix_check": {"must": {"fix": ["放寬"]}}}}
        fix_check = evals.score(verdict(fix=["改 interval"]), expected)
        self.assertEqual(["fix ~ /放寬/"], [c["name"] for c in fix_check["checks"] if not c["ok"]])
        observe = evals.score(verdict(action="observe", category="transient", fix=[],
                                      needs_human=True), expected)
        self.assertEqual(["needs_human"], [c["name"] for c in observe["checks"] if not c["ok"]])


class LoadCasesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_loads_sorted_and_skips_incomplete_dirs(self):
        write_case(self.tmp.name, "b_case")
        write_case(self.tmp.name, "a_case")
        Path(self.tmp.name, "no_expected").mkdir()
        Path(self.tmp.name, "no_expected", "context.json").write_text("{}")
        cases = evals.load_cases(self.tmp.name)
        self.assertEqual(["a_case", "b_case"], [c.id for c in cases])
        self.assertEqual({"total": 3}, cases[0].context["evidence"])

    def test_only_filters_and_unknown_id_raises(self):
        write_case(self.tmp.name, "a_case")
        write_case(self.tmp.name, "b_case")
        self.assertEqual(["b_case"], [c.id for c in evals.load_cases(self.tmp.name, ["b_case"])])
        with self.assertRaisesRegex(ValueError, "nope"):
            evals.load_cases(self.tmp.name, ["nope"])

    def test_rejects_bad_expected(self):
        for bad in ({**EXPECTED, "action": ["shrug"]},
                    {**EXPECTED, "must": {"cause": ["(unclosed"]}},
                    {**EXPECTED, "must": {"remark": ["x"]}},
                    {**EXPECTED, "extra_key": 1},
                    {**EXPECTED, "category": []}):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as root:
                write_case(root, "c", expected=bad)
                with self.assertRaises(ValueError):
                    evals.load_cases(root)

    def test_shipped_cases_are_valid(self):
        # 真實事件的 eval case 含內部資料,公開版不附;本機有 evals/cases/ 才檢查
        if not evals.CASES_DIR.is_dir():
            self.skipTest("evals/cases/ not shipped")
        cases = {c.id: c for c in evals.load_cases()}
        for case in cases.values():
            self.assertIn("repos", case.context)


class RunCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        write_case(self.tmp.name, "c1")
        self.case = evals.load_cases(self.tmp.name)[0]
        self.run_dir = os.path.join(self.tmp.name, "out", "c1")

    def run_case(self, runner, **kw):
        return evals.run_case(self.case, self.run_dir, model="sonnet", escalation_model="opus",
                              timeout=10, runner=runner, **kw)

    def test_pass_without_escalation(self):
        runner = FakeRunner(verdict())
        result = self.run_case(runner)
        self.assertEqual("PASS", result["status"])
        self.assertEqual("sonnet", result["final_model"])
        self.assertFalse(result["escalated"])
        self.assertEqual((1, 0), (result["elk_queries"], result["elk_failed"]))
        self.assertTrue(Path(self.run_dir, "context.json").exists())
        self.assertTrue(Path(self.run_dir, "verdict.sonnet.json").exists())
        self.assertEqual(self.run_dir, runner.calls[0]["cwd"])

    def test_prompt_matches_analyzer(self):
        runner = FakeRunner(verdict())
        self.run_case(runner)
        self.assertEqual(analyzer.build_prompt({}), runner.calls[0]["prompt"])
        self.assertNotIn("__ELK_QUERY__", runner.calls[0]["prompt"])

    def test_snapshot_dir_added_when_present(self):
        runner = FakeRunner(verdict())
        self.run_case(runner, snapshot_dir=self.tmp.name)
        self.assertEqual([self.tmp.name], runner.calls[0]["add_dirs"])

    def test_low_confidence_escalates_and_reports_final_model(self):
        runner = FakeRunner(verdict(confidence=0.3), verdict())
        result = self.run_case(runner)
        self.assertEqual(["sonnet", "opus"], [c["model"] for c in runner.calls])
        self.assertTrue(result["escalated"])
        self.assertEqual("opus", result["final_model"])
        self.assertEqual("PASS", result["status"])
        self.assertEqual(2, result["elk_queries"])

    def test_unrepairable_verdict_fails_validation_check(self):
        bad = verdict(action="fix_check", category="code_bug")
        result = self.run_case(FakeRunner(bad, bad))
        self.assertEqual("FAIL", result["status"])
        self.assertFalse(result["checks"][0]["ok"])
        self.assertEqual("驗證", result["checks"][0]["name"])

    def test_runner_error_is_reported(self):
        result = self.run_case(FakeRunner(RuntimeError("claude 失敗 rc=1")))
        self.assertEqual("ERROR", result["status"])
        self.assertIn("claude 失敗", result["error"])

    def test_run_eval_writes_report_and_table(self):
        report = evals.run_eval([self.case], model="sonnet", escalation_model="opus",
                                timeout=10, runs=2, runs_root=os.path.join(self.tmp.name, "runs"),
                                runner=FakeRunner(verdict(), verdict(cause="x")),
                                now=datetime(2026, 10, 20, 17, 0, tzinfo=analyzer.TAIPEI))
        path = Path(self.tmp.name, "runs", "20261020-170000", "report.json")
        saved = json.loads(path.read_text())
        self.assertEqual((1, 2), (saved["passed"], saved["total"]))
        self.assertTrue(Path(self.tmp.name, "runs", "20261020-170000", "c1-2").is_dir())
        table = evals.format_report(report)
        self.assertIn("通過 1/2", table)
        self.assertIn("cause ~ /14:54/", table)


class CliTests(unittest.TestCase):
    def test_eval_command_wires_config(self):
        report = {"passed": 1, "total": 1}
        cfg_path = Path(__file__).resolve().parent.parent / "config.example.toml"
        with mock.patch.object(evals, "load_cases", return_value=["case"]) as load, \
                mock.patch.object(evals, "run_eval", return_value=report) as run, \
                mock.patch.object(evals, "format_report", return_value="table"), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["eval", "--config", str(cfg_path), "--case", "x",
                             "--model", "haiku", "--runs", "3"])
        self.assertEqual(0, code)
        load.assert_called_once_with(only=["x"])
        kwargs = run.call_args.kwargs
        self.assertEqual(("haiku", 3), (kwargs["model"], kwargs["runs"]))
        self.assertIn("table", out.getvalue())


if __name__ == "__main__":
    unittest.main()
