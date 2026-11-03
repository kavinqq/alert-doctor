import os
import tempfile
import unittest

from alert_doctor import analyzer
from alert_doctor.analyzer import Analyzer, should_escalate, validate_verdict
from alert_doctor.models import CheckSpec

LOG = "10/20 15:37:02 | 203.0.113.76 | T+1交割款不足自動通知結束"
CODE = {"type": "code", "repo": "r", "file": "app/a.py", "line": 2, "note": "n"}
COMMON = {"severity": "medium", "cause": "c", "impact": "i", "project": "r",
          "fix_in_system": "unknown", "evidence": []}
BASES = {
    "fix_code": {"category": "code_bug", "needs_human": False, "confidence": 0.8,
                 "fix": ["msg_helper.py 取 phone 改用 .get()"], "evidence": [CODE]},
    "fix_check": {"category": "noise", "needs_human": False, "confidence": 0.8,
                  "fix": ["檢查窗由 40 分鐘延長到 90 分鐘"], "logs": [LOG]},
    "ops": {"category": "infra", "needs_human": True, "confidence": 0.8,
            "fix": ["ELK 10.0.0.100 檢查 heap 與慢查詢"], "logs": [LOG]},
    "observe": {"category": "transient", "needs_human": False, "confidence": 0.8, "fix": []},
    "vendor": {"category": "external_dependency", "needs_human": True, "confidence": 0.8,
               "action_target": "廠商乙", "fix": [], "logs": [LOG]},
    "investigate": {"category": "unknown", "needs_human": True, "confidence": 0.4,
                    "fix": ["查 10/20 14:00 後 203.0.113.76 的 ERROR 與重啟紀錄"]},
}


def verdict(base, **kw):
    return {**COMMON, "action": base, **BASES[base], **kw}


class MatrixBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = os.path.join(tmp.name, "repo")
        os.makedirs(os.path.join(self.repo, "app"))
        with open(os.path.join(self.repo, "app", "a.py"), "w") as f:
            f.write("one\ntwo\nthree\n")
        self.run_dir = tmp.name
        with open(os.path.join(tmp.name, analyzer.ELK_RESULTS_FILE), "w") as f:
            f.write(f"$ elk-query recent '結束' --size 1\n{LOG}\n\n")

    def problems(self, v, **kw):
        return analyzer._blocking(validate_verdict(v, {"r": self.repo}, None, self.run_dir, **kw))

    def assertRejected(self, v, needle):
        found = self.problems(v)
        self.assertTrue(any(needle in p for p in found), (needle, found))


class ActionMatrixTest(MatrixBase):
    def test_every_base_is_valid(self):
        for action in BASES:
            self.assertEqual(self.problems(verdict(action)), [], action)

    def test_category_must_match_action(self):
        allowed = {"fix_code": ("code_bug", "config"), "fix_check": ("noise",),
                   "ops": ("infra", "config"),
                   "observe": ("transient", "noise", "infra"), "vendor": ("external_dependency",),
                   "investigate": ("unknown", "infra")}
        for action, categories in allowed.items():
            for category in sorted(analyzer.CATEGORIES):
                v = verdict(action, category=category)
                if category in categories:
                    self.assertEqual(self.problems(v), [], (action, category))
                else:
                    self.assertRejected(v, "category")

    def test_unknown_or_missing_action(self):
        self.assertRejected(verdict("observe", action="maybe"), "action")
        v = verdict("observe")
        del v["action"]
        self.assertRejected(v, "action")

    def test_steps_required_for_code_check_and_investigate(self):
        for action in ("fix_code", "fix_check", "investigate"):
            self.assertRejected(verdict(action, fix=[]), "fix 至少")
            v = verdict(action)
            del v["fix"]
            self.assertRejected(v, "fix 至少")

    def test_fix_code_needs_code_evidence_logs_are_not_enough(self):
        self.assertRejected(verdict("fix_code", evidence=[], logs=[LOG]), "code 類 evidence")

    def test_check_and_vendor_need_code_or_real_log(self):
        for action in ("fix_check", "vendor"):
            self.assertRejected(verdict(action, logs=[]), "真實 log")
            self.assertRejected(verdict(action, logs=["10/20 15:00:00 | invented"]), "真實 log")
            self.assertEqual(self.problems(verdict(action, logs=[], evidence=[CODE])), [])

    def test_observe_must_not_need_a_human(self):
        self.assertRejected(verdict("observe", needs_human=True), "needs_human")

    def test_vendor_and_investigate_need_a_human(self):
        for action in ("vendor", "investigate"):
            self.assertRejected(verdict(action, needs_human=False), "needs_human")

    def test_vendor_target(self):
        for target in (None, "", "  ", 3):
            v = verdict("vendor", action_target=target)
            self.assertRejected(v, "action_target")
        self.assertRejected(verdict("vendor", action_target="奇" * 21), "action_target")
        self.assertEqual(self.problems(verdict("vendor", action_target="奇" * 20)), [])

    def test_target_only_for_vendor(self):
        for action in ("fix_code", "fix_check", "observe", "investigate"):
            v = verdict(action, action_target="廠商乙")
            self.assertEqual(self.problems(v), [])
            self.assertIsNone(v["action_target"])
            self.assertEqual(self.problems(verdict(action, action_target="")), [])

    def test_investigate_confidence_capped(self):
        self.assertEqual(self.problems(verdict("investigate", confidence=0.6)), [])
        self.assertRejected(verdict("investigate", confidence=0.7), "confidence")


class FixItemsTest(MatrixBase):
    def test_surplus_items_dropped(self):
        v = verdict("fix_code", fix=["改 a.py", "改 b.py", "改 c.py", "改 d.py"])
        self.assertEqual(self.problems(v), [])
        self.assertEqual(v["fix"], ["改 a.py", "改 b.py", "改 c.py"])

    def test_length_never_rejects_a_step(self):
        self.assertEqual(self.problems(verdict("fix_code", fix=["改" * 120])), [])
        v = verdict("fix_code", fix=["改" * 121])
        self.assertEqual(analyzer._blocking(self.problems(v)), [])
        self.assertEqual(v["fix"], ["改" * 119 + "…"])

    def test_vague_whole_items_rejected(self):
        for item in ("查 log", "查log。", "確認問題", "持續觀察", "請相關人員確認", " 確認問題! "):
            self.assertRejected(verdict("investigate", fix=[item]), "空泛")

    def test_vague_words_inside_a_concrete_step_are_fine(self):
        v = verdict("investigate", fix=["查 log:10/20 14:00 後 203.0.113.76 有無重啟"])
        self.assertEqual(self.problems(v), [])

    def test_observe_steps_are_also_checked(self):
        self.assertRejected(verdict("observe", fix=["持續觀察"]), "空泛")
        self.assertEqual(self.problems(verdict("observe", fix=["若明天 14:40 再發生,看結束 log 時間"])), [])


class EscalationAndFinalizeTest(MatrixBase):
    def test_matrix_violation_escalates(self):
        v = verdict("observe", category="code_bug")
        problems = validate_verdict(v, {"r": self.repo}, None, self.run_dir)
        self.assertTrue(should_escalate(v, problems, CheckSpec(key="k")))

    def test_valid_verdict_does_not_escalate(self):
        v = verdict("fix_check")
        self.assertFalse(should_escalate(v, validate_verdict(v, {"r": self.repo}, None, self.run_dir),
                                         CheckSpec(key="k")))

    def test_finalize_raises_on_matrix_violation(self):
        v = verdict("fix_code", fix=[])
        problems = validate_verdict(v, {"r": self.repo}, None, self.run_dir)
        with self.assertRaises(ValueError):
            Analyzer._finalize(v, problems, {"r": self.repo}, None, self.run_dir)

    def test_finalize_repairs_observe_with_bad_citation(self):
        v = verdict("observe", evidence=[{"type": "elk", "key": "nope"}])
        problems = validate_verdict(v, {"r": self.repo}, None, self.run_dir)
        repaired = Analyzer._finalize(v, problems, {"r": self.repo}, None, self.run_dir)
        self.assertEqual(repaired["evidence"], [])
        self.assertTrue(repaired["needs_human"])

    def test_finalize_dropping_the_only_code_citation_of_fix_code_raises(self):
        v = verdict("fix_code", evidence=[{**CODE, "line": 99}])
        problems = validate_verdict(v, {"r": self.repo}, None, self.run_dir)
        with self.assertRaises(ValueError):
            Analyzer._finalize(v, problems, {"r": self.repo}, None, self.run_dir)


class FullLineLogMatchTest(MatrixBase):
    def setUp(self):
        super().setUp()
        with open(os.path.join(self.run_dir, analyzer.ELK_RESULTS_FILE), "w") as f:
            f.write("$ elk-query recent x --size 3\n"
                    "# 區間內最新 3 筆\n"
                    "10/20 14:00:01 | h1 | T+1交割款不足自動通知開始 run=1 sent=10\n"
                    "10/20 14:00:07 | h1 | KeyError:   'phone' in msg_helper\n"
                    "\n"
                    "# failed: elk-query count x --from bad (exit 1)\n"
                    "10/20 14:00:09 | h1 | ES 400 parse_exception\n"
                    "\n")

    def kept(self, logs):
        v = verdict("observe", logs=list(logs))
        validate_verdict(v, {}, None, self.run_dir)
        return v["logs"]

    def test_whole_line_with_timestamp_and_whitespace_normalised(self):
        logs = ["10/20 14:00:01 | h1 | T+1交割款不足自動通知開始 run=1 sent=10",
                "2026-10-20T14:00:07+08:00 h1 | KeyError: 'phone' in msg_helper"]
        self.assertEqual(self.kept(logs), logs)

    def test_prefix_or_partial_line_is_rejected(self):
        self.assertEqual(self.kept(["10/20 14:00:01 | h1 | T+1交割款不足自動通知開始"]), [])
        self.assertEqual(self.kept(["10/20 14:00:01 | h1 | T+1交割款不足自動通知開始 run=1 sent=99"]), [])

    def test_failed_query_output_and_comments_are_not_logs(self):
        self.assertEqual(self.kept(["10/20 14:00:09 | h1 | ES 400 parse_exception",
                                    "# 區間內最新 3 筆"]), [])

    def test_evidence_samples_no_longer_count(self):
        v = verdict("observe", logs=["ConnectionError: broker down"])
        validate_verdict(v, {}, {"samples": [{"message": "ConnectionError: broker down"}]},
                         self.run_dir)
        self.assertEqual(v["logs"], [])

    def test_stored_line_stays_raw(self):
        raw = "10/20 14:00:07 | h1 | KeyError:   'phone' in msg_helper"
        self.assertEqual(self.kept([raw]), [raw])


class PromptRulesTest(unittest.TestCase):
    def setUp(self):
        self.text = analyzer.PROMPT_PATH.read_text()

    def test_decisive_conditions_before_querying(self):
        self.assertIn("判定條件", self.text)
        self.assertIn("不要寫進 `verdict.json`", self.text)

    def test_fixed_query_plan_within_budget(self):
        self.assertIn("### 查詢計畫", self.text)
        self.assertIn("最多 8 次", self.text)
        self.assertIn("前 3 個交易日", self.text)
        self.assertIn("10 次", self.text)
        self.assertNotIn("12 次", self.text)

    def test_boundary_only_logs_rule(self):
        self.assertIn("「還沒看到結束 log」本身不能說成中斷", self.text)

    def test_exact_time_formats_and_failure_warning(self):
        for fragment in ("2026-10-20T14:00:00+08:00", "now-2h", "格式錯誤"):
            self.assertIn(fragment, self.text)

    def test_cjk_phrases_match_log_message(self):
        self.assertIn("log.message", self.text)
        self.assertIn("中文片語", self.text)

    def test_quantified_section(self):
        self.assertIn("### 量化:跑太久 / 量太多時一定要算數字", self.text)
        self.assertIn("2,431", self.text)

    def test_action_boundaries(self):
        self.assertIn("只有在外部表現比歷史明顯異常時才選 `vendor`", self.text)
        self.assertIn("一定要先查歷史", self.text)
        self.assertIn("不要叫人去找廠商確認一件每天都會發生的事", self.text)
        self.assertIn("完全不需要任何後續處置", self.text)
        for action, categories in analyzer.ACTION_CATEGORIES.items():
            self.assertIn(f"`{action}`", self.text)

    def test_example_verdict_passes_the_matrix(self):
        import json
        import re
        block = re.search(r"範例:\s*```json\n(.*?)```", self.text, re.S)[1]
        example = json.loads(block)
        self.assertEqual(analyzer._check_action(example), [])
        self.assertEqual(analyzer._check_fixes(example["fix"], example["action"]), [])


if __name__ == "__main__":
    unittest.main()


class OpsActionTest(unittest.TestCase):
    def test_infra_needing_hands_is_ops(self):
        from alert_doctor.analyzer import validate_verdict
        from alert_doctor import replies
        v = {"category": "infra", "severity": "high", "confidence": 0.8, "needs_human": True,
             "fix_in_system": "unknown", "cause": "ELK 10.0.0.100 查詢逾時", "impact": "watchdog 檢查失明",
             "project": "elk", "action": "ops", "fix": ["ELK 10.0.0.100 檢查 heap 與慢查詢"],
             "evidence": [], "logs": []}
        problems = validate_verdict(dict(v), {}, None)
        self.assertTrue(any("佐證" in p or "evidence" in p or "log" in p for p in problems))
        self.assertIn("🧰 需維運處理", replies.verdict(v))
