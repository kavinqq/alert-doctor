import os
import tempfile
import unittest

from alert_doctor import replies
from alert_doctor.analyzer import ELK_RESULTS_FILE, LOG_PROBLEM, validate_verdict

BASE = {"category": "external_dependency", "severity": "medium", "confidence": 0.8, "needs_human": True,
        "fix_in_system": "unknown", "evidence": [], "cause": "廠商乙未產出回檔", "impact": "開戶結果延遲",
        "project": "acme-sso"}
LOG = "10/20 09:00:00 | prod-app-oa-91 | 廠商乙回檔不存在"


def problems(v):
    with tempfile.TemporaryDirectory() as run_dir:
        with open(os.path.join(run_dir, ELK_RESULTS_FILE), "w") as f:
            f.write(f"$ elk-query recent 回檔\n{LOG}\n")
        return [p for p in validate_verdict(dict(v), {}, None, run_dir) if not p.startswith(LOG_PROBLEM)]


class ActionValidationTest(unittest.TestCase):
    def test_action_is_required_and_from_the_fixed_list(self):
        self.assertTrue(any("action" in p for p in problems({**BASE, "fix": ["x"]})))
        self.assertTrue(any("action" in p for p in problems({**BASE, "action": "maybe", "fix": ["x"]})))

    def test_observe_and_vendor_may_omit_steps(self):
        self.assertEqual(problems({**BASE, "category": "transient", "needs_human": False,
                                   "action": "observe", "fix": []}), [])
        self.assertEqual(problems({**BASE, "action": "vendor", "action_target": "廠商乙", "logs": [LOG]}), [])

    def test_code_check_and_investigate_need_steps(self):
        self.assertTrue(problems({**BASE, "category": "code_bug", "action": "fix_code", "fix": []}))
        self.assertTrue(problems({**BASE, "category": "noise", "action": "fix_check", "logs": [LOG]}))
        self.assertTrue(problems({**BASE, "category": "unknown", "confidence": 0.4,
                                  "action": "investigate", "fix": []}))


class ActionRenderTest(unittest.TestCase):
    def test_direction_is_first_line_then_steps(self):
        text = replies.verdict({**BASE, "action": "vendor", "action_target": "廠商乙",
                                "fix": ["請開戶窗口向廠商乙確認回檔時程"]})
        self.assertIn("*建議修正方法*:\n  📞 廠商 / 外部問題(廠商乙)\n  1. 請開戶窗口向廠商乙確認回檔時程", text)

    def test_direction_alone_when_no_steps(self):
        text = replies.verdict({**BASE, "action": "observe", "fix": []})
        self.assertIn("*建議修正方法*:\n  👀 不用修,待觀察\n\n", text)

    def test_every_direction_has_a_label(self):
        for action in ("fix_code", "fix_check", "observe", "vendor", "investigate"):
            self.assertNotIn(action, replies.verdict({**BASE, "action": action, "fix": ["a"]}))

    def test_old_verdict_without_action_still_renders_steps(self):
        text = replies.verdict({**BASE, "fix": ["a"]})
        self.assertIn("*建議修正方法*:\n  1. a", text)


if __name__ == "__main__":
    unittest.main()
