import unittest

from alert_doctor import replies
from alert_doctor.models import ParsedAlert
from alert_doctor.rules import load_rules


class DatasourceReplyTest(unittest.TestCase):
    def test_reply_states_elk_failure_and_reason(self):
        alert = ParsedAlert(channel="C1", ts="1.0", raw_text="", parse_ok=True,
                            check_title="查不到關鍵字就報錯",
                            result_message="ES連線出現異常，請立即檢查：[10.0.0.100] Connection timed out")
        text = replies.datasource(alert, ())
        self.assertIn("ELK 查詢失敗", text)
        self.assertIn("[10.0.0.100] Connection timed out", text)
        self.assertIn("查不到關鍵字就報錯", text)

    def test_reply_mentions_owners_when_given(self):
        alert = ParsedAlert(channel="C1", ts="1.0", raw_text="", parse_ok=True, check_title="t",
                            result_message="ES連線出現異常")
        self.assertIn("<@U1>", replies.datasource(alert, ("<@U1>",)))

    def test_example_rules_route_es_connection_errors_to_datasource(self):
        from alert_doctor.rules import match_rule
        rules = load_rules("rules.example.toml")
        alert = ParsedAlert(channel="C1", ts="1.0", raw_text="", parse_ok=True,
                            check_title="[check_oa_file_return]久未收到開戶檔案 通知", check_code="x",
                            result_message="ES連線出現異常，請立即檢查：[10.0.0.100] Connection timed out")
        self.assertEqual(match_rule(rules, alert, 1792400000.0).action, "datasource")


if __name__ == "__main__":
    unittest.main()
