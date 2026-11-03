import unittest

from alert_doctor.parse import parse_message
from alert_doctor.redact import for_slack, redact


class SecretStripTest(unittest.TestCase):
    TEXT = ("[check_log_message]檢查\n{'code': 'c1', 'task_id': 't', 'vkwargs': {'crontab_task_pk': 118, "
            "'access': 'eyJ1c2VybmFtZSI6ICJlIn0=', 'db_passwd': 'p@ss', 'elk_host': '10.0.0.100', "
            "'uri': 'mongodb://u:pw@10.0.0.1:27017/db'}, 'result': {'level': 40, 'message': 'ES連線出現異常'}}")

    def test_secret_kwargs_removed_even_without_pii_redaction(self):
        alert = parse_message("C1", "1.0", self.TEXT)
        vk = alert.extra["vkwargs"]
        self.assertEqual((vk["access"], vk["db_passwd"]), ("<redacted>", "<redacted>"))
        self.assertEqual(vk["crontab_task_pk"], 118)
        self.assertEqual(vk["uri"], "mongodb://<redacted>@10.0.0.1:27017/db")
        for secret in ("eyJ1c2VybmFtZSI6ICJlIn0=", "p@ss", "u:pw@"):
            self.assertNotIn(secret, alert.raw_text)
        self.assertEqual(alert.result_message, "ES連線出現異常")


class RedactTest(unittest.TestCase):
    def test_taiwan_ids_and_resident_certificates(self):
        self.assertEqual(redact('"A123456789", "F226950585"'), '"[身分證]", "[身分證]"')
        self.assertEqual(redact("居留證 A812345678 舊式 AB12345678"), "居留證 [身分證] 舊式 [身分證]")

    def test_mobile_numbers(self):
        self.assertEqual(redact("聯絡 0912345678 或 0912-345-678"), "聯絡 [手機] 或 [手機]")

    def test_leaves_codes_and_ids_that_are_not_pii(self):
        text = "ORS111 task 6bfe206f-1f7c status 504 10.0.0.100 A12345678"
        self.assertEqual(redact(text), text)

    def test_parse_keeps_text_as_is_by_default(self):
        alert = parse_message("C1", "1.0", "T\n{'code': 'c', 'result': {'level': 40, 'message': 'A123456789 失敗'}}")
        self.assertEqual(alert.result_message, "A123456789 失敗")

    def test_parse_message_redacts_when_enabled(self):
        text = "[check_log_message]檢查\n{'code': 'c1', 'task_id': 't', 'vkwargs': {'ids': ['A123456789']}, 'result': {'level': 40, 'message': '名單 F226950585 失敗'}}"
        alert = parse_message("C1", "1.0", text, redact_pii=True)
        self.assertTrue(alert.parse_ok)
        self.assertNotIn("A123456789", alert.raw_text)
        self.assertEqual(alert.result_message, "名單 [身分證] 失敗")
        self.assertEqual(alert.extra["vkwargs"]["ids"], ["[身分證]"])

    def test_same_template_for_different_people(self):
        from alert_doctor.fingerprint import fine_fp
        a = parse_message("C1", "1.0", "T\n{'code': 'c', 'result': {'level': 40, 'message': 'A123456789 失敗'}}")
        b = parse_message("C1", "2.0", "T\n{'code': 'c', 'result': {'level': 40, 'message': 'F226950585 失敗'}}")
        self.assertEqual(fine_fp(a), fine_fp(b))


class ForSlackTest(unittest.TestCase):
    def test_bare_and_quoted_secrets_and_pii_masked(self):
        line = ("login_token 21O4obuGox6mYHmpOg4U, api_key=abcdefgh12, {'password': 'p@ss'} "
                "https://u:pw@h/x A123456789 0912-345-678")
        self.assertEqual(for_slack(line),
                         "login_token <redacted>, api_key=<redacted>, {'password': '<redacted>'} "
                         "https://<redacted>@h/x [身分證] [手機]")

    def test_ordinary_text_untouched(self):
        line = "10/20 14:00:01 | T+1交割款不足自動通知開始 token error count 3"
        self.assertEqual(for_slack(line), line)


if __name__ == "__main__":
    unittest.main()
