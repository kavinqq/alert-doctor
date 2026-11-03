import unittest

from alert_doctor import replies
from alert_doctor.hosts import format_hosts, hosts_in_text

SSO = ("[SSO] 檢查是否有M999的異常回應\n{'code': 'c', 'result': {'level': 40, 'message': \"['SSO']服務中出現異常關鍵字"
       "「['M999']」，請立即查看系統狀況！「{'remote_address': '198.51.100.253', 'server_hostname': 'prod-app-pxy-tc-101', "
       "'request_path': '/bcgw/user/login/'}」\"}}")
FASTPXY = 'x {"log": {"extra": {"server_ip": "192.0.2.76", "request_path": "/a"}}}'
ELK_LINE = "10/20 14:18:44 | prod-app-oa-91 | MOPEN_OUT.TXT 檔案存在"


class HostsInTextTest(unittest.TestCase):
    def test_server_hostname_not_client_address(self):
        self.assertEqual(hosts_in_text(SSO), ["prod-app-pxy-tc-101"])

    def test_server_ip_json_style(self):
        self.assertEqual(hosts_in_text(FASTPXY), ["192.0.2.76"])

    def test_backslash_escaped_quotes_as_in_real_slack_text(self):
        raw = ".24.1.253\\', \\'server_hostname\\': \\'prod-app-pxy-tc-101\\', \\'request_method"
        self.assertEqual(hosts_in_text(raw), ["prod-app-pxy-tc-101"])

    def test_nothing_found(self):
        self.assertEqual(hosts_in_text("ES連線出現異常:[10.0.0.100] Connection timed out"), [])
        self.assertEqual(hosts_in_text(ELK_LINE), [])


class FormatHostsTest(unittest.TestCase):
    def test_sorted_by_count_and_capped(self):
        counts = {"a": 1, "b": 3, "c": 2, "d": 1}
        self.assertEqual(format_hosts(counts), "b ×3、c ×2、a ×1 等 4 台")

    def test_single(self):
        self.assertEqual(format_hosts({"198.51.100.91": 1}), "198.51.100.91 ×1")

    def test_empty(self):
        self.assertEqual(format_hosts({}), "")


class RenderTest(unittest.TestCase):
    def test_first_report_lists_hosts_instead_of_bare_count(self):
        text = replies.first_report(decision_text="d", mentions=(),
                                    summary={"count": 2, "hosts": 1, "host_counts": {"198.51.100.91": 1}})
        self.assertIn("主機:198.51.100.91 ×1", text)
        self.assertNotIn("主機 1 台", text)

    def test_first_report_falls_back_to_count(self):
        text = replies.first_report(decision_text="d", mentions=(), summary={"count": 2, "hosts": 3})
        self.assertIn("主機 3 台", text)

    def test_minute_update_lists_hosts(self):
        text = replies.minute_update(incident_id=1, window_label="13:43", batch_count=2, total=5, hosts=2,
                                     changes=[], host_counts={"a": 4, "b": 1})
        self.assertIn("主機:a ×4、b ×1", text)
        self.assertNotIn("ELK", text)

    def test_elk_count_shown_when_samples_name_fewer_hosts(self):
        text = replies.minute_update(incident_id=14, window_label="20:03", batch_count=1, total=2, hosts=4,
                                     changes=[], host_counts={"prod-app-sb-93": 1, "prod-app-tw-192": 1})
        self.assertIn("主機:prod-app-sb-93 ×1、prod-app-tw-192 ×1 (ELK 共 4 台)", text)
        first = replies.first_report(decision_text="d", mentions=(),
                                     summary={"count": 1, "hosts": 2, "host_counts": {"prod-app-sb-93": 1}})
        self.assertIn("主機:prod-app-sb-93 ×1 (ELK 共 2 台)", first)


if __name__ == "__main__":
    unittest.main()
