import io
import contextlib
import os
import tempfile
import unittest
from types import SimpleNamespace

from alert_doctor import __main__ as cli
from alert_doctor.replies import pretty_log

RAW = ('10/20 14:18:44 | {"@timestamp": "2026-10-20T06:18:44.108Z", "@version": "1", '
       '"message": "MOPEN_OUT.TXT \\u6a94\\u6848\\u5b58\\u5728\\uff0c\\u9032\\u884crename\\u8655\\u7406", '
       '"host": "prod-app-oa-91", "path')
TRUNCATED_ESCAPE = ('10/20 14:40:30 | {"@timestamp": "2026-10-20T06:40:30.770Z", '
                    '"message": "(CWNU9)\\u4ea4\\u5272 =&gt; {\'code\': \'N001\', \'message\': \'\\u5df2\\u')


class PrettyLogTest(unittest.TestCase):
    def test_json_log_line_becomes_time_host_message(self):
        self.assertEqual(pretty_log(RAW), "10/20 14:18:44 prod-app-oa-91 MOPEN_OUT.TXT 檔案存在，進行rename處理")

    def test_truncated_unicode_escape_and_html_entities(self):
        self.assertEqual(pretty_log(TRUNCATED_ESCAPE), "10/20 14:40:30 (CWNU9)交割 => {'code': 'N001', 'message': '已")

    def test_our_own_query_format_is_left_alone(self):
        line = "10/20 15:37:02 | 203.0.113.76 | T+1交割款不足自動通知結束"
        self.assertEqual(pretty_log(line), line)

    def test_empty_message_falls_back_to_raw_line(self):
        line = '10/20 14:00:00 | {"message": "", "host": "h1"}'
        self.assertEqual(pretty_log(line), line)

    def test_host_kept_and_message_never_dropped(self):
        line = '10/20 14:00:00 | {"host": "h1", "message": "boom \\u4ea4"}'
        self.assertEqual(pretty_log(line), "10/20 14:00:00 h1 boom 交")

    def test_unparseable_input_returns_raw(self):
        line = '10/20 14:00:00 | {"message": "\\ud800 lone surrogate", "host": "h1"}'
        self.assertEqual(pretty_log(line), line)

    def test_plain_lines_are_left_alone(self):
        self.assertEqual(pretty_log("10/20 14:00:07 | KeyError: 'phone'"), "10/20 14:00:07 | KeyError: 'phone'")


class ElkQueryLimitTest(unittest.TestCase):
    def test_refuses_after_the_query_limit(self):
        with tempfile.TemporaryDirectory() as d:
            run = lambda cmd, **kw: SimpleNamespace(stdout="ok\n", stderr="", returncode=0)  # noqa: E731
            codes = []
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                for _ in range(cli.ELK_QUERY_LIMIT + 1):
                    codes.append(cli.cmd_elk_query(["count", "x"], run=run, cli_path="/elk.py", cwd=d))
            self.assertEqual(codes[:-1], [0] * cli.ELK_QUERY_LIMIT)
            self.assertEqual(codes[-1], 2)
            self.assertIn("上限", err.getvalue())
            with open(os.path.join(d, cli.ELK_RESULTS_FILE), encoding="utf-8") as f:
                self.assertEqual(f.read().count("$ elk-query"), cli.ELK_QUERY_LIMIT)


if __name__ == "__main__":
    unittest.main()
