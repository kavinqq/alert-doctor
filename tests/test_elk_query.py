import contextlib
import io
import tempfile
import types
import unittest
from pathlib import Path

from alert_doctor import __main__ as cli
from alert_doctor import analyzer
from alert_doctor.config import Config

ISO_FROM = "2026-10-20T14:00:00+08:00"


class QueryCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cwd = tmp.name
        self.calls = []

    def runner(self, code=0, stdout="3\n", stderr=""):
        def run(cmd, **kw):
            self.calls.append((cmd, kw))
            return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        return run

    def query(self, argv, run=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_elk_query(argv, run=run or self.runner(), cli_path="/x/elk.py",
                                     cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def results(self):
        path = Path(self.cwd, cli.ELK_RESULTS_FILE)
        return path.read_text() if path.exists() else ""


class BudgetTest(QueryCase):
    def test_limit_and_timeout_fit_the_llm_timeout(self):
        self.assertEqual(cli.ELK_QUERY_LIMIT, 10)
        self.assertEqual(cli.ELK_QUERY_TIMEOUT, 45)
        self.assertLess(cli.ELK_QUERY_LIMIT * cli.ELK_QUERY_TIMEOUT, Config.llm_timeout)

    def test_timeout_passed_to_elk_cli(self):
        self.query(["count", "x", "--from", "now-2h"])
        self.assertEqual(self.calls[0][1]["timeout"], 45)

    def test_failed_queries_are_recorded_but_not_counted(self):
        for _ in range(3):
            code, _, _ = self.query(["count", "x"], self.runner(code=1, stdout="", stderr="ES 400\n"))
            self.assertEqual(code, 1)
        self.assertEqual(self.results().count("# failed: elk-query count x"), 3)
        self.assertNotIn("$ elk-query", self.results())
        for _ in range(cli.ELK_QUERY_LIMIT):
            self.assertEqual(self.query(["count", "x"])[0], 0)
        code, _, err = self.query(["count", "x"])
        self.assertEqual(code, 2)
        self.assertIn("上限", err)

    def test_successful_query_recorded_under_query_header(self):
        self.query(["count", "x"])
        self.assertTrue(self.results().startswith(f"{analyzer.ELK_QUERY_HEADER} count x\n3\n"))

    def test_bad_time_formats_rejected_without_running_or_counting(self):
        for bad in ("2026-10-20T14:00:00 14:20:00+08:00", "2026-10-20T+08:00", "2026-10-20T14:00:00",
                    "yesterday", "now-2x", "14:00", ""):
            for flag in (["--from", bad], ["--to", bad], [f"--from={bad}"]):
                code, _, err = self.query(["count", "x", *flag])
                self.assertEqual(code, 2, (flag, err))
                self.assertIn("+08:00", err)
        self.query(["count", "x", "--from"])
        self.assertEqual(self.calls, [])
        self.assertNotIn("$ elk-query", self.results())
        for _ in range(cli.ELK_QUERY_LIMIT):
            self.assertEqual(self.query(["count", "x"])[0], 0)

    def test_accepted_time_formats(self):
        for good in (ISO_FROM, "2026-10-20T14:00:00.5+08:00", "2026-10-20T06:00:00Z",
                     "now", "now-2h", "now-30m", "now-1d/d"):
            code, _, err = self.query(["count", "x", "--from", good, "--to", "now"])
            self.assertEqual(code, 0, (good, err))


class PhraseQueryTest(QueryCase):
    def phrase_call(self):
        self.assertEqual(len(self.calls), 1)
        cmd, kw = self.calls[0]
        self.assertEqual(cmd[1], "/x/elk.py")
        self.assertEqual(kw["timeout"], cli.ELK_QUERY_TIMEOUT)
        return cmd[2:]

    def test_cjk_count_runs_elk_cli_with_exact_limit_and_prefixes_count(self):
        argv = ["count", "T+1交割款不足自動通知結束", "--from", ISO_FROM, "--to", "now",
                "--where", "log.tags=PKMS"]
        code, out, _ = self.query(argv, run=self.runner(stdout="42\n"))
        self.assertEqual(code, 0)
        self.assertEqual(out, "count: 42\n")
        self.assertEqual(self.phrase_call(), [*argv, "--exact-limit", str(cli.PHRASE_EXACT_LIMIT)])
        self.assertIn("$ elk-query count 'T+1交割款不足自動通知結束' --from", self.results())
        self.assertIn("count: 42", self.results())

    def test_approximate_count_is_marked_as_upper_bound(self):
        err = "# ⚠ 近似上界:log.message 上「每個字都出現」(AND)候選 80000 筆\n"
        _, out, _ = self.query(["count", "請求處理完成", "--from", ISO_FROM],
                               run=self.runner(stdout="80000\n", stderr=err))
        self.assertEqual(out, "count: ≤80000(近似上界,見下方 ⚠ 說明)\n")
        self.assertIn("⚠ 近似上界", self.results())

    def test_model_exact_loose_and_parallel_are_dropped_for_cjk(self):
        self.query(["timeline", "結束", "--from", ISO_FROM, "--exact", "--loose",
                    "--parallel", "4", "--parallel=2", "--interval", "1h"])
        args = self.phrase_call()
        self.assertEqual(args, ["timeline", "結束", "--from", ISO_FROM, "--interval", "1h",
                                "--exact-limit", str(cli.PHRASE_EXACT_LIMIT)])
        self.calls.clear()
        self.query(["recent", "結束", "--from", ISO_FROM, "--loose", "--exact"])
        args = self.phrase_call()
        self.assertEqual(args.count("--exact"), 1)
        self.assertNotIn("--loose", args)

    def test_parallel_without_value_keeps_the_next_flag(self):
        self.query(["count", "結束", "--parallel", "--from", ISO_FROM, "--parallel"])
        self.assertEqual(self.phrase_call(), ["count", "結束", "--from", ISO_FROM,
                                              "--exact-limit", str(cli.PHRASE_EXACT_LIMIT)])

    def test_ascii_phrase_passes_through_unchanged(self):
        self.query(["count", "Token error", "--from", "now-1h"])
        self.assertEqual(self.phrase_call(), ["count", "Token error", "--from", "now-1h"])

    def test_cjk_phrase_needs_from(self):
        code, _, err = self.query(["count", "結束"])
        self.assertEqual(code, 2)
        self.assertIn("--from", err)
        self.assertEqual(self.calls, [])

    def test_recent_asks_for_host_column_long_message_and_default_size(self):
        self.query(["recent", "結束", "--from", ISO_FROM])
        args = self.phrase_call()
        self.assertEqual(args[args.index("--show") + 1], cli.RECENT_HOST_COLUMN)
        self.assertEqual(args[args.index("--msg-chars") + 1], cli.RECENT_MESSAGE_CHARS)
        self.assertEqual(args[args.index("--size") + 1], cli.RECENT_DEFAULT_SIZE)
        self.assertIn("--exact", args)
        self.calls.clear()
        self.query(["recent", "結束", "--size", "3", "--from", ISO_FROM])
        self.assertEqual(self.phrase_call().count("--size"), 1)

    def test_recent_lines_pass_log_verification(self):
        stdout = ("# 區間內最新 1 筆(index=logs-generic-default, field=log.message)\n"
                  "10/20 15:37:02 | prod-cms-1 | T+1交割款不足自動通知結束\n")
        _, out, _ = self.query(["recent", "結束", "--from", ISO_FROM], run=self.runner(stdout=stdout))
        line = out.splitlines()[1]
        v = {"logs": [line, "10/20 15:37:02 | prod-cms-1 | T+1交割款不足自動通知"]}
        analyzer._check_logs(v, self.cwd)
        self.assertEqual(v["logs"], [line])

    def test_timeline_output_passes_through(self):
        stdout = "10/20 14:00:00  3\n10/20 15:00:00  2\n"
        code, out, _ = self.query(["timeline", "發簡訊成功", "--interval", "1h", "--from", ISO_FROM],
                                  run=self.runner(stdout=stdout))
        self.assertEqual((code, out), (0, stdout))

    def test_bad_interval_rejected_without_running(self):
        code, _, _ = self.query(["timeline", "結束", "--from", ISO_FROM, "--interval", "5 min"])
        self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])

    def test_cli_failure_is_recorded_as_failed_and_not_counted(self):
        code, _, err = self.query(["count", "結束", "--from", ISO_FROM],
                                  run=self.runner(code=1, stdout="", stderr="候選探測 逾時或 shard 失敗\n"))
        self.assertEqual(code, 1)
        self.assertIn("shard 失敗", err)
        self.assertIn("# failed: elk-query count '結束' --from", self.results())
        self.assertNotIn("$ elk-query", self.results())

    def test_bad_where_rejected_without_counting(self):
        code, _, err = self.query(["count", "結束", "--from", ISO_FROM, "--where", "log.tags"])
        self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])

if __name__ == "__main__":
    unittest.main()
