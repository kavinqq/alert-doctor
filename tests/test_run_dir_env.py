import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from alert_doctor import __main__ as cli
from alert_doctor import analyzer


class RunDirEnvTest(unittest.TestCase):
    def test_claude_env_carries_the_run_dir(self):
        env = analyzer._claude_env("/runs/7")
        self.assertEqual(env[analyzer.RUN_DIR_ENV], "/runs/7")

    def test_run_claude_passes_its_cwd_as_run_dir(self):
        seen = {}

        def run(cmd, **kw):
            seen.update(kw)
            raise RuntimeError("stop")
        with mock.patch.object(analyzer, "resolve_cli", return_value="/bin/claude"):
            with self.assertRaises(Exception):
                analyzer.run_claude("sonnet", "p", "/runs/9", [], 5, run=run)
        self.assertEqual(seen["env"][analyzer.RUN_DIR_ENV], "/runs/9")

    def test_elk_query_logs_into_run_dir_even_after_cd(self):
        with tempfile.TemporaryDirectory() as run_dir, tempfile.TemporaryDirectory() as elsewhere:
            old = os.getcwd()
            os.chdir(elsewhere)
            try:
                with mock.patch.dict(os.environ, {analyzer.RUN_DIR_ENV: run_dir}):
                    runner = lambda cmd, **kw: SimpleNamespace(stdout="ok\n", stderr="", returncode=0)  # noqa: E731
                    cli.main(["elk-query", "count", "x", "--from", "now-1h"], elk_runner=runner)
            finally:
                os.chdir(old)
            self.assertTrue(os.path.exists(os.path.join(run_dir, cli.ELK_RESULTS_FILE)))
            self.assertFalse(os.path.exists(os.path.join(elsewhere, cli.ELK_RESULTS_FILE)))


if __name__ == "__main__":
    unittest.main()
