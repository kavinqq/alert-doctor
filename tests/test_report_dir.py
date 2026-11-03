import contextlib
import io
import tempfile
import types
import unittest
import unittest.mock
from pathlib import Path

from alert_doctor import __main__ as cli
from alert_doctor.config import Config, load_config


class ReportDirTest(unittest.TestCase):
    def test_without_channel_report_is_written_to_report_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(channels=(), workspace_url="https://x.slack.com", report_dir=str(Path(tmp, "reports")))
            with contextlib.redirect_stderr(io.StringIO()):
                code = cli._post_report(cfg, None, "📊 日報", "daily-2026-10-21")
            self.assertEqual(code, 0)
            self.assertEqual(Path(tmp, "reports", "daily-2026-10-21.md").read_text(), "📊 日報\n")

    def test_relative_report_dir_resolves_next_to_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "config.toml")
            path.write_text('workspace_url = "https://x.slack.com"\n'
                            '[[channels]]\nid = "C1"\nname = "alerts-a"\nsystems = []\n')
            self.assertEqual(Path(load_config(str(path)).report_dir), Path(tmp, "reports").resolve())

    def test_with_channel_report_is_posted(self):
        posts = []
        slack = types.SimpleNamespace(post_message=lambda token, ch, text: posts.append((ch, text)))
        cfg = Config(channels=(), workspace_url="https://x.slack.com", report_channel="C1")
        with unittest.mock.patch.object(cli, "_bot_token", lambda cfg: "t"):
            self.assertEqual(cli._post_report(cfg, slack, "x", "daily-2026-10-21"), 0)
        self.assertEqual(posts, [("C1", "x")])


if __name__ == "__main__":
    unittest.main()
