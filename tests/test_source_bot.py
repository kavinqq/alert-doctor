import os
import tempfile
import unittest

from alert_doctor import __main__ as cli
from alert_doctor.collector import is_source_message
from alert_doctor.config import load_config

SOURCE = {"ts": "1.0", "bot_id": "B01SRCBOT00", "text": "x"}
HUMAN = {"ts": "2.0", "user": "U01EEEEEEEE", "text": "先試運行一陣子喔"}
OTHER_BOT = {"ts": "3.0", "bot_id": "BOTHER", "text": "x"}


class SourceFilterTest(unittest.TestCase):
    def test_only_configured_bots_when_set(self):
        ids = ("B01SRCBOT00",)
        self.assertTrue(is_source_message(SOURCE, ids))
        self.assertFalse(is_source_message(HUMAN, ids))
        self.assertFalse(is_source_message(OTHER_BOT, ids))

    def test_unconfigured_keeps_old_behaviour(self):
        self.assertTrue(is_source_message(HUMAN, ()))

    def test_backfill_filter_uses_source_bots(self):
        self.assertTrue(cli._is_top_level_alert(SOURCE, ("B01SRCBOT00",)))
        self.assertFalse(cli._is_top_level_alert(HUMAN, ("B01SRCBOT00",)))

    def test_config_reads_source_bot_ids(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.toml")
            with open(path, "w", encoding="utf-8") as f:
                f.write('workspace_url = "https://x"\nsource_bot_ids = ["B01SRCBOT00"]\n'
                        '[[channels]]\nid = "C1"\nname = "n"\nsystems = []\n')
            self.assertEqual(load_config(path).source_bot_ids, ("B01SRCBOT00",))


if __name__ == "__main__":
    unittest.main()
