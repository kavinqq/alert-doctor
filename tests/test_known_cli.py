import argparse
import os
import unittest
from types import SimpleNamespace

from alert_doctor import known_cli, known_store
from alert_doctor.store import Store

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "known.example.toml")


class KnownCliTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.cfg = SimpleNamespace(known_path=EXAMPLE, db_path=":memory:")
        self.parser = argparse.ArgumentParser()
        known_cli.add_arguments(self.parser)
        self.lines = []

    def run_cli(self, *argv):
        args = self.parser.parse_args(argv)
        self.lines = []
        return known_cli.cmd_known(self.cfg, args, store=self.store, out=self.lines.append,
                                   clock=lambda: 1_792_523_100.0)

    @property
    def output(self):
        return "\n".join(self.lines)

    def test_add_link_show_unlink(self):
        self.assertEqual(self.run_cli("add", "ddsc", "--title", "廠商甲重啟", "--description", "凌晨"), 0)
        self.assertEqual(self.run_cli("add", "ddsc", "--title", "又一次"), 1)
        self.assertEqual(self.run_cli("link", "k1", "ddsc"), 0)
        self.assertEqual(known_store.lookup(self.store, "k1").entry.id, "ddsc")
        self.assertEqual(self.run_cli("show", "ddsc"), 0)
        self.assertIn("已連結 1 種錯誤", self.output)
        self.assertIn("k1", self.output)
        self.assertEqual(self.run_cli("unlink", "k1"), 0)
        self.assertEqual(self.run_cli("unlink", "k1"), 1)

    def test_link_days_and_show_lifecycle(self):
        self.run_cli("add", "ddsc", "--title", "廠商甲重啟")
        self.assertEqual(self.run_cli("link", "k1", "ddsc", "--days", "30"), 0)
        self.assertIn("2026-11-20 03:05 到期", self.output)
        known_store.record_hit(self.store, "k1", 1_792_523_100.0)
        self.run_cli("show", "ddsc")
        self.assertIn("2026-11-20 03:05 到期", self.output)
        self.assertIn("命中 1 次", self.output)

    def test_review_lists_links_to_look_at(self):
        day = 86400
        now = 1_792_523_100.0
        self.run_cli("add", "ddsc", "--title", "廠商甲重啟")
        known_store.link(self.store, "soon", "ddsc", now=now - 12 * day, sample_label="快到期")
        known_store.link(self.store, "gone", "ddsc", now=now - 20 * day, sample_label="已過期")
        self.assertEqual(self.run_cli("review"), 0)
        self.assertIn("3 天內到期 1 筆", self.output)
        self.assertIn("soon", self.output)
        self.assertIn("已過期(不再比對,恢復分析) 1 筆", self.output)
        self.assertIn("gone", self.output)
        self.assertIn("14 天沒有命中 0 筆", self.output)
        self.assertIn("7 天命中 ≥ 50 次 0 筆", self.output)

    def test_review_with_nothing_to_do(self):
        self.assertEqual(self.run_cli("review"), 0)
        self.assertIn("沒有需要複查的連結", self.output)

    def test_link_to_unknown_id_fails(self):
        self.assertEqual(self.run_cli("link", "k1", "nope"), 1)

    def test_show_unknown(self):
        self.assertEqual(self.run_cli("show", "nope"), 1)

    def test_bad_expires(self):
        self.assertEqual(self.run_cli("add", "x", "--title", "t", "--expires", "明天"), 1)

    def test_list_includes_windows_from_known_toml(self):
        self.run_cli("add", "ddsc", "--title", "廠商甲重啟")
        self.assertEqual(self.run_cli("list"), 0)
        self.assertIn("資料庫固定錯誤 1 筆", self.output)
        self.assertIn("known.toml 時段 4 筆", self.output)
        self.assertIn("ddsc-nightly-context", self.output)
        self.assertIn("03:00 62 號主機重啟", self.output)

    def test_search_covers_store_and_windows(self):
        self.run_cli("add", "x", "--title", "廠商甲 602 逾時")
        self.assertEqual(self.run_cli("search", "廠商甲"), 0)
        self.assertIn("廠商甲 602 逾時", self.output)
        self.assertIn("ddsc-nightly-restart", self.output)
        self.assertEqual(self.run_cli("search", "完全沒有"), 1)


if __name__ == "__main__":
    unittest.main()
