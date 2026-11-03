import dataclasses
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from alert_doctor.archive import Archive
from alert_doctor.budget import Budgets
from alert_doctor.config import ChannelSpec, Config
from alert_doctor.models import ParsedAlert
from alert_doctor.publisher import Publisher, report_changes
from alert_doctor.slack_io import SlackError, SlackRateLimited
from alert_doctor.store import Store

NOW = 1_760_000_000.0
TAIPEI = timezone(timedelta(hours=8))


class FakeSlack:
    def __init__(self):
        self.posts, self.reactions, self.removed = [], [], []
        self.post_errors, self.reaction_errors = [], []

    def post_message(self, token, channel, text, thread_ts=None):
        if self.post_errors:
            raise self.post_errors.pop(0)
        self.posts.append((channel, text, thread_ts))
        return f"{NOW + 5000 + len(self.posts):.0f}.000001"

    def add_reaction(self, token, channel, ts, name):
        if self.reaction_errors:
            raise self.reaction_errors.pop(0)
        self.reactions.append((channel, ts, name))

    def remove_reaction(self, token, channel, ts, name):
        self.removed.append((channel, ts, name))


def ts_at(offset, n=0):
    return f"{NOW + offset:.0f}.{n:06d}"


class Base(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(workspace_url="https://w.slack.com",
                          channels=(ChannelSpec("C1", "alerts-a", ("sys",)),
                                    ChannelSpec("C2", "alerts-b", ("sys",))))
        self.store = Store(":memory:")
        self.slack = FakeSlack()
        self.now = NOW
        self.budgets = Budgets(self.cfg)
        self.pub = Publisher(self.cfg, self.store, self.slack, "xoxb", self.budgets,
                             clock=lambda: self.now)

    def occurrence(self, ts, channel="C1", incident_id=None, backfilled=False, raw_text="r"):
        alert = ParsedAlert(channel=channel, ts=ts, raw_text=raw_text, parse_ok=True,
                            check_title="[L3] 訂單檢查", check_code="ORS1")
        self.store.insert_message(alert, self.now)
        if incident_id is None:
            incident_id = self.store.create_incident(alert, "fp", "g").id
        else:
            self.store.attach(incident_id, alert)
        self.store.mark_handled(channel, ts, category="new", incident_id=incident_id,
                                fingerprint="fp", reply_ts=None, handled_epoch=self.now,
                                backfilled=backfilled)
        return incident_id

    def first(self, incident_id, ts, channel="C1", priority=1, **payload):
        body = {"decision_text": "🔍 新錯誤,已排入分析", "mentions": ["<@UDEF>"],
                "severity": None, "reaction": "mag", "severity_reaction": None,
                "reply_kind": "triage", "hosts": None}
        body.update(payload)
        return self.store.enqueue_reply(
            incident_id=incident_id, channel=channel, kind="first", priority=priority,
            due_epoch=self.now, thread_ts=ts, dedupe_key=f"first:{incident_id}:{channel}",
            payload=body, now=self.now)

    def update(self, incident_id, channel="C1", **payload):
        return self.store.enqueue_reply(
            incident_id=incident_id, channel=channel, kind="update", priority=2,
            due_epoch=self.now, dedupe_key=f"update:{incident_id}:{channel}",
            payload={"hosts": None, "severity": None, "severity_reaction": None, **payload},
            now=self.now)

    def tick(self, seconds=1.0):
        self.now += seconds
        return self.pub.process(self.now)

    def status(self, item_id):
        return self.store.read("SELECT status, attempts FROM outbox WHERE id=?", (item_id,))[0]


class FirstTests(Base):
    def test_first_posts_in_alert_thread_and_becomes_primary_report(self):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.occurrence(ts_at(-20), incident_id=inc)
        item = self.first(inc, anchor, severity="high", severity_reaction="large_orange_circle",
                          hosts=3)
        self.assertEqual(self.pub.process(self.now), 1)
        channel, text, thread = self.slack.posts[0]
        self.assertEqual((channel, thread), ("C1", anchor))
        self.assertTrue(text.startswith("<@UDEF>"))
        self.assertIn("本分鐘 2 則", text)
        self.assertIn("主機 3 台", text)
        report = self.store.get_report(inc, "C1")
        self.assertEqual((report["root_ts"], report["is_primary"], report["last_count"],
                          report["last_hosts"], report["last_severity"]),
                         (anchor, True, 2, 3, "high"))
        self.assertEqual(self.slack.reactions, [("C1", anchor, "mag"),
                                                ("C1", anchor, "large_orange_circle")])
        reply_ts = self.store.read("SELECT reply_ts FROM messages WHERE ts=?", (anchor,))[0][0]
        self.assertEqual(self.store.lookup_reply("C1", reply_ts), (anchor, inc, "triage"))
        self.assertEqual(self.status(item), ("sent", 0))

    def test_first_not_due_yet_waits(self):
        inc = self.occurrence(ts_at(-30))
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=1,
                                 due_epoch=self.now + 20, thread_ts=ts_at(-30), payload={})
        self.assertEqual(self.pub.process(self.now), 0)
        self.assertEqual(self.pub.process(self.now + 20), 1)

    def test_first_after_report_exists_is_posted_as_update_without_tags(self):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.first(inc, anchor)
        self.pub.process(self.now)
        self.occurrence(ts_at(-10), incident_id=inc)
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=1,
                                 due_epoch=self.now, thread_ts=ts_at(-10),
                                 payload={"mentions": ["<@UDEF>"], "decision_text": "x"})
        self.tick()
        self.assertEqual(len(self.slack.posts), 2)
        self.assertNotIn("<@", self.slack.posts[1][1])
        self.assertEqual(self.slack.posts[1][2], anchor)

    def test_reaction_failure_never_reposts(self):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        item = self.first(inc, anchor)
        self.slack.reaction_errors = [SlackError("boom")]
        self.pub.process(self.now)
        self.tick(3600)
        self.assertEqual(len(self.slack.posts), 1)
        self.assertEqual(self.status(item)[0], "sent")


class UpdateTests(Base):
    def setUp(self):
        super().setUp()
        self.anchor = ts_at(-300)
        self.inc = self.occurrence(self.anchor)
        self.first(self.inc, self.anchor, hosts=1, severity="high")
        self.pub.process(self.now)
        self.slack.posts.clear()

    def test_update_counts_new_occurrences_live_and_never_tags(self):
        for i in range(3):
            self.occurrence(ts_at(-200 + i), incident_id=self.inc)
        self.update(self.inc)
        self.tick()
        (channel, text, thread), = self.slack.posts
        self.assertEqual(thread, self.anchor)
        self.assertIn("3 則(累計 4 則)", text)
        self.assertNotIn("<@", text)
        self.assertNotIn("量級翻倍", text, "1 -> 4 is below MIN_DOUBLING_TOTAL")
        self.assertEqual(self.store.get_report(self.inc, "C1")["last_count"], 4)
        reply_ts = self.store.read("SELECT reply_ts FROM outbox WHERE kind='update'")[0][0]
        self.assertEqual(self.store.lookup_reply("C1", reply_ts), (self.anchor, self.inc, "update"))

    def test_update_without_new_occurrences_is_dropped_silently(self):
        item = self.update(self.inc)
        self.tick()
        self.assertEqual(self.slack.posts, [])
        self.assertEqual(self.status(item), ("dropped", 0))

    def test_host_increase_and_severity_upgrade_are_listed_and_reacted(self):
        self.occurrence(ts_at(-100), incident_id=self.inc)
        self.update(self.inc, hosts=4, severity="critical", severity_reaction="red_circle")
        self.tick()
        text = self.slack.posts[0][1]
        self.assertIn("ELK 主機數 1 → 4 台", text)
        self.assertIn("嚴重度升級為 🔴", text)
        self.assertIn(("C1", self.anchor, "red_circle"), self.slack.reactions)
        report = self.store.get_report(self.inc, "C1")
        self.assertEqual((report["last_hosts"], report["last_severity"]), (4, "critical"))

    def test_update_waits_for_pending_first(self):
        other = self.occurrence(ts_at(-50), channel="C2")
        self.first(other, ts_at(-50), channel="C2")
        self.occurrence(ts_at(-40), channel="C2", incident_id=other)
        item = self.update(other, channel="C2")
        with self.store.tx() as db:
            db.execute("UPDATE outbox SET due_epoch=? WHERE kind='first'", (self.now + 100,))
        self.tick()
        self.assertEqual(self.status(item), ("pending", 0))
        self.assertEqual(self.slack.posts, [])


class ReportChangesTests(unittest.TestCase):
    def test_changes(self):
        report = {"last_count": 10, "last_hosts": 2, "last_severity": "high"}
        self.assertEqual(report_changes(report, total=12, hosts=2, severity="high"), [])
        self.assertEqual(report_changes(report, total=20, hosts=3, severity="critical"),
                         ["量級翻倍", "嚴重度升級為 🔴", "ELK 主機數 2 → 3 台"])
        self.assertEqual(report_changes(report, total=11, hosts=None, severity="low"), [])


class PacingAndBudgetTests(Base):
    def test_one_post_per_channel_per_second(self):
        incs = [self.occurrence(ts_at(-30 + i, i)) for i in range(3)]
        for i, inc in enumerate(incs):
            self.first(inc, ts_at(-30 + i, i))
        self.assertEqual(self.pub.process(self.now), 1)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.store.read("SELECT MAX(attempts) FROM outbox")[0][0], 0)

    def test_channels_are_paced_independently(self):
        a = self.occurrence(ts_at(-30), channel="C1")
        b = self.occurrence(ts_at(-29), channel="C2")
        self.first(a, ts_at(-30), channel="C1")
        self.first(b, ts_at(-29), channel="C2")
        self.assertEqual(self.pub.process(self.now), 2)

    def test_exhausted_budget_defers_without_attempt_and_spares_critical_reserve(self):
        self.budgets.slack._shared = 0
        self.budgets.slack._reserve["first"] = 0
        normal = self.occurrence(ts_at(-30))
        self.store.upsert_report(normal, "C1", ts_at(-30), now=self.now)
        self.occurrence(ts_at(-29), incident_id=normal)
        item = self.update(normal)
        critical = self.occurrence(ts_at(-20), channel="C2")
        self.first(critical, ts_at(-20), channel="C2", priority=0)
        self.assertEqual(self.pub.process(self.now), 1)
        self.assertEqual(self.slack.posts[0][0], "C2")
        self.assertEqual(self.status(item), ("pending", 0))


class FailureTests(Base):
    def setUp(self):
        super().setUp()
        self.anchor = ts_at(-30)
        self.inc = self.occurrence(self.anchor)
        self.item = self.first(self.inc, self.anchor)

    def test_rate_limit_pauses_everything_without_attempts(self):
        other = self.occurrence(ts_at(-20), channel="C2")
        self.first(other, ts_at(-20), channel="C2")
        self.slack.post_errors = [SlackRateLimited(30)]
        self.assertEqual(self.pub.process(self.now), 0)
        self.assertEqual(self.tick(10), 0)
        self.assertEqual(self.store.read("SELECT MAX(attempts) FROM outbox")[0][0], 0)
        self.assertEqual(self.tick(21), 2)

    def test_network_error_does_not_spend_attempt(self):
        self.slack.post_errors = [OSError("down")]
        self.pub.process(self.now)
        self.assertEqual(self.status(self.item), ("pending", 0))
        self.assertEqual(self.tick(30), 1)

    def test_other_error_spends_attempt_and_backs_off(self):
        self.slack.post_errors = [SlackError("internal_error")]
        self.pub.process(self.now)
        self.assertEqual(self.status(self.item), ("pending", 1))
        self.assertEqual(self.tick(10), 0)
        self.assertEqual(self.tick(20), 1)


class OtherKindsTests(Base):
    def setUp(self):
        super().setUp()
        self.anchor = ts_at(-30)
        self.inc = self.occurrence(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.slack.posts.clear()
        self.slack.reactions.clear()

    def test_analysis_posts_in_report_thread_and_applies_root_reactions(self):
        self.store.enqueue_reply(
            incident_id=self.inc, channel="C1", kind="analysis", priority=1, due_epoch=self.now,
            thread_ts=self.anchor, dedupe_key=f"analysis:{self.inc}",
            payload={"text": "🟠 *分析結果*:x", "reactions_on_root": ["white_check_mark",
                                                                    "large_orange_circle"],
                     "remove_on_root": ["mag"]})
        self.tick()
        self.assertEqual(self.slack.posts, [("C1", "🟠 *分析結果*:x", self.anchor)])
        self.assertEqual(self.slack.removed, [("C1", self.anchor, "mag")])
        self.assertEqual(self.slack.reactions, [("C1", self.anchor, "white_check_mark"),
                                                ("C1", self.anchor, "large_orange_circle")])
        reply_ts = self.store.read("SELECT reply_ts FROM outbox WHERE kind='analysis'")[0][0]
        self.assertEqual(self.store.lookup_reply("C1", reply_ts), (self.anchor, self.inc, "analysis"))

    def test_link_to_primary_goes_to_secondary_report_root(self):
        root2 = ts_at(-25)
        self.occurrence(root2, channel="C2", incident_id=self.inc)
        self.store.upsert_report(self.inc, "C2", root2, now=self.now)
        link = self.cfg.permalink("C1", self.anchor)
        self.store.enqueue_reply(incident_id=self.inc, channel="C2", kind="link", priority=2,
                                 due_epoch=self.now, payload={"permalink": link})
        self.tick()
        (channel, text, thread), = self.slack.posts
        self.assertEqual((channel, thread), ("C2", root2))
        self.assertIn(link, text)

    def test_failure_text_without_any_root_is_dropped(self):
        self.store.enqueue_reply(incident_id=999, channel="C1", kind="failure", priority=1,
                                 due_epoch=self.now, payload={"text": "分析失敗"})
        self.tick()
        self.assertEqual(self.slack.posts, [])
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='failure'"),
                         [("dropped",)])

    def test_backfill_summary_counts_backfilled_and_absorbs_them(self):
        self.now += 10
        for i in range(3):
            self.occurrence(ts_at(-3600 + i * 60), incident_id=self.inc, backfilled=True)
        self.store.enqueue_reply(incident_id=self.inc, channel="C1", kind="backfill", priority=2,
                                 due_epoch=self.now, dedupe_key=f"backfill:{self.inc}:C1",
                                 payload={})
        self.tick()
        self.assertIn("補撈期間共 3 則", self.slack.posts[0][1])
        self.assertEqual(self.store.get_report(self.inc, "C1")["last_count"], 4)
        self.update(self.inc)
        self.tick()
        self.assertEqual(len(self.slack.posts), 1)

    def test_protection_notice_then_storm_in_its_thread(self):
        for i in range(5):
            self.occurrence(ts_at(i, i), incident_id=self.inc)
        other = self.occurrence(ts_at(10, 9), channel="C2")
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="protection", priority=0,
                                 due_epoch=self.now, payload={"entering": True, "reason": "量大",
                                                              "mentions": ["<@UDEF>"]})
        minute = int(NOW // 60)
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="storm", priority=2,
                                 due_epoch=self.now, dedupe_key=f"storm:{minute}",
                                 payload={"minute": minute})
        self.tick()
        self.tick()
        notice, storm = self.slack.posts
        self.assertIn("<@UDEF>", notice[1])
        self.assertIsNone(notice[2])
        notice_ts = self.store.read("SELECT reply_ts FROM outbox WHERE kind='protection'")[0][0]
        self.assertEqual(storm[2], notice_ts)
        self.assertIn(f"#{self.inc}", storm[1])
        self.assertIn(f"#{other}", storm[1])
        self.assertLess(storm[1].index(f"#{self.inc}"), storm[1].index(f"#{other}"))
        self.assertNotIn("<@", storm[1])
        self.assertEqual(self.store.lookup_reply("C1", notice_ts)[2], "protection")


class OccurrenceLineTests(Base):
    """`📊 出現次數` is looked up in the error archive when the post is sent."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.archive = Archive(os.path.join(tmp.name, "archive.db"))
        self.pub = Publisher(self.cfg, self.store, self.slack, "xoxb", self.budgets,
                             clock=lambda: self.now, archive=self.archive)
        self.anchor = ts_at(-30)
        self.inc = self.occurrence(self.anchor)

    def archived(self, ts, channel="C1", message="逾時 3 秒"):
        alert = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True,
                            check_title="[L3] 訂單檢查", check_code="ORS1", level=40,
                            result_message=message)
        self.archive.record_occurrence(alert, incident=None, category="new", severity=None,
                                       source_system="sys", task_label="L", task_pk=118)

    def test_first_post_gets_the_line_as_its_own_section(self):
        self.archived(ts_at(-3 * 86400))
        self.archived(ts_at(-60))
        self.archived(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        text = self.slack.posts[0][1]
        first_day = datetime.fromtimestamp(NOW - 3 * 86400, TAIPEI).strftime("%m/%d")
        self.assertTrue(text.endswith("\n\n📊 出現次數:今日 2 次 · 近 7 日 3 次 · 近 30 日 3 次"
                                      f" · 首次 {first_day}"), text)
        self.assertEqual(text.count("📊"), 1)

    def test_first_ever_occurrence(self):
        self.archived(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.assertTrue(self.slack.posts[0][1].endswith("\n\n📊 出現次數:近 30 日首次出現"))

    def test_missing_row_or_unavailable_archive_omits_the_line(self):
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.assertNotIn("📊", self.slack.posts[0][1])

        inc2 = self.occurrence(ts_at(-20, 1), channel="C2")
        self.archived(ts_at(-20, 1), channel="C2")
        self.first(inc2, ts_at(-20, 1), channel="C2")
        with mock.patch.object(self.archive, "key_of", side_effect=RuntimeError("boom")):
            self.tick()
        self.assertNotIn("📊", self.slack.posts[1][1])

    def test_no_archive_configured(self):
        self.pub = Publisher(self.cfg, self.store, self.slack, "xoxb", self.budgets,
                             clock=lambda: self.now, archive=None)
        self.archived(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.assertNotIn("📊", self.slack.posts[0][1])

    def test_analysis_post_gets_the_line_from_the_incident_anchor(self):
        self.archived(self.anchor)
        self.archived(ts_at(-10))
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.store.enqueue_reply(
            incident_id=self.inc, channel="C1", kind="analysis", priority=1, due_epoch=self.now,
            dedupe_key=f"analysis:{self.inc}", payload={"text": "🟠 *標題*\n\n*錯誤原因*:\n  x"})
        self.tick()
        text = self.slack.posts[-1][1]
        self.assertTrue(text.startswith("🟠 *標題*\n\n*錯誤原因*:\n  x\n\n📊 出現次數:今日 2 次"),
                        text)

    def test_update_and_other_kinds_never_get_the_line(self):
        self.archived(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.occurrence(ts_at(-5), incident_id=self.inc)
        self.archived(ts_at(-5))
        self.update(self.inc)
        self.store.enqueue_reply(incident_id=self.inc, channel="C1", kind="failure", priority=1,
                                 due_epoch=self.now, payload={"text": "分析失敗"})
        self.tick(200)
        self.tick(2)
        self.assertEqual(len(self.slack.posts), 3)
        for _, text, _ in self.slack.posts[1:]:
            self.assertNotIn("📊", text)


class ArchiveDiscoveryTests(unittest.TestCase):
    def test_relative_archive_path_is_never_opened(self):
        cfg = Config(workspace_url="https://w", channels=(ChannelSpec("C1", "a", ("s",)),))
        pub = Publisher(cfg, Store(":memory:"), FakeSlack(), "x", Budgets(cfg))
        with mock.patch("alert_doctor.archive.Archive") as opened:
            self.assertIsNone(pub.archive())
        opened.assert_not_called()

    def test_absolute_existing_archive_path_is_opened_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.db")
            cfg = Config(workspace_url="https://w", channels=(ChannelSpec("C1", "a", ("s",)),),
                         archive_db_path=path)
            pub = Publisher(cfg, Store(":memory:"), FakeSlack(), "x", Budgets(cfg))
            self.assertIsNone(pub.archive())
            self.assertFalse(os.path.exists(path))
            Archive(path)
            first = pub.archive()
            self.assertIsInstance(first, Archive)
            self.assertIs(pub.archive(), first)


if __name__ == "__main__":
    unittest.main()


class OverloadFirstTagTest(Base):
    def test_non_urgent_first_during_overload_is_not_tagged(self):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.store.set_protection("overload", "測試", self.now)
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=1,
                                 due_epoch=self.now, thread_ts=anchor, dedupe_key=f"first:{inc}:C1",
                                 payload={"decision_text": "🔍 新錯誤", "mentions": ["<@U1>"]})
        self.pub.process(self.now)
        (_, text, _), = self.slack.posts
        self.assertNotIn("<@U1>", text)
        self.assertIn("告警風暴中", text)

    def test_urgent_first_during_overload_still_tags(self):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.store.set_protection("overload", "測試", self.now)
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=0,
                                 due_epoch=self.now, thread_ts=anchor, dedupe_key=f"first:{inc}:C1",
                                 payload={"decision_text": "🚨 重要", "mentions": ["<@U1>"]})
        self.pub.process(self.now)
        self.assertIn("<@U1>", self.slack.posts[0][1])


class V3ReviewPublisherTests(Base):
    def test_notice_channel_prefers_report_channel_then_busiest_then_first(self):
        self.assertEqual(self.pub.notice_channel(), "C1")
        self.occurrence(ts_at(-700), channel="C1")
        self.occurrence(ts_at(-100), channel="C2")
        self.assertEqual(self.pub.notice_channel(), "C2")
        self.pub.cfg = dataclasses.replace(self.cfg, report_channel="C9")
        self.assertEqual(self.pub.notice_channel(), "C9")

    def overload_first(self, since_offset):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.store.set_protection("overload", "測試", self.now + since_offset)
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=1,
                                 due_epoch=self.now, thread_ts=anchor, dedupe_key=f"first:{inc}:C1",
                                 payload={"decision_text": "🔍 新錯誤", "mentions": ["<@U1>"]})
        self.pub.process(self.now)
        return self.slack.posts[0][1]

    def test_overload_untags_only_during_first_thirty_minutes(self):
        text = self.overload_first(-1799)
        self.assertNotIn("<@U1>", text)

    def test_overload_older_than_thirty_minutes_tags_again(self):
        text = self.overload_first(-1800)
        self.assertIn("<@U1>", text)
        self.assertNotIn("告警風暴中", text)

    def test_storm_lists_every_incident_of_the_minute(self):
        minute = int(NOW // 60)
        base = minute * 60 - NOW
        incs = []
        for i in range(15):
            inc = self.occurrence(ts_at(base + 1 + i, i))
            for j in range(15 - i):
                self.occurrence(ts_at(base + 1 + i, 100 + i * 20 + j), incident_id=inc)
            incs.append(inc)
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="storm", priority=2,
                                 due_epoch=self.now, dedupe_key=f"storm:{minute}",
                                 payload={"minute": minute})
        self.tick()
        text = self.slack.posts[0][1]
        for inc in incs:
            self.assertIn(f"#{inc} ", text)
        self.assertEqual(text.count("→"), 10)
        self.assertIn("其餘 5 件:", text)
        self.assertIn(f"#{incs[-1]} [L3] 訂單檢查 · 2 則", text)
        self.assertNotIn("延後", text)

    def test_storm_threads_under_notice_of_its_own_channel(self):
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="protection", priority=0,
                                 due_epoch=self.now, payload={"entering": True, "reason": "量大"})
        self.tick()
        for i in range(3):
            self.occurrence(ts_at(1, i), channel="C2")
        minute = int(self.now // 60)
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="storm", priority=2,
                                 due_epoch=self.now, dedupe_key=f"storm:{minute}",
                                 payload={"minute": minute})
        self.tick(2)
        notice, storm = self.slack.posts
        notice_ts = self.store.read("SELECT reply_ts FROM outbox WHERE kind='protection'")[0][0]
        self.assertEqual(storm[2], notice_ts)


class BackfillEpisodeTests(Base):
    def setUp(self):
        super().setUp()
        self.anchor = ts_at(-30)
        self.inc = self.occurrence(self.anchor)
        self.first(self.inc, self.anchor)
        self.pub.process(self.now)
        self.slack.posts.clear()

    def backfill(self):
        return self.store.enqueue_reply(
            incident_id=self.inc, channel="C1", kind="backfill", priority=2, due_epoch=self.now,
            dedupe_key=f"backfill:{self.inc}:C1", payload={}, now=self.now)

    def backfilled(self, n, start):
        for i in range(n):
            self.occurrence(ts_at(start + i * 60, i), incident_id=self.inc, backfilled=True)

    def test_summary_does_not_absorb_live_occurrences(self):
        self.now += 10
        self.backfilled(3, -3600)
        for i in range(2):
            self.occurrence(ts_at(5 + i), incident_id=self.inc)
        self.backfill()
        self.tick()
        self.assertIn("補撈期間共 3 則", self.slack.posts[0][1])
        self.assertEqual(self.store.get_report(self.inc, "C1")["last_count"], 4)
        self.update(self.inc)
        self.tick()
        self.assertIn("2 則(累計 6 則)", self.slack.posts[1][1])

    def test_second_summary_within_thirty_minutes_is_merged(self):
        self.now += 10
        self.backfilled(3, -3600)
        self.backfill()
        self.tick()
        self.now += 600
        self.backfilled(2, -3000)
        item = self.backfill()
        self.tick()
        self.assertEqual(len(self.slack.posts), 1)
        self.assertEqual(self.status(item)[0], "dropped")
        self.assertEqual(self.store.get_report(self.inc, "C1")["last_count"], 6)
        self.update(self.inc)
        self.tick()
        self.assertEqual(len(self.slack.posts), 1, "merged backfill is not re-reported live")

    def test_new_summary_after_thirty_minutes_counts_only_new_backfill(self):
        self.now += 10
        self.backfilled(3, -3600)
        self.backfill()
        self.tick()
        self.now += 1801
        self.backfilled(2, -3000)
        self.backfill()
        self.tick()
        self.assertEqual(len(self.slack.posts), 2)
        self.assertIn("補撈期間共 2 則", self.slack.posts[1][1])
        self.assertEqual(self.store.get_report(self.inc, "C1")["last_count"], 6)


class UntagWindowConfigTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg = dataclasses.replace(self.cfg, overload_untag_minutes=5)
        self.pub.cfg = self.cfg

    def post_first(self, since_offset):
        anchor = ts_at(-30)
        inc = self.occurrence(anchor)
        self.store.set_protection("overload", "測試", self.now + since_offset)
        self.store.enqueue_reply(incident_id=inc, channel="C1", kind="first", priority=1,
                                 due_epoch=self.now, thread_ts=anchor, dedupe_key=f"first:{inc}:C1",
                                 payload={"decision_text": "🔍 新錯誤", "mentions": ["<@U1>"]})
        self.pub.process(self.now)
        return self.slack.posts[-1][1]

    def test_tags_return_after_configured_minutes(self):
        self.assertIn("<@U1>", self.post_first(-300))

    def test_untagged_within_configured_minutes(self):
        self.assertNotIn("<@U1>", self.post_first(-299))

    def test_protection_notice_states_configured_window(self):
        self.store.enqueue_reply(incident_id=None, channel="C1", kind="protection", priority=0,
                                 due_epoch=self.now, payload={"entering": True, "reason": "量大"})
        self.pub.process(self.now)
        self.assertIn("前 5 分鐘", self.slack.posts[0][1])


class HostCountsTests(Base):
    def test_first_post_lists_hosts_quoted_in_the_alerts(self):
        anchor = ts_at(-60)
        inc = self.occurrence(anchor, raw_text="{'server_hostname': 'prod-app-sb-193'}")
        self.occurrence(ts_at(-50), incident_id=inc, raw_text="{'server_hostname': 'prod-app-sb-193'}")
        self.occurrence(ts_at(-40), incident_id=inc, raw_text="{'server_ip': '198.51.100.91'}")
        self.first(inc, anchor)
        self.pub.process(self.now)
        self.assertIn("主機:prod-app-sb-193 ×2、198.51.100.91 ×1", self.slack.posts[0][1])

    def test_falls_back_to_elk_evidence_hosts(self):
        anchor = ts_at(-60)
        inc = self.occurrence(anchor)
        self.store.save_evidence(inc, {"per_host": {"192.0.2.76": 4}})
        self.first(inc, anchor)
        self.pub.process(self.now)
        self.assertIn("主機:192.0.2.76 ×4", self.slack.posts[0][1])
