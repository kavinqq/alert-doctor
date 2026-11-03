import dataclasses
import json
import unittest

from alert_doctor.models import Category
from alert_doctor.parse import parse_message
from tests.test_collector import NOW, Base, FakeSlack, alert_text, msg, ts_at
from tests.test_fragments import CollectorReassemblyTest

GREEN = {"severity": "low", "action": "observe", "needs_human": False, "cause": "暫時性逾時"}


class DeletingSlack(FakeSlack):
    def __init__(self):
        super().__init__()
        self.deletes = []

    def delete_message(self, token, channel, ts):
        self.deletes.append((token, channel, ts))


def go_green(store, at):
    iid = store.read("SELECT id FROM incidents ORDER BY id LIMIT 1")[0][0]
    store.complete_analysis_with_purge(iid, GREEN, "m", at, channels=["C1"], analysis_text="🔍 分析")
    return iid


class PurgeCollectorTest(Base):
    def setUp(self):
        super().setUp()
        self.slack = DeletingSlack()
        self.cfg = dataclasses.replace(self.cfg, default_owners=("U0OWNER",))

    def make(self, **kw):
        return super().make(source_bot_token="xoxb-source", **kw)

    def first_alert_purged(self, c):
        self.feed(c, f"{NOW:.0f}.000001")
        self.handle_and_publish(c)
        self.assertEqual(len(self.slack.posts), 1)
        iid = go_green(self.store, self.now)
        c.purge()
        deleted = [d[2] for d in self.slack.deletes]
        first_reply = self.store.read("SELECT reply_ts FROM outbox WHERE kind='first'")[0][0]
        self.assertEqual(deleted, [f"{NOW:.0f}.000001", first_reply])
        return iid

    def test_purge_runs_in_loop_and_deletes_alert_and_first_reply(self):
        c = self.make()
        self.slack.history_result = [msg(ts_at(-10))]
        ticks = []

        def sleep(_):
            ticks.append(1)
            self.now += 5
            if len(ticks) == 6:
                go_green(self.store, self.now)

        c.run_forever(stop=lambda: len(ticks) >= 8, sleep=sleep)
        first_reply = self.store.read("SELECT reply_ts FROM outbox WHERE kind='first'")[0][0]
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(-10), first_reply])
        iid = self.store.read("SELECT id FROM incidents")[0][0]
        self.assertIsNone(self.store.get_report(iid, "C1"))
        self.assertEqual(self.store.purge_rows("incident_id=?", (iid,))[0]["state"], "done")

    def test_duplicate_after_green_joins_purge_no_first(self):
        c = self.make()
        self.first_alert_purged(c)
        posts = len(self.slack.posts)
        self.now += 120
        self.feed(c, f"{NOW + 120:.0f}.000001")
        self.handle_and_publish(c)
        self.assertEqual(len(self.slack.posts), posts)
        c.purge()
        self.assertEqual(self.slack.deletes[-1][2], f"{NOW + 120:.0f}.000001")
        pending = self.store.read("SELECT kind FROM outbox WHERE status='pending'")
        self.assertEqual(pending, [])

    def test_spike_after_purge_posts_new_first_with_tags(self):
        c = self.make()
        self.store.insert_message(parse_message("C1", ts_at(-8 * 86400), alert_text(code="OTHER")), NOW)
        for i in range(4):
            self.feed(c, ts_at(-300 + i))
        self.handle_and_publish(c)
        iid = self.store.read("SELECT id FROM incidents ORDER BY id DESC LIMIT 1")[0][0]
        self.store.claim_incident("w", NOW)
        self.store.complete_analysis_with_purge(iid, GREEN, "m", NOW - 60, channels=["C1"],
                                                analysis_text="🔍 分析")
        for _ in range(3):
            c.purge()
        self.assertIn(ts_at(-300), [d[2] for d in self.slack.deletes])
        spike = ts_at(-5)
        self.feed(c, spike)
        self.handle_and_publish(c)
        self.assertEqual(self.store.read("SELECT category FROM messages WHERE ts=?", (spike,)),
                         [("spike",)])
        channel, text, thread = self.slack.posts[-1]
        self.assertEqual(thread, spike)
        self.assertIn("<@U0OWNER>", text)
        self.assertEqual(self.store.get_report(iid, "C1")["root_ts"], spike)
        self.assertEqual(self.store.get_incident(iid).analysis_state, "pending")
        self.assertNotIn(spike, [d[2] for d in self.slack.deletes])

    def test_publisher_drops_post_into_deleted_thread(self):
        c = self.make()
        iid = self.first_alert_purged(c)
        self.store.enqueue_reply(incident_id=iid, channel="C1", kind="analysis", priority=1,
                                 due_epoch=self.now, thread_ts=f"{NOW:.0f}.000001",
                                 payload={"text": "遲到的分析"}, dedupe_key="late", now=self.now)
        posts = len(self.slack.posts)
        self.publish(c)
        self.assertEqual(len(self.slack.posts), posts)
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE dedupe_key='late'"),
                         [("dropped",)])

    def test_publisher_drops_post_into_pending_target(self):
        c = self.make()
        alert_ts = f"{NOW:.0f}.000001"
        self.feed(c, alert_ts)
        c.process_pending()
        iid = go_green(self.store, self.now)
        (pid,) = [r["id"] for r in self.store.purge_rows("incident_id=?", (iid,))]
        self.store.add_purge_targets(pid, "C1", "alert", [alert_ts])
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='first'"),
                         [("pending",)])
        self.publish(c)
        self.assertEqual(self.slack.posts, [])
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='first'"),
                         [("dropped",)])


class RootlessAnalysisTest(Base):
    def test_rootless_analysis_posts_top_level_and_becomes_the_report(self):
        c = self.make()
        self.feed(c, f"{NOW:.0f}.000001")
        c.process_pending()
        iid = self.store.read("SELECT id FROM incidents")[0][0]
        self.store.enqueue_reply(incident_id=iid, channel="C1", kind="analysis", priority=1,
                                 due_epoch=self.now, thread_ts=None, payload={"text": "🔍 新分析"},
                                 dedupe_key="a", now=self.now)
        self.store.read("SELECT 1")
        with self.store.tx() as db:
            db.execute("UPDATE outbox SET status='cancelled' WHERE kind='first'")
        self.publish(c)
        channel, text, thread = self.slack.posts[-1]
        self.assertIsNone(thread)
        self.assertTrue(text.startswith("🔍 新分析"))
        reply_ts = self.store.read("SELECT reply_ts FROM outbox WHERE dedupe_key='a'")[0][0]
        self.assertEqual(self.store.get_report(iid, "C1")["root_ts"], reply_ts)


class AnalysisOnSurvivingAlertTest(Base):
    def test_analysis_on_a_surviving_alert_rebuilds_the_report(self):
        c = self.make()
        alert_ts = f"{NOW:.0f}.000001"
        self.feed(c, alert_ts)
        c.process_pending()
        iid = self.store.read("SELECT id FROM incidents")[0][0]
        with self.store.tx() as db:
            db.execute("UPDATE outbox SET status='cancelled' WHERE kind='first'")
        self.store.enqueue_reply(incident_id=iid, channel="C1", kind="analysis", priority=1,
                                 due_epoch=self.now, thread_ts=alert_ts,
                                 payload={"text": "🔍 分析"}, dedupe_key="a", now=self.now)
        self.publish(c)
        self.assertEqual(self.slack.posts[-1][2], alert_ts)
        self.assertEqual(self.store.get_report(iid, "C1")["root_ts"], alert_ts)


class PurgeLateFragmentTest(CollectorReassemblyTest):
    def setUp(self):
        super().setUp()
        self.slack = DeletingSlack()

    def make(self, **kw):
        return super().make(source_bot_token="xoxb-source", **kw)

    def test_late_fragment_of_deleted_head_joins_and_no_reply(self):
        c = self.make()
        _, head, pieces = self.split()
        self.now = float(head["ts"]) + 0.2
        for message in [head, *pieces[:-1]]:
            self.feed_event(c, message)
        self.now = float(pieces[-2]["ts"]) + 16
        self.assertEqual(c.process_pending(), 1)
        self.publish(c)
        go_green(self.store, self.now)
        for _ in range(5):
            c.purge()
        self.assertIn(head["ts"], [d[2] for d in self.slack.deletes])
        self.now += 60
        self.feed_event(c, pieces[-1])
        self.assertEqual(self.store.read("SELECT 1 FROM outbox WHERE kind='late_fragment'"), [])
        c.purge()
        self.assertEqual(self.slack.deletes[-1][2], pieces[-1]["ts"])


if __name__ == "__main__":
    unittest.main()
