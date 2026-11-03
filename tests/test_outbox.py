import os
import sqlite3
import tempfile
import unittest

from alert_doctor.models import ParsedAlert
from alert_doctor.store import MAX_OUTBOX_ATTEMPTS, Store

CH = "C1"


def alert(ts, channel=CH):
    return ParsedAlert(
        channel=channel, ts=ts, raw_text="raw", parse_ok=True, check_title="T",
        check_code="c1", task_id="t", level=3, result_message="msg", extra={},
        mentions=(),
    )


def enqueue(s, **kw):
    args = dict(incident_id=1, channel=CH, kind="update", priority=2, due_epoch=100.0,
                payload={"n": 1})
    args.update(kw)
    return s.enqueue_reply(**args)


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_payload_roundtrip(self):
        enqueue(self.s, payload={"text": "中文", "l": [1]}, thread_ts="5.5",
                dedupe_key="k")
        (item,) = self.s.claim_outbox(100)
        self.assertEqual(item.payload, {"text": "中文", "l": [1]})
        self.assertEqual((item.thread_ts, item.dedupe_key, item.attempts, item.kind),
                         ("5.5", "k", 0, "update"))

    def test_dedupe_merges_unsent_row(self):
        a = enqueue(self.s, dedupe_key="k", due_epoch=200.0, payload={"v": 1}, priority=2)
        b = enqueue(self.s, dedupe_key="k", due_epoch=150.0, payload={"v": 2}, priority=1)
        c = enqueue(self.s, dedupe_key="k", due_epoch=900.0, payload={"v": 3}, priority=2)
        self.assertEqual(a, b)
        self.assertEqual(a, c)
        self.assertEqual(self.s.outbox_stats(1000)["pending"], 1)
        (item,) = self.s.claim_outbox(1000)
        self.assertEqual((item.payload, item.due_epoch, item.priority),
                         ({"v": 3}, 150.0, 1))

    def test_dedupe_after_send_creates_new_row(self):
        a = enqueue(self.s, dedupe_key="k")
        self.s.complete_outbox(a, "9.9", 101)
        self.assertNotEqual(enqueue(self.s, dedupe_key="k"), a)

    def test_merge_skips_row_leased_by_publisher(self):
        a = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 1})
        self.s.claim_outbox(100, lease_seconds=60)
        b = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 2}, now=110)
        self.assertNotEqual(a, b)
        self.s.complete_outbox(a, "9.9", 111)
        (item,) = self.s.claim_outbox(200)
        self.assertEqual((item.id, item.payload), (b, {"v": 2}))

    def test_merge_into_row_whose_lease_expired(self):
        a = enqueue(self.s, dedupe_key="k", payload={"v": 1})
        self.s.claim_outbox(100, lease_seconds=60)
        self.assertEqual(enqueue(self.s, dedupe_key="k", payload={"v": 2}, now=161), a)
        (item,) = self.s.claim_outbox(161)
        self.assertEqual(item.payload, {"v": 2})

    def test_retry_of_leased_row_yields_to_newer_sibling(self):
        a = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 1}, due_epoch=50.0,
                    priority=1)
        self.s.claim_outbox(100)
        b = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 2}, due_epoch=120.0,
                    priority=2, now=110)
        self.s.retry_outbox(a, "boom", 130.0)
        self.assertEqual(self.s.outbox_stats(200)["pending"], 1)
        (item,) = self.s.claim_outbox(200)
        self.assertEqual((item.id, item.payload, item.due_epoch, item.priority),
                         (b, {"v": 2}, 50.0, 1))

    def test_crashed_lease_and_newer_sibling_claim_only_newest(self):
        a = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 1})
        self.s.claim_outbox(100, lease_seconds=60)
        b = enqueue(self.s, kind="analysis", dedupe_key="k", payload={"v": 2}, now=110)
        got = self.s.claim_outbox(500)
        self.assertEqual([(i.id, i.payload) for i in got], [(b, {"v": 2})])
        self.assertEqual(self.s.read("SELECT status FROM outbox WHERE id=?", (a,)),
                         [("superseded",)])

    def test_drop_removes_without_counting_as_sent_or_failed(self):
        i = enqueue(self.s, dedupe_key="k")
        self.s.claim_outbox(100)
        self.s.drop_outbox(i, "沒有新的告警", 101)
        stats = self.s.outbox_stats(200)
        self.assertEqual((stats["pending"], stats["failed"]), (0, 0))
        self.assertNotEqual(enqueue(self.s, dedupe_key="k"), i)

    def test_no_dedupe_key_never_merges(self):
        self.assertNotEqual(enqueue(self.s), enqueue(self.s))

    def test_claim_order_and_due_filter(self):
        late = enqueue(self.s, priority=0, due_epoch=500.0)
        p2 = enqueue(self.s, priority=2, due_epoch=10.0)
        p1b = enqueue(self.s, priority=1, due_epoch=20.0)
        p1a = enqueue(self.s, priority=1, due_epoch=5.0)
        tie = enqueue(self.s, priority=1, due_epoch=20.0)
        got = [i.id for i in self.s.claim_outbox(100)]
        self.assertEqual(got, [p1a, p1b, tie, p2])
        self.assertNotIn(late, got)

    def test_claim_limit(self):
        for _ in range(5):
            enqueue(self.s)
        self.assertEqual(len(self.s.claim_outbox(100, limit=3)), 3)

    def test_lease_blocks_then_expires(self):
        enqueue(self.s)
        self.assertEqual(len(self.s.claim_outbox(100, lease_seconds=60)), 1)
        self.assertEqual(self.s.claim_outbox(130), [])
        self.assertEqual(len(self.s.claim_outbox(160)), 1)

    def test_complete_removes_from_queue(self):
        i = enqueue(self.s)
        self.s.claim_outbox(100)
        self.s.complete_outbox(i, "9.9", 101)
        self.assertEqual(self.s.claim_outbox(10_000), [])
        self.assertEqual(self.s.outbox_stats(200)["pending"], 0)

    def test_retry_reschedules_and_counts(self):
        i = enqueue(self.s)
        self.s.claim_outbox(100)
        self.s.retry_outbox(i, "boom", 300.0)
        self.assertEqual(self.s.claim_outbox(200), [])
        (item,) = self.s.claim_outbox(300)
        self.assertEqual((item.id, item.attempts), (i, 1))

    def test_retry_without_counting(self):
        i = enqueue(self.s)
        for _ in range(MAX_OUTBOX_ATTEMPTS + 2):
            self.s.retry_outbox(i, "429", 100.0, count_attempt=False)
        (item,) = self.s.claim_outbox(100)
        self.assertEqual(item.attempts, 0)

    def test_eighth_attempt_fails(self):
        i = enqueue(self.s)
        for _ in range(MAX_OUTBOX_ATTEMPTS - 1):
            self.s.retry_outbox(i, "boom", 100.0)
        self.assertEqual(self.s.outbox_stats(200)["failed"], 0)
        self.s.retry_outbox(i, "boom", 100.0)
        stats = self.s.outbox_stats(200)
        self.assertEqual((stats["failed"], stats["pending"]), (1, 0))
        self.assertEqual(self.s.claim_outbox(10_000), [])

    def test_failed_row_does_not_block_new_dedupe(self):
        i = enqueue(self.s, dedupe_key="k")
        for _ in range(MAX_OUTBOX_ATTEMPTS):
            self.s.retry_outbox(i, "boom", 100.0)
        self.assertNotEqual(enqueue(self.s, dedupe_key="k"), i)

    def test_stats(self):
        enqueue(self.s, kind="first", priority=0, due_epoch=40.0)
        enqueue(self.s, kind="update", priority=2, due_epoch=10.0)
        enqueue(self.s, kind="update", priority=2, due_epoch=20.0)
        enqueue(self.s, kind="link", priority=2, due_epoch=9999.0)
        stats = self.s.outbox_stats(100)
        self.assertEqual(stats["pending"], 4)
        self.assertEqual(stats["by_kind"], {"first": 1, "update": 2, "link": 1})
        self.assertEqual(stats["oldest_pending_age"], 90)
        self.assertEqual(stats["oldest_critical_age"], 60)
        self.assertEqual(stats["failed"], 0)

    def test_stats_empty(self):
        stats = self.s.outbox_stats(100)
        self.assertIsNone(stats["oldest_pending_age"])
        self.assertIsNone(stats["oldest_critical_age"])
        self.assertEqual(stats["by_kind"], {})


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_first_channel_is_primary(self):
        self.s.upsert_report(1, "A", "1.1", now=10)
        self.s.upsert_report(1, "B", "2.2", now=20)
        self.assertTrue(self.s.get_report(1, "A")["is_primary"])
        self.assertFalse(self.s.get_report(1, "B")["is_primary"])
        primary = self.s.primary_report(1)
        self.assertEqual((primary["root_ts"], primary["channel"]), ("1.1", "A"))
        self.assertIsNone(self.s.primary_report(2))
        self.assertIsNone(self.s.get_report(1, "C"))

    def test_upsert_again_keeps_primary_and_created(self):
        self.s.upsert_report(1, "A", "1.1", now=10)
        self.s.upsert_report(1, "B", "2.2", now=20)
        self.s.upsert_report(1, "B", "3.3", now=30)
        rep = self.s.get_report(1, "B")
        self.assertEqual((rep["root_ts"], rep["created_epoch"], rep["is_primary"]),
                         ("3.3", 20, False))

    def test_primary_per_incident(self):
        self.s.upsert_report(1, "A", "1.1", now=10)
        self.s.upsert_report(2, "B", "2.2", now=10)
        self.assertEqual(self.s.primary_report(2)["channel"], "B")

    def test_initial_and_updated_state(self):
        self.s.upsert_report(1, "A", "1.1", now=10)
        rep = self.s.get_report(1, "A")
        self.assertEqual((rep["last_update_epoch"], rep["last_count"], rep["last_hosts"],
                          rep["last_severity"]), (10, 0, None, None))
        self.s.set_report_state(1, "A", last_update_epoch=70, last_count=5,
                                last_hosts=2, last_severity="high")
        self.s.set_report_state(1, "A", last_update_epoch=130, last_count=9)
        rep = self.s.get_report(1, "A")
        self.assertEqual((rep["last_update_epoch"], rep["last_count"], rep["last_hosts"],
                          rep["last_severity"]), (130, 9, 2, "high"))

    def test_count_incident_messages(self):
        specs = [("1000.1", CH), ("1010.1", CH), ("1020.1", "C2"), ("1030.1", CH)]
        for ts, ch in specs:
            a = alert(ts, ch)
            self.s.insert_message(a, 1.0)
        with self.s.tx() as db:
            db.execute("UPDATE messages SET incident_id=1")
            db.execute("UPDATE messages SET incident_id=2 WHERE ts='1030.1'")
        self.assertEqual(self.s.count_incident_messages(1, None, 1000, 1025), 3)
        self.assertEqual(self.s.count_incident_messages(1, CH, 1000, 1025), 2)
        self.assertEqual(self.s.count_incident_messages(1, CH, 1005, 1025), 1)
        self.assertEqual(self.s.count_incident_messages(2, None, 0, 9999), 1)


class ProtectionAndCounterTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_default_protection(self):
        p = self.s.get_protection()
        self.assertEqual((p["state"], p["reason"]), ("normal", ""))

    def test_set_protection_tracks_since(self):
        self.s.set_protection("overload", "intake 1200/min", 100)
        self.assertEqual(self.s.get_protection(),
                         {"state": "overload", "since": 100, "reason": "intake 1200/min"})
        self.s.set_protection("overload", "incidents 31", 160)
        p = self.s.get_protection()
        self.assertEqual((p["since"], p["reason"]), (100, "incidents 31"))
        self.s.set_protection("normal", "recovered", 400)
        self.assertEqual(self.s.get_protection()["since"], 400)

    def test_counter_minute_buckets(self):
        self.s.bump_counter("intake", 3, 120.5)
        self.s.bump_counter("intake", 2, 150)
        self.s.bump_counter("intake", 4, 185)
        self.s.bump_counter("other", 9, 130)
        self.assertEqual(self.s.counter_sum("intake", 120, 179), 5)
        self.assertEqual(self.s.counter_sum("intake", 180, 239), 4)
        self.assertEqual(self.s.counter_sum("intake", 0, 1000), 9)
        self.assertEqual(self.s.counter_sum("intake", 300, 400), 0)
        self.assertEqual(self.s.counter_sum("nope", 0, 1000), 0)


class CoverageV3Tests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def _msg(self, ts, ch=CH, **handled):
        self.s.insert_message(alert(ts, ch), 1.0)
        self.s.mark_handled(ch, ts, category="new", incident_id=handled.pop("inc", 1),
                            fingerprint="fp", reply_ts=None, handled_epoch=2000.0,
                            **handled)

    def test_flags_stored_and_counted(self):
        self._msg("1001.0")
        self._msg("1002.0", degraded=True)
        self._msg("1003.0", backfilled=True)
        rows = self.s.read("SELECT ts, degraded, backfilled FROM messages ORDER BY ts")
        self.assertEqual(rows, [("1001.0", 0, 0), ("1002.0", 1, 0), ("1003.0", 0, 1)])
        self.assertEqual(self.s.coverage(CH, 0, 5000)["degraded"], 1)

    def test_published_and_deferred(self):
        self._msg("1001.0", inc=1)
        self._msg("1002.0", inc=2)
        self._msg("1003.0", ch="C2", inc=1)
        sent = self.s.enqueue_reply(incident_id=1, channel=CH, kind="first", priority=1,
                                    due_epoch=1, payload={})
        self.s.complete_outbox(sent, "9.9", 2)
        self.s.enqueue_reply(incident_id=2, channel=CH, kind="first", priority=1,
                             due_epoch=1, payload={})
        cov = self.s.coverage(CH, 0, 5000)
        self.assertEqual((cov["published"], cov["deferred"], cov["handled"]), (1, 1, 2))
        other = self.s.coverage("C2", 0, 5000)
        self.assertEqual((other["published"], other["deferred"]), (0, 0))

    def test_new_keys_on_empty_channel(self):
        cov = self.s.coverage("none", 0, 1)
        self.assertEqual((cov["degraded"], cov["published"], cov["deferred"]), (0, 0, 0))


class MigrationTests(unittest.TestCase):
    def test_old_db_upgrades(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            db = sqlite3.connect(path)
            db.executescript(
                "CREATE TABLE messages (channel TEXT NOT NULL, ts TEXT NOT NULL,"
                " epoch REAL NOT NULL, raw_text TEXT NOT NULL, parse_ok INTEGER NOT NULL,"
                " check_title TEXT NOT NULL, check_code TEXT, task_id TEXT, level INTEGER,"
                " result_message TEXT NOT NULL, extra TEXT NOT NULL, mentions TEXT NOT NULL,"
                " received_epoch REAL NOT NULL, status TEXT NOT NULL DEFAULT 'received',"
                " attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, category TEXT,"
                " incident_id INTEGER, fingerprint TEXT, reply_ts TEXT, handled_epoch REAL,"
                " next_attempt_epoch REAL NOT NULL DEFAULT 0, PRIMARY KEY (channel, ts));"
                "INSERT INTO messages (channel, ts, epoch, raw_text, parse_ok, check_title,"
                " result_message, extra, mentions, received_epoch, status)"
                " VALUES ('C1','1.0',1,'r',1,'T','m','{}','[]',1,'handled');")
            db.close()
            s = Store(path)
            Store(path)
            cov = s.coverage("C1", 0, 10)
            self.assertEqual((cov["handled"], cov["degraded"]), (1, 0))
            self.assertEqual(s.read("SELECT degraded, backfilled FROM messages"), [(0, 0)])
            enqueue(s)
            self.assertEqual(len(s.claim_outbox(1000)), 1)


if __name__ == "__main__":
    unittest.main()


class OutboxAgeTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_critical_first_retried_for_an_hour_reports_full_age(self):
        item = enqueue(self.s, kind="first", priority=0, due_epoch=1000.0, now=1000.0)
        t = 1000.0
        while t < 4600:
            self.s.claim_outbox(t)
            self.s.retry_outbox(item, "Slack 429", t + 30, count_attempt=False)
            t += 30
        stats = self.s.outbox_stats(4600.0)
        self.assertAlmostEqual(stats["oldest_critical_age"], 3600, delta=1)
        self.assertAlmostEqual(stats["oldest_pending_age"], 3600, delta=1)
        self.assertAlmostEqual(stats["oldest_error_age"], 3600, delta=1)

    def test_rows_not_yet_due_count_from_enqueue(self):
        enqueue(self.s, kind="update", due_epoch=900.0, now=100.0)
        stats = self.s.outbox_stats(400.0)
        self.assertEqual(stats["oldest_pending_age"], 300)
        self.assertIsNone(stats["oldest_critical_age"])
        self.assertIsNone(stats["oldest_error_age"])
        self.assertIsNone(stats["first_pending_age"])

    def test_merge_keeps_original_enqueue_time(self):
        enqueue(self.s, dedupe_key="k", due_epoch=500.0, now=100.0)
        enqueue(self.s, dedupe_key="k", due_epoch=500.0, now=300.0)
        self.assertEqual(self.s.outbox_stats(400.0)["oldest_pending_age"], 300)

    def test_newer_sibling_inherits_older_enqueue_time(self):
        a = enqueue(self.s, kind="analysis", dedupe_key="k", due_epoch=100.0, now=100.0)
        self.s.claim_outbox(100)
        enqueue(self.s, kind="analysis", dedupe_key="k", due_epoch=120.0, now=110.0)
        self.s.retry_outbox(a, "boom", 130.0)
        self.assertEqual(self.s.outbox_stats(400.0)["oldest_pending_age"], 300)

    def test_error_and_first_ages(self):
        enqueue(self.s, kind="first", priority=0, due_epoch=100.0, now=100.0)
        enqueue(self.s, kind="first", priority=1, due_epoch=220.0, now=200.0)
        enqueue(self.s, kind="first", priority=1, due_epoch=300.0, now=300.0)
        failing = enqueue(self.s, kind="update", due_epoch=250.0, now=250.0)
        self.s.retry_outbox(failing, "boom", 260.0)
        stats = self.s.outbox_stats(400.0)
        self.assertEqual(stats["first_pending_age"], 200)
        self.assertEqual(stats["oldest_error_age"], 150)
        self.assertEqual(stats["oldest_critical_age"], 300)

    def test_sent_rows_do_not_count(self):
        item = enqueue(self.s, kind="first", priority=0, due_epoch=100.0, now=100.0)
        self.s.complete_outbox(item, "9.9", 101.0)
        stats = self.s.outbox_stats(400.0)
        self.assertIsNone(stats["oldest_pending_age"])
        self.assertIsNone(stats["oldest_critical_age"])


class ReportBackfillAccountingTests(unittest.TestCase):
    def test_last_backfilled_defaults_to_zero_and_is_kept_when_omitted(self):
        s = Store(":memory:")
        s.upsert_report(1, "A", "1.1", now=10)
        self.assertEqual(s.get_report(1, "A")["last_backfilled"], 0)
        s.set_report_state(1, "A", last_update_epoch=20, last_count=5, last_backfilled=3)
        s.set_report_state(1, "A", last_update_epoch=30, last_count=6)
        self.assertEqual(s.get_report(1, "A")["last_backfilled"], 3)
        self.assertEqual(s.primary_report(1)["last_backfilled"], 3)
        self.assertEqual(s.primary_report(1)["channel"], "A")
