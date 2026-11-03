import os
import sqlite3
import tempfile
import time
import unittest
import unittest.mock

from alert_doctor.models import ParsedAlert
from alert_doctor.store import Store

CH = "C1"


def alert(ts="1000.000100", title="T", code="c1", **kw):
    return ParsedAlert(
        channel=CH, ts=ts, raw_text="raw", parse_ok=True, check_title=title,
        check_code=code, task_id="t", level=3, result_message="msg",
        extra=kw.pop("extra", {"a": [1, 2]}), mentions=("U1", "U2"), **kw,
    )


def handle(s, a, category="new", incident_id=None, fp=None, at=2000.0):
    s.mark_handled(a.channel, a.ts, category=category, incident_id=incident_id,
                   fingerprint=fp, reply_ts="9.9", handled_epoch=at)


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_duplicate_insert_returns_false(self):
        self.assertTrue(self.s.insert_message(alert(), 1.0))
        self.assertFalse(self.s.insert_message(alert(), 2.0))

    def test_pending_roundtrip_and_order(self):
        self.s.insert_message(alert(ts="1002.0"), 1.0)
        self.s.insert_message(alert(ts="1001.0"), 1.0)
        got = self.s.pending_messages()
        self.assertEqual([a.ts for a in got], ["1001.0", "1002.0"])
        self.assertEqual(got[0], alert(ts="1001.0"))
        self.assertEqual(len(self.s.pending_messages(limit=1)), 1)

    def test_truncated_survives_the_roundtrip(self):
        self.s.insert_message(alert(truncated=True), 1.0)
        self.assertTrue(self.s.pending_messages()[0].truncated)
        self.assertEqual(self.s.get_message(CH, "1000.000100"), alert(truncated=True))

    def test_get_message(self):
        self.s.insert_message(alert(), 1.0)
        self.assertEqual(self.s.get_message(CH, "1000.000100"), alert())
        self.assertIsNone(self.s.get_message(CH, "1.0"))

    def test_slack_text_length_is_stored(self):
        self.s.insert_message(alert(), 1.0, bot_id="B1", text_len=4000)
        self.assertEqual(self.s.bot_message_before(CH, "B1", "2000.0")["text_len"], 4000)

    def test_text_length_falls_back_to_the_stored_text(self):
        self.s.insert_message(alert(), 1.0, bot_id="B1")
        self.assertEqual(self.s.bot_message_before(CH, "B1", "2000.0")["text_len"], len("raw"))

    def test_handled_leaves_pending(self):
        a = alert()
        self.s.insert_message(a, 1.0)
        handle(self.s, a)
        self.assertEqual(self.s.pending_messages(), [])

    def test_five_failures_mark_failed(self):
        a = alert()
        self.s.insert_message(a, 1.0)
        for _ in range(4):
            self.s.message_attempt_failed(CH, a.ts, "boom", now=0)
        self.assertEqual(len(self.s.pending_messages(now=1e9)), 1)
        self.s.message_attempt_failed(CH, a.ts, "boom", now=0)
        self.assertEqual(self.s.pending_messages(now=1e9), [])
        cov = self.s.coverage(CH, 0, 5000)
        self.assertEqual((cov["failed"], cov["pending"], cov["handled"]), (1, 0, 0))
        self.assertEqual(cov["unhandled"], [(a.ts, "T")])

    def test_coverage_counts(self):
        a, b, c = alert(ts="1001.0"), alert(ts="1002.0", title="B"), alert(ts="1003.0")
        for x in (a, b, c):
            self.s.insert_message(x, 1.0)
        handle(self.s, a, category="noise")
        handle(self.s, c, category="noise")
        cov = self.s.coverage(CH, 1000, 1002.5)
        self.assertEqual(cov["total"], 2)
        self.assertEqual(cov["handled"], 1)
        self.assertEqual(cov["pending"], 1)
        self.assertEqual(cov["unhandled"], [("1002.0", "B")])
        self.assertEqual(cov["by_category"], {"noise": 1})
        self.assertEqual(self.s.coverage("other", 0, 9999)["total"], 0)

    def test_mark_handled_flags_default_false(self):
        a = alert()
        self.s.insert_message(a, 1.0)
        handle(self.s, a)
        self.assertEqual(
            self.s.read("SELECT degraded, backfilled FROM messages"), [(0, 0)])
        cov = self.s.coverage(CH, 0, 5000)
        self.assertEqual((cov["degraded"], cov["published"], cov["deferred"]), (0, 0, 0))

    def test_count_messages(self):
        for i, ts in enumerate(["1001.0", "1002.0", "1003.0"]):
            a = alert(ts=ts)
            self.s.insert_message(a, 1.0)
            handle(self.s, a, fp="fp")
        other = alert(ts="1002.5")
        self.s.insert_message(other, 1.0)
        handle(self.s, other, fp="zz")
        self.assertEqual(self.s.count_messages("fp", 1001.5, 1003.5), 2)


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def make(self, ts="1000.0", fp="fp"):
        return self.s.create_incident(alert(ts=ts), fp, "g")

    def test_create_and_get(self):
        inc = self.make()
        self.assertEqual((inc.count, inc.analysis_state, inc.anchor_ts), (1, "none", "1000.0"))
        self.assertEqual(inc.first_epoch, 1000.0)
        self.assertEqual(self.s.get_incident(inc.id), inc)
        self.assertIsNone(self.s.get_incident(999))

    def test_open_incident_window(self):
        inc = self.make()
        self.assertEqual(self.s.open_incident("fp", 1000 + 3600, 60).id, inc.id)
        self.assertIsNone(self.s.open_incident("fp", 1000 + 3601, 60))
        self.assertIsNone(self.s.open_incident("nope", 1000, 60))

    def test_attach(self):
        inc = self.make()
        got = self.s.attach(inc.id, alert(ts="1500.0"))
        self.assertEqual((got.count, got.last_epoch, got.first_epoch), (2, 1500.0, 1000.0))
        self.assertEqual(self.s.open_incident("fp", 1500 + 3600, 60).id, inc.id)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        self.inc = self.s.create_incident(alert(), "fp", "g")

    def pend(self):
        self.s.request_analysis(self.inc.id)

    def state(self):
        return self.s.get_incident(self.inc.id).analysis_state

    def test_defer_returns_to_queue_without_spending_attempt(self):
        self.pend()
        self.s.claim_incident("w1", 100)
        self.s.defer_analysis(self.inc.id)
        got = self.s.get_incident(self.inc.id)
        self.assertEqual((got.analysis_state, got.attempts), ("pending", 0))
        self.assertIsNotNone(self.s.claim_incident("w2", 101))

    def test_earliest_message_epoch(self):
        self.assertIsNone(Store(":memory:").earliest_message_epoch())
        self.s.insert_message(alert(ts="2000.0"), 0)
        self.s.insert_message(alert(ts="1500.0"), 0)
        self.assertEqual(self.s.earliest_message_epoch(), 1500.0)

    def test_claim_requires_pending(self):
        self.assertIsNone(self.s.claim_incident("w", 0))

    def test_claim_mutual_exclusion(self):
        self.pend()
        got = self.s.claim_incident("w1", 100)
        self.assertEqual((got.id, got.analysis_state, got.attempts), (self.inc.id, "leased", 1))
        self.assertIsNone(self.s.claim_incident("w2", 101))

    def test_lease_expiry_reclaim(self):
        self.pend()
        self.s.claim_incident("w1", 100, lease_seconds=60)
        self.assertIsNone(self.s.claim_incident("w2", 159))
        got = self.s.claim_incident("w2", 160, lease_seconds=60)
        self.assertEqual((got.id, got.attempts), (self.inc.id, 2))

    def test_attempts_cap(self):
        self.pend()
        for i in range(3):
            self.assertIsNotNone(self.s.claim_incident("w", i * 100, lease_seconds=10))
        self.assertIsNone(self.s.claim_incident("w", 1000, lease_seconds=10))
        self.assertEqual(self.state(), "failed")

    def test_fail_returns_to_pending_then_failed(self):
        self.pend()
        self.s.claim_incident("w", 0)
        self.s.fail_analysis(self.inc.id, "e")
        self.assertEqual(self.state(), "pending")
        self.s.claim_incident("w", 1)
        self.s.claim_incident("w", 2)
        self.s.fail_analysis(self.inc.id, "e")
        self.assertEqual(self.state(), "pending")
        self.s.claim_incident("w", 3)
        self.s.fail_analysis(self.inc.id, "e")
        self.assertEqual(self.state(), "failed")

    def test_complete_and_reopen(self):
        self.pend()
        self.s.claim_incident("w", 0)
        self.s.complete_analysis(self.inc.id, {"k": "v"}, "sonnet", 50.0)
        got = self.s.get_incident(self.inc.id)
        self.assertEqual((got.analysis_state, got.verdict), ("done", {"k": "v"}))
        self.assertIsNone(self.s.claim_incident("w", 60))
        self.pend()
        self.assertEqual(self.state(), "pending")
        self.assertEqual(self.s.claim_incident("w", 70).attempts, 1)

    def test_request_leaves_leased_alone(self):
        self.pend()
        self.s.claim_incident("w", 0)
        self.pend()
        self.assertEqual(self.state(), "leased")

    def test_recent_verdict_window(self):
        self.pend()
        self.s.claim_incident("w", 0)
        self.s.complete_analysis(self.inc.id, {"k": 1}, "opus", 1000.0)
        self.assertEqual(self.s.recent_verdict("fp", 1000 + 86400), ({"k": 1}, "opus", 1000.0))
        self.assertIsNone(self.s.recent_verdict("fp", 1000 + 86401))
        self.assertEqual(self.s.recent_verdict("fp", 1100, within_seconds=200)[1], "opus")
        self.assertIsNone(self.s.recent_verdict("other", 1100))

    def test_stale_pending(self):
        self.pend()
        self.assertEqual([i.id for i in self.s.stale_pending_analysis(time.time() + 10)], [self.inc.id])
        self.assertEqual(self.s.stale_pending_analysis(time.time() - 100), [])


class MiscTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_llm_calls(self):
        self.s.record_llm_call("sonnet", 100)
        self.s.record_llm_call("sonnet", 200)
        self.s.record_llm_call("opus", 150)
        self.assertEqual(self.s.llm_calls_on("sonnet", 100, 200), 1)
        self.assertEqual(self.s.llm_calls_on("sonnet", 100, 201), 2)
        self.assertEqual(self.s.llm_calls_on("opus", 0, 1000), 1)

    def test_beat(self):
        self.assertIsNone(self.s.last_beat("collector"))
        self.s.beat("collector", 5.0)
        self.s.beat("collector", 9.0)
        self.assertEqual(self.s.last_beat("collector"), 9.0)

    def test_cursor_never_goes_back(self):
        self.assertIsNone(self.s.get_cursor(CH))
        self.s.set_cursor(CH, "100.5")
        self.s.set_cursor(CH, "99.0")
        self.assertEqual(self.s.get_cursor(CH), "100.5")
        self.s.set_cursor(CH, "100.6")
        self.assertEqual(self.s.get_cursor(CH), "100.6")

    def test_evidence(self):
        inc = self.s.create_incident(alert(), "fp", "g")
        self.assertIsNone(self.s.load_evidence(inc.id))
        self.s.save_evidence(inc.id, {"total": 3})
        self.s.save_evidence(inc.id, {"total": 4})
        self.assertEqual(self.s.load_evidence(inc.id), {"total": 4})


class TwoProcessTests(unittest.TestCase):
    def test_second_connection_sees_writes_and_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            a, b = Store(path), Store(path)
            inc = a.create_incident(alert(), "fp", "g")
            a.request_analysis(inc.id)
            self.assertIsNotNone(b.claim_incident("b", 0))
            self.assertIsNone(a.claim_incident("a", 1))
            self.assertEqual(
                a._db.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")


class FirstMessageTests(unittest.TestCase):
    def test_returns_anchor_message_or_none(self):
        s = Store(":memory:")
        a = alert()
        s.insert_message(a, 1.0)
        inc = s.create_incident(a, "fp", "g")
        s.insert_message(alert(ts="1001.0"), 1.0)
        self.assertEqual(s.first_message(inc.id), a)
        self.assertIsNone(s.first_message(999))


if __name__ == "__main__":
    unittest.main()


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        self.a = alert()
        self.s.insert_message(self.a, 1.0)

    def test_exponential_backoff_capped(self):
        delays = []
        for _ in range(4):
            self.s.message_attempt_failed(CH, self.a.ts, "e", 99, now=0)
            row = self.s.read("SELECT next_attempt_epoch FROM messages")
            delays.append(row[0][0])
        self.assertEqual(delays, [30, 60, 120, 240])
        for _ in range(10):
            self.s.message_attempt_failed(CH, self.a.ts, "e", 99, now=0)
        self.assertEqual(self.s.read("SELECT next_attempt_epoch FROM messages")[0][0], 1800)

    def test_retry_later_keeps_attempts(self):
        self.s.message_retry_later(CH, self.a.ts, "net", retry_in=30, now=100)
        self.assertEqual(self.s.pending_messages(now=129), [])
        self.assertEqual(len(self.s.pending_messages(now=130)), 1)
        self.assertEqual(self.s.read("SELECT attempts FROM messages")[0][0], 0)

    def test_revive_failed_only_recent(self):
        old = alert(ts="10.0")
        self.s.insert_message(old, 1.0)
        self.s._db.execute("UPDATE messages SET status='failed'")
        self.assertEqual(self.s.revive_failed(1000.0 + 86400, max_age=86400), 1)
        self.assertEqual([m.ts for m in self.s.pending_messages(now=1e9)], [self.a.ts])
        self.s.message_attempt_failed(CH, self.a.ts, "again", now=0)
        self.assertEqual(self.s.read("SELECT status FROM messages WHERE ts=?", (self.a.ts,))[0][0], "failed")

    def test_migrates_old_schema(self):
        import os, sqlite3, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "o.db")
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE messages (channel TEXT NOT NULL, ts TEXT NOT NULL,"
                       " epoch REAL NOT NULL, raw_text TEXT NOT NULL, parse_ok INTEGER NOT NULL,"
                       " check_title TEXT NOT NULL, check_code TEXT, task_id TEXT, level INTEGER,"
                       " result_message TEXT NOT NULL, extra TEXT NOT NULL, mentions TEXT NOT NULL,"
                       " received_epoch REAL NOT NULL, status TEXT NOT NULL DEFAULT 'received',"
                       " attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, category TEXT,"
                       " incident_id INTEGER, fingerprint TEXT, reply_ts TEXT, handled_epoch REAL,"
                       " PRIMARY KEY (channel, ts))")
            db.commit()
            db.close()
            self.assertEqual(Store(path).pending_messages(), [])


class AttachIdempotentTests(unittest.TestCase):
    def test_second_attach_of_same_message_not_counted(self):
        s = Store(":memory:")
        inc = s.create_incident(alert(), "fp", "g")
        b = alert(ts="1500.0")
        s.insert_message(b, 1.0)
        s.attach(inc.id, b)
        self.assertEqual(s.attach(inc.id, b).count, 2)
        self.assertEqual(s.message_incident(CH, b.ts), inc.id)


class RequestAnalysisIntervalTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        self.inc = self.s.create_incident(alert(), "fp", "g")
        self.s.request_analysis(self.inc.id)
        self.s.claim_incident("w", 100)
        self.s.complete_analysis(self.inc.id, {"x": 1}, "m", 1000)

    def state(self):
        return self.s.get_incident(self.inc.id).analysis_state

    def test_recent_done_not_reopened(self):
        self.s.request_analysis(self.inc.id, min_interval=3600, now=2000)
        self.assertEqual(self.state(), "done")

    def test_old_done_reopened(self):
        self.s.request_analysis(self.inc.id, min_interval=3600, now=1000 + 3600)
        self.assertEqual(self.state(), "pending")

    def test_incidents_in_states(self):
        self.assertEqual([i.id for i in self.s.incidents_in_states(("done",))], [self.inc.id])
        self.assertEqual(self.s.incidents_in_states(("failed", "leased")), [])


class V2StoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_tx_and_read_are_public_and_commit(self):
        with self.s.tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS mine (x INTEGER)")
            db.execute("INSERT INTO mine VALUES (7)")
        self.assertEqual(self.s.read("SELECT x FROM mine WHERE x=?", (7,)), [(7,)])

    def test_tx_rolls_back_on_error(self):
        with self.assertRaises(RuntimeError):
            with self.s.tx() as db:
                db.execute("INSERT INTO cursors (channel, ts) VALUES ('Cx', '1.0')")
                raise RuntimeError("x")
        self.assertIsNone(self.s.get_cursor("Cx"))

    def test_source_system_roundtrip(self):
        inc = self.s.create_incident(alert(), "fp", "g", source_system="pxy")
        self.assertEqual(inc.source_system, "pxy")
        self.assertEqual(self.s.get_incident(inc.id).source_system, "pxy")
        self.assertEqual(self.s.create_incident(alert(ts="2000.0"), "fp2", "g").source_system, "")

    def test_migrates_old_db_without_source_system(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " fingerprint TEXT NOT NULL, group_fp TEXT NOT NULL, check_code TEXT,"
                " check_title TEXT NOT NULL, channel TEXT NOT NULL, anchor_ts TEXT NOT NULL,"
                " first_epoch REAL NOT NULL, last_epoch REAL NOT NULL, count INTEGER NOT NULL,"
                " analysis_state TEXT NOT NULL DEFAULT 'none', verdict TEXT, model TEXT,"
                " completed_epoch REAL, attempts INTEGER NOT NULL DEFAULT 0, lease_owner TEXT,"
                " lease_expires REAL, requested_epoch REAL, last_error TEXT)")
            db.execute("INSERT INTO incidents (fingerprint, group_fp, check_title, channel,"
                       " anchor_ts, first_epoch, last_epoch, count) VALUES ('f','g','T','C1','1.0',1,1,1)")
            db.commit()
            db.close()
            s = Store(path)
            self.assertEqual(s.get_incident(1).source_system, "")
            s2 = Store(path)
            self.assertEqual(s2.create_incident(alert(), "f2", "g", source_system="x").source_system, "x")

    def _msg(self, ts, task_id, channel=CH):
        a = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True, check_title="T",
                        check_code="c1", task_id=task_id, result_message="m")
        self.s.insert_message(a, 1.0)
        return a

    def test_incident_for_task(self):
        a = self._msg("1000.0", "tk")
        inc = self.s.create_incident(a, "fp", "g")
        self.assertEqual(self.s.incident_for_task("tk", 500.0).id, inc.id)
        self.assertIsNone(self.s.incident_for_task("tk", 1500.0))
        self.assertIsNone(self.s.incident_for_task("other", 0))

    def test_incident_for_task_ignores_unbound_messages(self):
        self._msg("1000.0", "tk")
        self.assertIsNone(self.s.incident_for_task("tk", 0))

    def test_reply_index_roundtrip(self):
        self.assertIsNone(self.s.lookup_reply("C1", "9.1"))
        self.s.index_reply("C1", "9.1", "1000.0", 3, "triage")
        self.assertEqual(self.s.lookup_reply("C1", "9.1"), ("1000.0", 3, "triage"))
        self.assertIsNone(self.s.lookup_reply("C2", "9.1"))
        self.s.index_reply("C1", "9.1", "1000.0", 3, "analysis")
        self.assertEqual(self.s.lookup_reply("C1", "9.1")[2], "analysis")

    def test_coverage_all_groups_by_channel(self):
        for ch, ts in (("C1", "1000.0"), ("C1", "1001.0"), ("C2", "1002.0")):
            handle(self.s, self._msg(ts, None, channel=ch))
        self._msg("1003.0", None, channel="C2")
        got = self.s.coverage_all(0, 5000)
        self.assertEqual(set(got), {"C1", "C2"})
        self.assertEqual((got["C1"]["total"], got["C1"]["handled"]), (2, 2))
        self.assertEqual((got["C2"]["total"], got["C2"]["pending"]), (2, 1))
        self.assertEqual(got["C1"], self.s.coverage("C1", 0, 5000))

    def test_reactions_inbox(self):
        self.assertTrue(self.s.add_reaction_inbox("C1", "1000.0", "U1", "x", 5.0))
        self.assertFalse(self.s.add_reaction_inbox("C1", "1000.0", "U1", "x", 5.0))
        self.assertEqual(self.s.read("SELECT channel, ts, user, name, epoch FROM reactions_inbox"),
                         [("C1", "1000.0", "U1", "x", 5.0)])


class ReviewFixStoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        self.inc = self.s.create_incident(alert(), "fp", "g")
        self.s.request_analysis(self.inc.id)
        self.s.claim_incident("w", 100)

    def flags(self):
        return self.s.read(
            "SELECT verdict_reused, fresh_requested FROM incidents WHERE id=?", (self.inc.id,))[0]

    def test_reused_verdict_is_not_reused_again(self):
        self.s.complete_analysis(self.inc.id, {"x": 1}, "m", 1000, reused=True)
        self.assertIsNone(self.s.recent_verdict(self.inc.fingerprint, 1001))

    def test_complete_analysis_records_reuse(self):
        self.s.complete_analysis(self.inc.id, {"x": 1}, "m", 1000, reused=True)
        self.assertEqual(self.flags(), (1, 0))
        self.s.request_analysis(self.inc.id, now=5000)
        self.s.claim_incident("w", 5000)
        self.s.complete_analysis(self.inc.id, {"x": 2}, "m", 5000)
        self.assertEqual(self.flags(), (0, 0))

    def test_fresh_request_bypasses_min_interval_and_is_cleared_on_completion(self):
        self.s.complete_analysis(self.inc.id, {"x": 1}, "m", 1000)
        self.s.request_analysis(self.inc.id, min_interval=3600, now=1001)
        self.assertEqual(self.s.get_incident(self.inc.id).analysis_state, "done")
        self.s.request_analysis(self.inc.id, min_interval=3600, now=1002, fresh=True)
        inc = self.s.get_incident(self.inc.id)
        self.assertEqual((inc.analysis_state, inc.fresh_requested), ("pending", True))
        claimed = self.s.claim_incident("w", 1003)
        self.assertTrue(claimed.fresh_requested)
        self.s.complete_analysis(self.inc.id, {"x": 2}, "m", 1004)
        self.assertFalse(self.s.get_incident(self.inc.id).fresh_requested)
        self.assertEqual(self.flags(), (0, 0))

    def test_fresh_request_marks_already_pending_incident(self):
        other = self.s.create_incident(alert(ts="2000.0"), "fp2", "g")
        self.s.request_analysis(other.id)
        self.s.request_analysis(other.id, fresh=True)
        self.assertTrue(self.s.get_incident(other.id).fresh_requested)

    def test_non_fresh_request_does_not_set_flag(self):
        self.s.complete_analysis(self.inc.id, {"x": 1}, "m", 1000)
        self.s.request_analysis(self.inc.id, now=1001)
        self.assertFalse(self.s.get_incident(self.inc.id).fresh_requested)

    def test_migration_tolerates_column_added_concurrently(self):
        from alert_doctor import store as store_mod
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "race.db")
            Store(path)
            real = store_mod._column_names

            def stale_view(db, table):
                # The column already exists, as if a peer process added it after our check.
                names = real(db, table)
                return names - {"verdict_reused"} if table == "incidents" else names

            with unittest.mock.patch.object(store_mod, "_column_names", stale_view):
                s = Store(path)
            inc = s.create_incident(alert(), "f", "g")
            s.complete_analysis(inc.id, {}, "m", 1.0, reused=True)
            self.assertEqual(s.read("SELECT verdict_reused FROM incidents")[0][0], 1)

    def test_migrates_old_db_gaining_flag_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            Store(path)
            db = sqlite3.connect(path)
            db.execute("ALTER TABLE incidents DROP COLUMN verdict_reused")
            db.execute("ALTER TABLE incidents DROP COLUMN fresh_requested")
            db.commit()
            db.close()
            s = Store(path)
            inc = s.create_incident(alert(), "f", "g")
            self.assertFalse(s.get_incident(inc.id).fresh_requested)


def task_alert(ts, pk, code="c1", level=3, channel=CH):
    return ParsedAlert(
        channel=channel, ts=ts, raw_text="raw", parse_ok=True, check_title="T",
        check_code=code, task_id="t", level=level, result_message="msg",
        extra={"vkwargs": {"crontab_task_pk": pk}}, mentions=())


class V3ReviewStoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def task_pks(self):
        return [r[0] for r in self.s.read("SELECT task_pk FROM messages ORDER BY ts")]

    def test_insert_message_extracts_task_pk(self):
        for i, pk in enumerate((42, "17", "x1", True, None)):
            self.s.insert_message(task_alert(f"100{i}.0", pk), 1.0)
        self.s.insert_message(alert(ts="1009.0"), 1.0)
        self.s.insert_message(alert(ts="1010.0", extra={"vkwargs": "oops"}), 1.0)
        self.assertEqual(self.task_pks(), [42, 17, None, None, None, None, None])

    def test_indexes(self):
        def columns(table):
            found = set()
            for index in self.s.read(f"PRAGMA index_list({table})"):
                found.add(tuple(r[2] for r in self.s.read(f"PRAGMA index_info({index[1]})")))
            return found
        for cols in (("epoch",), ("received_epoch",), ("task_id",)):
            self.assertIn(cols, columns("messages"))
        self.assertIn(("incident_id", "channel", "kind", "status"), columns("outbox"))

    def test_migration_fills_task_pk_and_enqueued_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            s = Store(path)
            s.insert_message(task_alert("1000.0", 42), 1.0)
            s.insert_message(task_alert("1001.0", "7"), 1.0)
            s.insert_message(alert(ts="1002.0"), 1.0)
            s.enqueue_reply(incident_id=1, channel=CH, kind="first", priority=0,
                            due_epoch=500.0, payload={}, now=400.0)
            db = sqlite3.connect(path)
            for index in ("messages_task_pk",):
                db.execute(f"DROP INDEX IF EXISTS {index}")
            db.execute("ALTER TABLE messages DROP COLUMN task_pk")
            db.execute("ALTER TABLE outbox DROP COLUMN enqueued_epoch")
            db.commit()
            db.close()
            s = Store(path)
            self.assertEqual(s.read("SELECT task_pk FROM messages ORDER BY ts"),
                             [(42,), (7,), (None,)])
            self.assertEqual(s.read("SELECT enqueued_epoch FROM outbox"), [(500.0,)])

    def test_count_received_excludes_backfill_by_lag(self):
        for ts, received in (("1000.0", 1010.0), ("1001.0", 1122.0), ("1050.0", 1100.0),
                             ("900.0", 1050.0), ("1200.0", 1200.0)):
            self.s.insert_message(alert(ts=ts), received)
        self.assertEqual(self.s.count_received(1000, 1200), 2)
        self.assertEqual(self.s.count_received(1000, 1201), 3)
        self.assertEqual(self.s.count_received(1101, 1200), 0)

    def test_open_incident_for_task(self):
        first = task_alert("1000.0", 42)
        self.s.insert_message(first, 1.0)
        inc = self.s.create_incident(first, "fp", "g")
        other = task_alert("1001.0", 42, code="other")
        self.s.insert_message(other, 1.0)
        self.s.create_incident(other, "fp2", "g")
        self.s.insert_message(task_alert("1002.0", 43), 1.0)
        later = task_alert("1300.0", 42)
        self.s.insert_message(later, 1.0)
        self.s.attach(inc.id, later)
        self.assertEqual(self.s.open_incident_for_task(42, "c1", 3, 1300 + 600, 10).id, inc.id)
        self.assertIsNone(self.s.open_incident_for_task(42, "c1", 3, 1300 + 601, 10))
        self.assertIsNone(self.s.open_incident_for_task(42, "c1", 4, 1300, 10))
        self.assertIsNone(self.s.open_incident_for_task(43, "c1", 3, 1300, 10))
        self.assertNotEqual(self.s.open_incident_for_task(42, "other", 3, 1300, 10).id, inc.id)

    def test_open_incident_for_task_matches_null_code_and_level(self):
        a = task_alert("1000.0", 5, code=None, level=None)
        self.s.insert_message(a, 1.0)
        inc = self.s.create_incident(a, "fp", "g")
        self.assertEqual(self.s.open_incident_for_task(5, None, None, 1000, 10).id, inc.id)

    def make(self, ts):
        return self.s.create_incident(alert(ts=ts), f"fp{ts}", "g").id

    def test_claim_orders_by_priority_then_id(self):
        low, high, mid = self.make("1.0"), self.make("2.0"), self.make("3.0")
        self.s.request_analysis(low, now=10, priority=3)
        self.s.request_analysis(high, now=10, priority=0)
        self.s.request_analysis(mid, now=10)
        order = [self.s.claim_incident("w", 100).id for _ in range(3)]
        self.assertEqual(order, [high, mid, low])

    def test_rerequest_while_pending_keeps_most_urgent_priority(self):
        a, b = self.make("1.0"), self.make("2.0")
        self.s.request_analysis(a, now=10, priority=3)
        self.s.request_analysis(b, now=10, priority=2)
        self.s.request_analysis(a, now=11, priority=1)
        self.s.request_analysis(a, now=12, priority=4)
        self.assertEqual(self.s.claim_incident("w", 100).id, a)

    def test_defer_with_not_before_hides_until_then(self):
        a, b = self.make("1.0"), self.make("2.0")
        self.s.request_analysis(a, now=10, priority=0)
        self.s.request_analysis(b, now=10, priority=2)
        self.assertEqual(self.s.claim_incident("w", 100).id, a)
        self.s.defer_analysis(a, not_before=200)
        self.assertEqual(self.s.claim_incident("w", 150).id, b)
        self.assertIsNone(self.s.claim_incident("w", 199))
        got = self.s.claim_incident("w", 200)
        self.assertEqual((got.id, got.attempts), (a, 1))

    def test_defer_without_not_before_is_claimable_at_once(self):
        a = self.make("1.0")
        self.s.request_analysis(a, now=10)
        self.s.claim_incident("w", 100)
        self.s.defer_analysis(a)
        self.assertEqual(self.s.claim_incident("w", 100).id, a)

    def test_reopening_clears_not_before(self):
        a = self.make("1.0")
        self.s.request_analysis(a, now=10)
        self.s.claim_incident("w", 100)
        self.s.defer_analysis(a, not_before=10_000)
        self.s.claim_incident("w", 10_000)
        self.s.complete_analysis(a, {}, "m", 10_001)
        self.s.request_analysis(a, now=10_002, fresh=True)
        self.assertEqual(self.s.claim_incident("w", 10_002).id, a)

    def bind(self, ts, inc, channel=CH):
        a = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True, check_title="T",
                        check_code="c1")
        self.s.insert_message(a, 1.0)
        with self.s.tx() as db:
            db.execute("UPDATE messages SET incident_id=? WHERE channel=? AND ts=?",
                       (inc, channel, ts))

    def test_incidents_needing_catchup(self):
        for ts in ("1000.0", "1100.0"):
            self.bind(ts, 1)
        self.bind("1050.0", 1, channel="C2")
        self.bind("500.0", 2)
        self.bind("600.0", 2)
        self.bind("1200.0", 3)
        self.s.upsert_report(1, CH, "1000.0", now=1)
        self.s.set_report_state(1, CH, last_update_epoch=1, last_count=1)
        self.s.upsert_report(1, "C2", "1050.0", now=1)
        self.s.set_report_state(1, "C2", last_update_epoch=1, last_count=1)
        self.s.upsert_report(2, CH, "500.0", now=1)
        self.s.set_report_state(2, CH, last_update_epoch=1, last_count=1)
        self.s.upsert_report(3, CH, "1200.0", now=1)
        self.s.set_report_state(3, CH, last_update_epoch=1, last_count=1)
        self.assertEqual(self.s.incidents_needing_catchup(900), [(1, CH)])
        self.assertEqual(sorted(self.s.incidents_needing_catchup(0)), [(1, CH), (2, CH)])

    def test_busiest_channel(self):
        self.assertIsNone(self.s.busiest_channel(0))
        self.bind("1000.0", 1, channel="C2")
        self.bind("1001.0", 1, channel="C2")
        self.bind("1002.0", 1, channel="C3")
        for ts in ("100.0", "101.0", "102.0"):
            self.bind(ts, 1, channel="C4")
        self.assertEqual(self.s.busiest_channel(900), "C2")
        self.assertEqual(self.s.busiest_channel(0), "C4")
        self.assertIsNone(self.s.busiest_channel(2000))
