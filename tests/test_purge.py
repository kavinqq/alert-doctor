import dataclasses
import json
import unittest

from alert_doctor import purge
from alert_doctor.budget import Budgets
from alert_doctor.config import ChannelSpec, Config
from alert_doctor.models import CheckSpec, ParsedAlert
from alert_doctor.purge import PURGE_BATCH, Purger, blocked_thread, is_green
from alert_doctor.slack_io import SlackError, SlackRateLimited
from alert_doctor.store import Store

NOW = 1_760_000_000.0
GREEN = {"severity": "low", "action": "observe", "needs_human": False, "cause": "暫時性逾時"}


class FakeSlack:
    def __init__(self):
        self.deletes = []
        self.errors = {}
        self.on_delete = None

    def delete_message(self, token, channel, ts):
        if self.on_delete:
            self.on_delete(ts)
        error = self.errors.pop(ts, None)
        if error is not None:
            raise error
        self.deletes.append((token, channel, ts))


def ts_at(offset):
    return f"{NOW + offset:.0f}.000001"


class Base(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(workspace_url="https://w.slack.com",
                          channels=(ChannelSpec("C1", "alerts-a", ("sys",)),
                                    ChannelSpec("C2", "alerts-b", ("sys",))))
        self.store = Store(":memory:")
        self.slack = FakeSlack()
        self.budgets = Budgets(self.cfg)
        self.checks = {}
        self.purger = self.make_purger()
        self.iid = None

    def make_purger(self, source="xoxb-source"):
        return Purger(self.cfg, self.store, self.slack, "xoxb-ours", source, self.budgets,
                      self.checks, clock=lambda: NOW)

    def message(self, ts, channel="C1", category="new", fragment_of=None):
        alert = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True,
                            check_title="[L3] 訂單檢查", check_code="ORS1")
        self.store.insert_message(alert, NOW)
        if fragment_of is not None:
            self.store.mark_fragment(channel, ts, fragment_of, NOW)
            return
        if self.iid is None:
            self.iid = self.store.create_incident(alert, "fp", "g").id
        else:
            self.store.attach(self.iid, alert)
        self.store.mark_handled(channel, ts, category=category, incident_id=self.iid,
                                fingerprint="fp", reply_ts=None, handled_epoch=NOW)

    def reply(self, channel, root_ts, reply_ts, kind="first", indexed=True):
        item = self.store.enqueue_reply(
            incident_id=self.iid, channel=channel, kind=kind, priority=1, due_epoch=NOW,
            thread_ts=root_ts, payload={}, dedupe_key=f"{kind}:{self.iid}:{channel}", now=NOW)
        self.store.complete_outbox(item, reply_ts, NOW)
        if indexed:
            self.store.index_reply(channel, reply_ts, root_ts, self.iid, "triage")
        if kind == "first":
            self.store.upsert_report(self.iid, channel, root_ts, now=NOW)

    def green(self, channels=("C1",), verdict=GREEN, at=NOW):
        return self.store.complete_analysis_with_purge(
            self.iid, verdict, "m", at, channels=list(channels), analysis_text="🔍 分析全文")

    def state(self, pid):
        return self.store.purge_rows("id=?", (pid,))[0]["state"]

    def run_rounds(self, n=10):
        for _ in range(n):
            self.purger.step(NOW)


class IsGreenTest(Base):
    def setUp(self):
        super().setUp()
        self.message(ts_at(1))

    def test_green_needs_low_observe_no_human(self):
        self.assertTrue(is_green(self.store, self.iid, GREEN, never_silence=False))
        for change in ({"severity": "medium"}, {"action": "investigate"}, {"needs_human": True}):
            self.assertFalse(is_green(self.store, self.iid, {**GREEN, **change},
                                      never_silence=False), change)

    def test_protected_category_blocks(self):
        self.message(ts_at(2), category="accumulated")
        self.assertFalse(is_green(self.store, self.iid, GREEN, never_silence=False))

    def test_never_silence_blocks(self):
        self.assertFalse(is_green(self.store, self.iid, GREEN, never_silence=True))


class PurgerTest(Base):
    def test_deletes_alerts_then_replies(self):
        self.message(ts_at(1))
        self.message(ts_at(2), category="duplicate")
        self.reply("C1", ts_at(1), ts_at(3))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2), ts_at(3)])
        self.assertEqual(self.state(pid), "done")
        self.assertIsNone(self.store.get_report(self.iid, "C1"))
        self.assertEqual(self.store.purge_rows("id=?", (pid,))[0]["old_root"], ts_at(1))
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='first'"),
                         [("purged",)])

    def test_alert_uses_source_token_reply_uses_bot_token(self):
        self.message(ts_at(1))
        self.reply("C1", ts_at(1), ts_at(3))
        self.green()
        self.purger.step(NOW)
        self.assertEqual([(d[0], d[2]) for d in self.slack.deletes],
                         [("xoxb-source", ts_at(1)), ("xoxb-ours", ts_at(3))])

    def test_void_when_reanalysed(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.store.request_analysis(self.iid, fresh=True, now=NOW + 5)
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")
        self.assertEqual(self.slack.deletes, [])

    def test_void_when_protected_arrives_after_generation(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.message(ts_at(9), category="spike")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")
        self.assertEqual(self.slack.deletes, [])

    def test_analysis_committed_between_check_and_hide_is_kept(self):
        self.message(ts_at(1))
        self.reply("C1", ts_at(1), ts_at(3))
        (pid,) = self.green()
        collect = self.purger._collect

        def analyzer_commits_meanwhile(purge_row):
            roots = collect(purge_row)
            self.store.complete_analysis(self.iid, {**GREEN, "severity": "high"}, "m", NOW + 9)
            self.store.enqueue_reply(incident_id=self.iid, channel="C1", kind="analysis",
                                     priority=1, due_epoch=NOW, thread_ts=ts_at(1),
                                     payload={"text": "紅燈"}, dedupe_key="analysis:new", now=NOW)
            return roots

        self.purger._collect = analyzer_commits_meanwhile
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")
        self.assertEqual(self.slack.deletes, [])
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='analysis'"),
                         [("pending",)])
        self.assertIsNotNone(self.store.get_report(self.iid, "C1"))

    def test_inbox_pending_skips_round(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "done")
        self.message(ts_at(2), category="duplicate")
        self.purger.join(self.store.get_incident(self.iid), "C1", ts_at(2),
                         category="duplicate", needs_analysis=False, now=NOW)
        self.store.add_reaction_inbox("C1", ts_at(2), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(len(self.slack.deletes), 1)
        self.assertEqual(self.state(pid), "pending")

    def test_inbox_written_mid_batch_stops(self):
        for i in range(1, 4):
            self.message(ts_at(i))
        self.green()
        self.slack.on_delete = lambda ts: self.store.add_reaction_inbox("C1", ts_at(3), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(len(self.slack.deletes), 1)

    def test_reply_from_purged_outbox_without_index(self):
        self.message(ts_at(1))
        self.reply("C1", ts_at(1), ts_at(3), indexed=False)
        self.green()
        self.run_rounds(2)
        self.assertIn(ts_at(3), [d[2] for d in self.slack.deletes])

    def test_fragments_are_targets(self):
        self.message(ts_at(1))
        self.message(ts_at(2), fragment_of=ts_at(1))
        self.green()
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2)])
        self.assertEqual(self.slack.deletes[1][0], "xoxb-source")

    def test_void_still_deletes_orphan_fragments_across_rounds(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.store.request_analysis(self.iid, fresh=True, now=NOW + 5)
        self.message(ts_at(2), fragment_of=ts_at(1))
        self.message(ts_at(3), fragment_of=ts_at(1))
        self.assertTrue(self.purger.join_fragment("C1", ts_at(1), ts_at(2), NOW))
        self.assertTrue(self.purger.join_fragment("C1", ts_at(1), ts_at(3), NOW))
        self.budgets.slack.take("normal", NOW, self.budgets.slack.available("normal", NOW) - 1)
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2)])
        self.budgets = Budgets(self.cfg)
        self.purger = self.make_purger()
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2), ts_at(3)])
        self.assertEqual(self.store.purge_rows("state='void' AND id IN (SELECT purge_id FROM"
                                               " purge_targets WHERE state='pending')"), [])

    def test_cant_delete_alert_falls_back(self):
        self.message(ts_at(1))
        self.message(ts_at(2), category="duplicate")
        self.reply("C1", ts_at(1), ts_at(5))
        (pid,) = self.green()
        self.slack.errors[ts_at(2)] = SlackError("cant_delete_message")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")
        self.assertNotIn(ts_at(5), [d[2] for d in self.slack.deletes])
        rows = self.store.read(
            "SELECT thread_ts, payload FROM outbox WHERE kind='analysis' AND status='pending'")
        self.assertEqual(rows[0][0], ts_at(2))
        self.assertEqual(json.loads(rows[0][1])["text"], "🔍 分析全文")
        self.assertEqual(self.store.get_report(self.iid, "C1")["root_ts"], ts_at(2))

    def test_fallback_is_per_channel(self):
        self.message(ts_at(1))
        self.message(ts_at(2), channel="C2", category="duplicate")
        pids = self.green(channels=("C1", "C2"))
        self.slack.errors[ts_at(2)] = SlackError("channel_not_found")
        self.purger.step(NOW)
        self.assertEqual([self.state(p) for p in pids], ["done", "fallback"])
        rows = self.store.read("SELECT channel, thread_ts FROM outbox WHERE kind='analysis'")
        self.assertEqual(rows, [("C2", ts_at(2))])

    def test_ratelimit_stops_round_and_resumes(self):
        for i in range(1, 4):
            self.message(ts_at(i))
        (pid,) = self.green()
        self.slack.errors[ts_at(2)] = SlackRateLimited(3)
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1)])
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2), ts_at(3)])
        self.assertEqual(self.state(pid), "done")

    def test_resume_from_targets_after_restart(self):
        for i in range(1, 8):
            self.message(ts_at(i))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.purger = self.make_purger()
        self.purger.step(NOW)
        deleted = [d[2] for d in self.slack.deletes]
        self.assertEqual(deleted, [ts_at(i) for i in range(1, 8)])
        self.assertEqual(self.state(pid), "done")

    def test_disabled_turns_pending_into_fallback(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger = self.make_purger(source=None)
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")
        self.assertEqual(self.slack.deletes, [])
        self.assertEqual(len(self.store.read("SELECT 1 FROM outbox WHERE kind='analysis'")), 1)

    def test_switch_off_by_config(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.cfg = dataclasses.replace(self.cfg, purge_green=False)
        self.purger = self.make_purger()
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")

    def test_batch_limit_5(self):
        for i in range(1, 13):
            self.message(ts_at(i))
        (pid,) = self.green()
        counts = [self.purger.step(NOW) for _ in range(3)]
        self.assertEqual(counts, [PURGE_BATCH, PURGE_BATCH, 2])
        self.assertEqual(self.state(pid), "done")

    def test_gone_counts_as_success(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.slack.errors[ts_at(1)] = SlackError("message_not_found")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "done")
        self.assertEqual(self.store.deleted_ts("C1"), {ts_at(1)})

    def test_never_silence_check_voids(self):
        self.message(ts_at(1))
        self.checks["ORS1"] = CheckSpec(key="ORS1", never_silence=True)
        (pid,) = self.green()
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")

    def test_pending_updates_cancelled_and_blocked(self):
        self.message(ts_at(1))
        self.reply("C1", ts_at(1), ts_at(3))
        self.store.enqueue_reply(incident_id=self.iid, channel="C1", kind="update", priority=2,
                                 due_epoch=NOW, payload={}, dedupe_key="update:x", now=NOW)
        self.green()
        self.purger.step(NOW)
        self.assertEqual(self.store.read("SELECT status FROM outbox WHERE kind='update'"),
                         [("cancelled",)])
        self.assertTrue(blocked_thread(self.store, "C1", ts_at(1)))
        self.assertFalse(blocked_thread(self.store, "C1", ts_at(3)))


class CodexFixesTest(Base):
    def test_unprocessed_reaction_in_other_channel_blocks_all(self):
        self.message(ts_at(1))
        self.message(ts_at(2), channel="C2", category="duplicate")
        pids = self.green(channels=("C1", "C2"))
        self.store.add_reaction_inbox("C2", ts_at(2), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(self.slack.deletes, [])
        self.assertEqual([self.state(p) for p in pids], ["pending", "pending"])

    def test_reaction_on_a_fragment_blocks(self):
        self.message(ts_at(1))
        self.message(ts_at(2), fragment_of=ts_at(1))
        self.green()
        self.purger._collect(self.store.purge_rows("1=1")[0])
        self.store.add_reaction_inbox("C1", ts_at(2), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(self.slack.deletes, [])

    def test_orphan_fragments_wait_for_inbox(self):
        self.message(ts_at(1))
        self.green()
        self.purger.step(NOW)
        self.store.request_analysis(self.iid, fresh=True, now=NOW + 5)
        self.message(ts_at(2), fragment_of=ts_at(1))
        self.purger.join_fragment("C1", ts_at(1), ts_at(2), NOW)
        self.store.add_reaction_inbox("C1", ts_at(1), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1)])

    def test_new_evidence_void_requests_fresh_analysis(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.message(ts_at(9), category="spike")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")
        incident = self.store.get_incident(self.iid)
        self.assertEqual(incident.analysis_state, "pending")
        self.assertTrue(incident.fresh_requested)

    def test_superseded_void_does_not_request_again(self):
        self.message(ts_at(1))
        self.green()
        self.store.complete_analysis(self.iid, GREEN, "m", NOW + 9)
        self.purger.step(NOW)
        self.assertEqual(self.store.get_incident(self.iid).analysis_state, "done")

    def test_fallback_interrupted_before_enqueue_is_retried(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger = self.make_purger(source=None)
        real = self.store.enqueue_reply
        self.store.enqueue_reply = lambda **kw: (_ for _ in ()).throw(RuntimeError("crash"))
        with self.assertRaises(RuntimeError):
            self.purger.step(NOW)
        self.assertEqual(self.state(pid), "pending")
        self.store.enqueue_reply = real
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")
        self.assertEqual(len(self.store.read("SELECT 1 FROM outbox WHERE kind='analysis'")), 1)

    def test_done_not_written_while_a_target_is_pending(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.store.add_purge_targets(pid, "C1", "fragment", ["late"])
        row = self.store.purge_rows("id=?", (pid,))[0]
        self.store.set_purge(pid, state="pending")
        self.purger._finish(row, "done", NOW)
        self.assertEqual(self.state(pid), "pending")

    def test_fragment_joined_after_fallback_is_deleted_when_head_gone(self):
        self.message(ts_at(1))
        self.message(ts_at(2), category="duplicate")
        (pid,) = self.green()
        self.slack.errors[ts_at(2)] = SlackError("cant_delete_message")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")
        self.message(ts_at(3), fragment_of=ts_at(1))
        self.assertTrue(self.purger.join_fragment("C1", ts_at(1), ts_at(3), NOW))
        self.purger.step(NOW)
        self.assertEqual(self.slack.deletes[-1][2], ts_at(3))


class CodexRound2Test(Base):
    def test_reaction_on_untargeted_fragment_in_other_channel_blocks(self):
        self.message(ts_at(1))
        self.message(ts_at(2), channel="C2", category="duplicate")
        self.message(ts_at(3), channel="C2", fragment_of=ts_at(2))
        self.green(channels=("C1", "C2"))
        self.store.add_reaction_inbox("C2", ts_at(3), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(self.slack.deletes, [])

    def test_reaction_on_unindexed_reply_in_other_channel_blocks(self):
        self.message(ts_at(1))
        self.message(ts_at(2), channel="C2", category="duplicate")
        self.reply("C2", ts_at(2), ts_at(5), indexed=False)
        self.green(channels=("C1", "C2"))
        self.store.add_reaction_inbox("C2", ts_at(5), "U1", "x", NOW)
        self.purger.step(NOW)
        self.assertEqual(self.slack.deletes, [])

    def test_crash_between_request_and_void_still_reanalyses(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.message(ts_at(9), category="spike")
        real = self.purger._finish

        def crash(purge_row, state, now, error=None):
            raise RuntimeError("crash")

        self.purger._finish = crash
        with self.assertRaises(RuntimeError):
            self.purger.step(NOW)
        self.purger._finish = real
        self.assertEqual(self.store.get_incident(self.iid).analysis_state, "pending")
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "void")

    def test_failed_alert_left_by_a_crash_still_falls_back(self):
        self.message(ts_at(1))
        self.reply("C1", ts_at(1), ts_at(5))
        (pid,) = self.green()
        self.purger._collect(self.store.purge_rows("id=?", (pid,))[0])
        self.store.set_target(pid, "alert", ts_at(1), "failed", error="cant_delete_message",
                              epoch=NOW)
        self.purger.step(NOW)
        self.assertEqual(self.state(pid), "fallback")
        self.assertNotIn(ts_at(5), [d[2] for d in self.slack.deletes])
        self.assertEqual(len(self.store.read("SELECT 1 FROM outbox WHERE kind='analysis'")), 1)


class JoinTest(Base):
    def test_duplicate_after_green_joins(self):
        self.message(ts_at(1))
        (pid,) = self.green()
        self.purger.step(NOW)
        self.message(ts_at(2), category="duplicate")
        joined = self.purger.join(self.store.get_incident(self.iid), "C1", ts_at(2),
                                  category="duplicate", needs_analysis=False, now=NOW)
        self.assertTrue(joined)
        self.assertEqual(self.state(pid), "pending")
        self.purger.step(NOW)
        self.assertEqual([d[2] for d in self.slack.deletes], [ts_at(1), ts_at(2)])

    def test_late_channel_joins_with_same_generation(self):
        self.message(ts_at(1))
        self.green()
        self.message(ts_at(2), channel="C2", category="duplicate")
        self.assertTrue(self.purger.join(self.store.get_incident(self.iid), "C2", ts_at(2),
                                         category="duplicate", needs_analysis=False, now=NOW))
        rows = self.store.purge_rows("channel='C2'")
        self.assertEqual(rows[0]["generation"], NOW)

    def test_spike_or_needs_analysis_does_not_join(self):
        self.message(ts_at(1))
        self.green()
        incident = self.store.get_incident(self.iid)
        self.assertFalse(self.purger.join(incident, "C1", ts_at(2), category="spike",
                                          needs_analysis=True, now=NOW))
        self.assertFalse(self.purger.join(incident, "C1", ts_at(2), category="new",
                                          needs_analysis=True, now=NOW))

    def test_no_join_without_green_purge(self):
        self.message(ts_at(1))
        self.store.complete_analysis(self.iid, GREEN, "m", NOW)
        self.assertFalse(self.purger.join(self.store.get_incident(self.iid), "C1", ts_at(2),
                                          category="duplicate", needs_analysis=False, now=NOW))


if __name__ == "__main__":
    unittest.main()
