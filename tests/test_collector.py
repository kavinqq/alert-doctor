import hashlib
import os
import tempfile
import unittest
from unittest import mock

from alert_doctor.collector import FINGERPRINT_SINCE_BEAT, Collector
from alert_doctor.config import ChannelSpec, Config
from alert_doctor.fingerprint import fine_fp
from alert_doctor.parse import parse_message
from alert_doctor.models import CheckSpec, ElkSpec, Evidence
from alert_doctor.rules import Rule
from alert_doctor.slack_io import SlackError, SlackRateLimited
from alert_doctor.store import Store

NOW = 1_760_000_000.0
BOT_USER = "UBOT"
BOT_ID = "BBOT"


def alert_text(message="連線逾時 12", code="ORS1", title="[L3] 訂單檢查"):
    return f"{title}\n{{'code': '{code}', 'task_id': 't1', 'result': {{'level': 3, 'message': '{message}'}}}}"


def msg(ts, text=None, **extra):
    return {"type": "message", "ts": ts, "text": text if text is not None else alert_text(), **extra}


def ts_at(offset, n=0):
    return f"{NOW + offset:.0f}.{n:06d}"


class FakeSlack:
    def __init__(self):
        self.posts, self.reactions, self.history_calls = [], [], []
        self.history_result = []
        self.post_errors = []
        self.reaction_errors = []

    def auth_test(self, token):
        return {"user_id": BOT_USER, "bot_id": BOT_ID}

    def post_message(self, token, channel, text, thread_ts=None):
        if self.post_errors:
            raise self.post_errors.pop(0)
        self.posts.append((channel, text, thread_ts))
        return f"{NOW + 1000 + len(self.posts):.0f}.000001"

    def add_reaction(self, token, channel, ts, name):
        if self.reaction_errors:
            raise self.reaction_errors.pop(0)
        self.reactions.append((ts, name))

    def remove_reaction(self, token, channel, ts, name):
        pass

    def history(self, token, channel, oldest, limit=200):
        self.history_calls.append(oldest)
        return list(self.history_result)


class FakeElk:
    def __init__(self, evidence=None):
        self.calls = []
        self.evidence = evidence or recovered()

    def gather(self, spec, until, variables):
        self.calls.append((spec, until, variables))
        return self.evidence


def recovered():
    return Evidence(True, "2026-01-01T00:00:00+08:00", "2026-01-01T00:17:00+08:00", total=3,
                    per_host={"10.0.0.1": 3}, histogram=(("a", 3), ("b", 0), ("c", 0), ("d", 0)))


def failed_elk():
    return Evidence(False, "x", "y", error="TimeoutError")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(channels=(ChannelSpec("C1", "alerts-a", ("sys",)),), workspace_url="https://w.slack.com",
                          db_path=os.path.join(self.tmp.name, "t.db"),
                          archive_db_path=os.path.join(self.tmp.name, "archive.db"),
                          watchdog_snapshot_path=os.path.join(self.tmp.name, "none.json"))
        self.store = Store(":memory:")
        self.slack = FakeSlack()
        self.elk = FakeElk()
        self.now = NOW
        self.rules = []
        self.checks = {}

    def make(self, **kw):
        return Collector(self.cfg, self.store, self.slack, self.elk, self.rules, self.checks,
                         "xoxb", clock=lambda: self.now, bot_user_id=BOT_USER, bot_id=BOT_ID, **kw)

    def feed(self, collector, ts, text=None):
        collector.on_socket_event("events_api", {"event": msg(ts, text, channel="C1")})

    def publish(self, collector, after=25, rounds=5):
        """Run the publisher past the batch settle time without moving the collector's clock."""
        for i in range(rounds):
            collector.publisher.process(self.now + after + i)

    def handle_and_publish(self, collector):
        handled = collector.process_pending()
        self.publish(collector)
        return handled

    def failing(self, *errors):
        """Make message handling itself fail (after the incident is bound) with `errors`, in order."""
        original = Collector._attachments
        queue = list(errors)

        def flaky(collector, incident, alert):
            if queue:
                raise queue.pop(0)
            return original(collector, incident, alert)
        return mock.patch.object(Collector, "_attachments", flaky)

    def incident_of(self, ts):
        row = self.store.read("SELECT incident_id FROM messages WHERE ts=?", (ts,))
        return self.store.get_incident(row[0][0])

    def category_of(self, ts):
        return self.store.read("SELECT category FROM messages WHERE ts=?", (ts,))[0][0]


class IntakeTests(Base):
    def test_same_message_via_socket_and_backfill_is_replied_once(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.slack.history_result = [msg(ts)]
        self.assertEqual(c.backfill(), 0)
        self.assertEqual(self.handle_and_publish(c), 1)
        self.assertEqual(self.handle_and_publish(c), 0)
        self.assertEqual(len(self.slack.posts), 1)
        self.assertEqual(len(self.slack.reactions), 1)

    def test_backfill_first_then_socket_is_replied_once(self):
        c = self.make()
        ts = ts_at(-10)
        self.slack.history_result = [msg(ts)]
        self.assertEqual(c.backfill(), 1)
        self.feed(c, ts)
        self.handle_and_publish(c)
        self.assertEqual(len(self.slack.posts), 1)

    def test_ineligible_events_are_ignored(self):
        c = self.make()
        events = [
            ("events_api", {"event": msg(ts_at(-9, 1), channel="C1", thread_ts=ts_at(-50), user="U1")}),
            ("events_api", {"event": msg(ts_at(-9, 2), channel="C1", user=BOT_USER)}),
            ("events_api", {"event": msg(ts_at(-9, 3), channel="C1", subtype="bot_message", bot_id=BOT_ID)}),
            ("events_api", {"event": msg(ts_at(-9, 4), channel="C9")}),
            ("events_api", {"event": msg(ts_at(-9, 5), channel="C1", subtype="message_changed")}),
            ("events_api", {"event": {"type": "reaction_added", "channel": "C1"}}),
            ("hello", {}),
        ]
        for kind, payload in events:
            c.on_socket_event(kind, payload)
        self.assertEqual(self.store.pending_messages(), [])

    def test_accepts_top_level_bot_message_and_thread_root(self):
        c = self.make()
        c.on_socket_event("events_api", {"event": msg(ts_at(-9, 1), channel="C1", subtype="bot_message", bot_id="BOTHER")})
        ts = ts_at(-9, 2)
        c.on_socket_event("events_api", {"event": msg(ts, channel="C1", thread_ts=ts)})
        self.assertEqual(len(self.store.pending_messages()), 2)

    def test_backfill_filters_and_advances_cursor(self):
        c = self.make()
        self.slack.history_result = [
            msg(ts_at(-30), user=BOT_USER),
            msg(ts_at(-20)),
            msg(ts_at(-10, 1), thread_ts=ts_at(-50)),
        ]
        self.assertEqual(c.backfill(), 1)
        self.assertEqual(self.store.get_cursor("C1"), ts_at(-10, 1))
        self.assertEqual(float(self.slack.history_calls[0]), NOW - 3600)
        c.backfill()
        self.assertEqual(float(self.slack.history_calls[1]), float(ts_at(-10, 1)) - 300)

    def test_backfill_since_overrides_cursor(self):
        c = self.make()
        self.store.set_cursor("C1", ts_at(-10))
        c.backfill(since=NOW - 7200)
        self.assertEqual(float(self.slack.history_calls[0]), NOW - 7200)

    def test_start_reads_bot_identity(self):
        c = Collector(self.cfg, self.store, self.slack, self.elk, [], {}, "xoxb")
        c.start()
        self.assertEqual((c.bot_user_id, c.bot_id), (BOT_USER, BOT_ID))


class ClassificationTests(Base):
    def setUp(self):
        super().setUp()
        self.checks = {"ORS1": CheckSpec(key="ORS1", elk=ElkSpec(index="logs-*", query={"match_all": {}}))}

    def test_new_incident_requests_analysis(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.handle_and_publish(c)
        incident = self.incident_of(ts)
        self.assertEqual(incident.analysis_state, "pending")
        self.assertEqual(self.category_of(ts), "new")
        self.assertEqual(self.slack.posts[0][2], ts)
        self.assertEqual(self.slack.reactions[0], (ts, "mag"))

    def test_noise_rule_with_recovered_elk_mutes_without_analysis(self):
        self.rules = [Rule(id="r", action="noise", match_code="ORS1", note="已知抖動", require_transient=True)]
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.handle_and_publish(c)
        self.assertEqual(self.category_of(ts), "noise")
        self.assertEqual(self.slack.reactions[0][1], "mute")
        self.assertEqual(self.incident_of(ts).analysis_state, "none")
        self.assertEqual(len(self.elk.calls), 1)
        self.assertIsNotNone(self.store.load_evidence(self.incident_of(ts).id))

    def test_elk_failure_is_not_noise(self):
        self.elk.evidence = failed_elk()
        self.rules = [Rule(id="r", action="noise", match_code="ORS1", note="x", require_transient=True)]
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertNotEqual(self.category_of(ts), "noise")
        self.assertEqual(self.category_of(ts), "new")
        self.assertEqual(self.incident_of(ts).analysis_state, "pending")

    def test_noise_without_require_transient_skips_elk(self):
        self.rules = [Rule(id="r", action="noise", match_code="ORS1", note="x")]
        self.checks = {}
        c = self.make()
        self.feed(c, ts_at(-10))
        self.handle_and_publish(c)
        self.assertEqual(self.elk.calls, [])
        self.assertEqual(self.slack.reactions[0][1], "mute")

    def test_elk_called_with_epoch_and_vkwargs(self):
        c = self.make()
        text = "[L3] 訂單檢查\n{'code': 'ORS1', 'vkwargs': {'order': 'A1'}, 'result': {'level': 3, 'message': 'x'}}"
        ts = ts_at(-10)
        self.feed(c, ts, text)
        c.process_pending()
        spec, until, variables = self.elk.calls[0]
        self.assertEqual((spec, until, variables), (self.checks["ORS1"].elk, float(ts), {"order": "A1"}))

    def test_duplicate_is_reported_in_the_anchor_thread(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed(c, first)
        c.process_pending()
        self.publish(c)
        self.feed(c, second, alert_text("連線逾時 99"))
        c.process_pending()
        self.assertEqual(self.category_of(second), "duplicate")
        self.assertEqual(self.incident_of(second).count, 2)
        self.assertEqual(len(self.elk.calls), 1)
        self.publish(c, after=200)
        self.assertEqual([p[2] for p in self.slack.posts], [first, first])
        self.assertIn("累計 2 則", self.slack.posts[1][1])

    def test_unparsed_is_replied_not_analyzed(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts, "完全不是告警格式")
        c.process_pending()
        self.assertEqual(self.category_of(ts), "unparsed")
        self.assertEqual(self.incident_of(ts).analysis_state, "none")

    def seed_history(self):
        """An unrelated message 8 days back, so all 7 baseline days count as collected."""
        self.store.insert_message(
            parse_message("C1", ts_at(-8 * 86400), alert_text(code="OTHER")), NOW)

    def test_spike_counts_current_plus_one_and_seven_daily_baselines(self):
        c = self.make()
        self.seed_history()
        for i in range(4):
            self.feed(c, ts_at(-300 + i))
        old = ts_at(-3 * 86400 - 100)
        self.store.insert_message(parse_message("C1", old, alert_text()), NOW)
        c.process_pending()
        last = ts_at(-5)
        self.feed(c, last)
        with mock.patch("alert_doctor.collector.triage.detect_spike", return_value=True) as spy:
            c.process_pending()
        current, baseline = spy.call_args.args
        self.assertEqual(current, 5)
        self.assertEqual(len(baseline), 7)
        self.assertEqual(baseline[2], 1)
        self.assertEqual(sum(baseline), 1)
        self.assertEqual(self.category_of(last), "spike")
        self.assertNotIn(float(last), [call[1] for call in self.elk.calls],
                         "evidence gathered for this incident minutes ago is reused")

    def test_days_before_the_fingerprint_version_are_not_baseline(self):
        self.store.beat(FINGERPRINT_SINCE_BEAT, NOW - 3600)
        c = self.make()
        self.seed_history()
        self.feed(c, ts_at(-300))
        with mock.patch("alert_doctor.collector.triage.detect_spike", return_value=False) as spy:
            c.process_pending()
        self.assertEqual(spy.call_args.args[1], [])

    def test_first_handled_message_marks_the_fingerprint_version(self):
        c = self.make()
        self.seed_history()
        c.process_pending()
        self.assertEqual(self.store.last_beat(FINGERPRINT_SINCE_BEAT), float(ts_at(-8 * 86400)))

    def test_no_spike_before_baseline_exists(self):
        c = self.make()
        for i in range(6):
            self.feed(c, ts_at(-300 + i))
        c.process_pending()
        self.assertNotIn("spike", [self.category_of(ts_at(-300 + i)) for i in range(6)])

    def test_spike_detected_end_to_end(self):
        c = self.make()
        self.seed_history()
        for i in range(4):
            self.feed(c, ts_at(-300 + i))
        c.process_pending()
        last = ts_at(-5)
        self.feed(c, last)
        c.process_pending()
        self.assertEqual(self.category_of(last), "spike")
        self.assertEqual(self.incident_of(last).analysis_state, "pending")


class DeliveryFailureTests(Base):
    def test_failed_after_five_attempts_and_shows_in_coverage(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        with self.failing(*[SlackError("boom")] * 6):
            for _ in range(5):
                self.assertEqual(c.process_pending(), 0)
                self.now += 3600
            self.publish(c)
        self.assertEqual(self.store.pending_messages(now=self.now), [])
        cov = self.store.coverage("C1", NOW - 100, NOW)
        self.assertEqual((cov["failed"], cov["handled"]), (1, 0))
        self.assertEqual(cov["unhandled"], [(ts, "[L3] 訂單檢查")])
        self.assertEqual(self.slack.posts, [])

    def test_transient_failure_retries_and_stays_new_with_one_reply(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        with self.failing(SlackError("a"), OSError("net")):
            for _ in range(3):
                self.handle_and_publish(c)
                self.now += 3600
        self.assertEqual(self.category_of(ts), "new")
        incident = self.incident_of(ts)
        self.assertEqual(incident.count, 1)
        self.assertEqual(incident.analysis_state, "pending")
        self.assertEqual(len(self.slack.posts), 1)

    def test_retry_of_duplicate_does_not_double_count(self):
        c = self.make()
        self.feed(c, ts_at(-20))
        c.process_pending()
        second = ts_at(-10)
        self.feed(c, second)
        with self.failing(SlackError("a")):
            c.process_pending()
            self.now += 3600
            c.process_pending()
        self.assertEqual(self.incident_of(second).count, 2)
        self.assertEqual(self.category_of(second), "duplicate")

    def test_retry_after_restart_keeps_new_category(self):
        first = self.make()
        ts = ts_at(-10)
        self.feed(first, ts)
        with self.failing(SlackError("a")):
            first.process_pending()
        self.now += 3600
        restarted = self.make()
        restarted.process_pending()
        self.assertEqual(self.category_of(ts), "new")
        self.assertEqual(self.incident_of(ts).analysis_state, "pending")

    def test_reaction_failure_does_not_repost_reply(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.slack.reaction_errors = [SlackError("x")]
        self.handle_and_publish(c)
        self.now += 3600
        self.handle_and_publish(c)
        self.assertEqual(len(self.slack.posts), 1)
        self.assertEqual(self.category_of(ts), "new")

    def test_slack_rate_limit_pauses_publishing_not_classification(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed(c, first)
        self.feed(c, second, alert_text("別的錯誤", code="ORS2"))
        self.slack.post_errors = [SlackRateLimited(30)]
        self.assertEqual(c.process_pending(), 2)
        self.assertEqual(c.publisher.process(self.now + 25), 0)
        self.assertEqual(c.publisher.process(self.now + 40), 0)
        self.assertEqual(self.slack.posts, [])
        self.publish(c, after=56)
        self.assertEqual(len(self.slack.posts), 2)

    def test_rate_limit_during_handling_stops_round_and_pauses(self):
        c = self.make()
        self.feed(c, ts_at(-20))
        self.feed(c, ts_at(-10), alert_text("別的錯誤"))
        with self.failing(SlackRateLimited(30)):
            self.assertEqual(c.process_pending(), 0)
            self.assertEqual(c.process_pending(), 0)
            self.now += 31
            self.assertEqual(c.process_pending(), 2)

    def test_non_slack_error_does_not_block_other_messages(self):
        c = self.make()
        self.feed(c, ts_at(-20))
        self.feed(c, ts_at(-10), alert_text("別的錯誤"))
        original = self.store.create_incident
        calls = []

        def flaky(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("db hiccup")
            return original(*a, **k)

        with mock.patch.object(self.store, "create_incident", side_effect=flaky):
            self.assertEqual(c.process_pending(), 1)


class ResilienceTests(Base):
    def attempts_of(self, ts):
        return self.store.read("SELECT attempts, status FROM messages WHERE ts=?", (ts,))[0]

    def test_network_errors_never_use_up_attempts(self):
        import urllib.error
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        with self.failing(*[OSError("a"), urllib.error.URLError("b"), TimeoutError("c")] * 3):
            for _ in range(9):
                c.process_pending()
                self.now += 60
            self.assertEqual(self.attempts_of(ts), (0, "received"))
            self.assertEqual(c.process_pending(), 1)

    def test_rate_limit_does_not_use_an_attempt(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        with self.failing(SlackRateLimited(30)):
            c.process_pending()
        self.assertEqual(self.attempts_of(ts), (0, "received"))

    def test_failed_message_backs_off_instead_of_immediate_retry(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        with self.failing(SlackError("a")):
            c.process_pending()
        self.assertEqual(self.store.pending_messages(now=self.now), [])
        self.assertEqual(len(self.store.pending_messages(now=self.now + 31)), 1)

    def test_failed_post_does_not_orphan_incident(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.slack.post_errors = [SlackError("a")]
        self.handle_and_publish(c)
        self.assertEqual(self.slack.posts, [])
        row = self.store.read("SELECT analysis_state FROM incidents")
        self.assertEqual(row[0][0], "pending")

    def test_restart_does_not_double_count_attached_message(self):
        first = self.make()
        self.feed(first, ts_at(-20))
        first.process_pending()
        second = ts_at(-10)
        self.feed(first, second)
        with self.failing(SlackError("x")):
            first.process_pending()
        self.now += 3600
        self.make().process_pending()
        self.assertEqual(self.incident_of(second).count, 2)

    def test_backfill_rereads_behind_cursor(self):
        c = self.make()
        self.store.set_cursor("C1", ts_at(-10))
        c.backfill()
        self.assertEqual(float(self.slack.history_calls[0]), float(ts_at(-10)) - 300)

    def test_heartbeat_after_each_message(self):
        c = self.make()
        self.feed(c, ts_at(-20))
        beats = []
        original = self.store.beat
        self.store.beat = lambda comp, at: (beats.append(comp), original(comp, at))
        c.process_pending()
        self.assertEqual(beats, ["collector"])

    def test_loop_revives_recent_failed_messages(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        self.store._db.execute("UPDATE messages SET status='failed', attempts=5")
        c.run_forever(stop=lambda: self.now > NOW, sleep=lambda _: setattr(self, "now", self.now + 5))
        self.assertEqual(self.category_of(ts), "new")


class SpikeFollowupTests(Base):
    def setUp(self):
        super().setUp()
        self.checks = {}

    def spike_on_done_incident(self, verdict_category="noise"):
        c = self.collector = self.make()
        anchor = ts_at(-300)
        self.store.insert_message(parse_message("C1", ts_at(-8 * 86400), alert_text(code="OTHER")), NOW)
        for i in range(4):
            self.feed(c, ts_at(-300 + i))
        c.process_pending()
        self.publish(c)
        incident = self.incident_of(anchor)
        self.store.claim_incident("w", NOW)
        self.store.complete_analysis(incident.id, {"summary": "s", "category": verdict_category}, "m", NOW - 60)
        last = ts_at(-5)
        self.feed(c, last)
        c.process_pending()
        return incident, anchor, last

    def test_spike_is_an_immediate_update_in_the_anchor_thread(self):
        c = self.make()
        anchor = ts_at(-300)
        self.store.insert_message(parse_message("C1", ts_at(-8 * 86400), alert_text(code="OTHER")), NOW)
        for i in range(4):
            self.feed(c, ts_at(-300 + i))
        self.handle_and_publish(c)
        last = ts_at(-5)
        self.feed(c, last)
        c.process_pending()
        self.assertEqual(self.store.read("SELECT due_epoch FROM outbox WHERE kind='update'"), [(self.now,)])
        c.publisher.process(self.now + 30)
        self.assertEqual(self.category_of(last), "spike")
        in_thread = [p for p in self.slack.posts if p[2] == anchor]
        self.assertEqual(len(in_thread), 2)
        self.assertEqual(self.slack.posts[-1][2], anchor)
        self.assertIn("嚴重度升級", self.slack.posts[-1][1])
        self.assertIn((anchor, "large_orange_circle"), self.slack.reactions)

    def test_spike_requests_fresh_analysis_even_after_recent_noise_verdict(self):
        incident, _, _ = self.spike_on_done_incident("noise")
        reopened = self.store.get_incident(incident.id)
        self.assertEqual(reopened.analysis_state, "pending")
        self.assertTrue(reopened.fresh_requested)

    def test_spike_keeps_recent_real_problem_verdict(self):
        incident, _, _ = self.spike_on_done_incident("infra")
        self.assertEqual(self.store.get_incident(incident.id).analysis_state, "done")

    def test_critical_spike_keeps_owners_and_appends_spike_link(self):
        self.checks = {"ORS1": CheckSpec(key="ORS1", never_silence=True, owners=("UOWN",))}
        incident, anchor, last = self.spike_on_done_incident()
        self.publish(self.collector, after=200)
        self.assertEqual(self.category_of(last), "critical")
        first, update = [p for p in self.slack.posts if p[2] == anchor]
        self.assertIn("<@UOWN>", first[1])
        self.assertIn("🚨", first[1])
        self.assertNotIn("<@", update[1])
        self.assertIn((anchor, "rotating_light"), self.slack.reactions)

    def test_v1_history_is_not_a_zero_baseline(self):
        old = parse_message("C1", ts_at(-8 * 86400), alert_text(code="OTHER"))
        self.store.insert_message(old, NOW)
        v1 = self.store.create_incident(old, "v1-fp", "g")
        self.store.mark_handled("C1", old.ts, category="new", incident_id=v1.id, fingerprint="v1-fp",
                                reply_ts="1.0", handled_epoch=NOW - 8 * 86400)
        c = self.make()
        for i in range(6):
            self.feed(c, ts_at(-300 + i))
        c.process_pending()
        self.assertNotIn("spike", [self.category_of(ts_at(-300 + i)) for i in range(6)])

    def test_unparsed_never_silence_title_is_critical_and_analyzed(self):
        self.rules = [Rule(id="r", action="never_silence", match_title="下單")]
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts, "下單失敗\n不是 dict 的內容")
        c.process_pending()
        self.assertEqual(self.category_of(ts), "critical")
        self.assertEqual(self.incident_of(ts).analysis_state, "pending")


class MultiChannelTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg = Config(
            channels=(ChannelSpec("C1", "alerts-cms", ("cms",)),
                      ChannelSpec("C2", "alerts-pxy", ("pxy", "fastpxy"))),
            workspace_url="https://w.slack.com", db_path=self.cfg.db_path)

    def feed_in(self, collector, channel, ts, text=None):
        collector.on_socket_event("events_api", {"event": msg(ts, text, channel=channel)})

    def row(self, channel, ts, column):
        return self.store.read(
            f"SELECT {column} FROM messages WHERE channel=? AND ts=?", (channel, ts))[0][0]

    def test_events_from_unlisted_channel_are_ignored(self):
        c = self.make()
        self.feed_in(c, "CZ", ts_at(-10))
        self.assertEqual(c.process_pending(), 0)

    def test_same_task_in_two_channels_one_incident_both_replied(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", first)
        self.feed_in(c, "C2", second, alert_text("連線逾時 99"))
        self.handle_and_publish(c)
        inc = self.store.get_incident(self.store.message_incident("C1", first))
        self.assertEqual(self.store.message_incident("C2", second), inc.id)
        self.assertEqual(inc.count, 2)
        self.assertEqual([(p[0], p[2]) for p in self.slack.posts], [("C1", first), ("C2", second)])
        self.assertEqual(self.row("C2", second, "category"), "duplicate")
        self.assertIn(f"https://w.slack.com/archives/C1/p{first.replace('.', '')}", self.slack.posts[1][1])
        self.assertIn("同一事件已在", self.slack.posts[1][1])
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM incidents")[0][0], 1)
        self.assertEqual(self.store.get_incident(inc.id).analysis_state, "pending")

    def test_cross_channel_duplicate_is_indexed_as_followup(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", first)
        self.feed_in(c, "C2", second)
        self.handle_and_publish(c)
        kinds = {r[0]: r[1] for r in self.store.read(
            "SELECT message_ts, kind FROM reply_index")}
        self.assertEqual(kinds, {first: "triage", second: "followup"})
        reply_ts = self.row("C2", second, "reply_ts")
        self.assertEqual(self.store.lookup_reply("C2", reply_ts)[0], second)

    def test_same_channel_duplicate_joins_the_first_report(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", first)
        self.feed_in(c, "C1", second)
        self.handle_and_publish(c)
        (post,) = self.slack.posts
        self.assertEqual(post[2], first)
        self.assertNotIn("同一事件已在", post[1])
        self.assertIn("2 則", post[1])
        self.assertEqual(self.store.read("SELECT message_ts, kind FROM reply_index"), [(first, "triage")])

    def test_task_id_of_another_check_does_not_merge(self):
        c = self.make()
        first, second = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", first)
        self.feed_in(c, "C2", second, alert_text(code="OTHER", title="[L3] 別的檢查"))
        c.process_pending()
        self.assertNotEqual(self.store.message_incident("C1", first), self.store.message_incident("C2", second))

    def test_task_link_expires_after_a_day(self):
        c = self.make()
        first, second = ts_at(-100000), ts_at(-10)
        self.feed_in(c, "C1", first)
        self.now = NOW - 99000
        c.process_pending()
        self.now = NOW
        self.feed_in(c, "C2", second)
        c.process_pending()
        self.assertNotEqual(self.store.message_incident("C1", first), self.store.message_incident("C2", second))

    def test_source_system_defaults_to_first_system_of_channel(self):
        c = self.make()
        a, b = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", a, alert_text(code="X1", title="t1"))
        self.feed_in(c, "C2", b, alert_text(code="X2", title="t2"))
        c.process_pending()
        self.assertEqual(self.incident_of_in("C1", a).source_system, "cms")
        self.assertEqual(self.incident_of_in("C2", b).source_system, "pxy")

    def incident_of_in(self, channel, ts):
        return self.store.get_incident(self.store.message_incident(channel, ts))

    def test_check_system_overrides_channel_default(self):
        self.checks = {"ORS1": CheckSpec(key="ORS1", system="fastpxy")}
        c = self.make()
        ts = ts_at(-10)
        self.feed_in(c, "C2", ts)
        c.process_pending()
        self.assertEqual(self.incident_of_in("C2", ts).source_system, "fastpxy")

    def test_fingerprint_is_fine_fp_plus_source_system(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed_in(c, "C1", ts)
        c.process_pending()
        alert = parse_message("C1", ts, alert_text())
        expected = hashlib.sha1(f"{fine_fp(alert)}|cms".encode()).hexdigest()
        self.assertEqual(self.row("C1", ts, "fingerprint"), expected)
        self.assertEqual(self.incident_of_in("C1", ts).fingerprint, expected)

    def test_same_text_different_system_is_a_different_fingerprint(self):
        c = self.make()
        a, b = ts_at(-20), ts_at(-10)
        self.feed_in(c, "C1", a, alert_text(message="x").replace("t1", "ta"))
        self.feed_in(c, "C2", b, alert_text(message="x").replace("t1", "tb"))
        c.process_pending()
        self.assertNotEqual(self.row("C1", a, "fingerprint"), self.row("C2", b, "fingerprint"))
        self.assertNotEqual(self.store.message_incident("C1", a), self.store.message_incident("C2", b))

    def test_each_channel_has_its_own_backfill_cursor(self):
        c = self.make()
        seen = {}

        def history(token, channel, oldest, limit=200):
            seen[channel] = oldest
            return {"C1": [msg(ts_at(-10))], "C2": []}[channel]

        self.slack.history = history
        self.assertEqual(c.backfill(), 1)
        self.assertEqual(self.store.get_cursor("C1"), ts_at(-10))
        self.assertIsNone(self.store.get_cursor("C2"))
        c.backfill()
        self.assertAlmostEqual(float(seen["C1"]), float(ts_at(-10)) - 300, delta=1)
        self.assertAlmostEqual(float(seen["C2"]), NOW - 3600, delta=1)

    def test_backfill_inserts_into_the_channel_it_read(self):
        c = self.make()
        self.slack.history = lambda token, channel, oldest, limit=200: (
            [msg(ts_at(-10))] if channel == "C2" else [])
        c.backfill()
        self.assertEqual(self.store.read("SELECT channel FROM messages"), [("C2",)])

    def test_backfill_failure_in_one_channel_does_not_block_others(self):
        c = self.make()

        def history(token, channel, oldest, limit=200):
            if channel == "C1":
                raise SlackError("boom")
            return [msg(ts_at(-10))]

        self.slack.history = history
        with self.assertRaises(SlackError):
            c.backfill()
        self.assertEqual(self.store.read("SELECT channel FROM messages"), [("C2",)])

    def test_replies_reactions_go_to_the_alerts_channel(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed_in(c, "C2", ts)
        self.handle_and_publish(c)
        self.assertEqual(self.slack.posts[0][0], "C2")


class ReactionInboxTests(Base):
    def event(self, **kw):
        base = {"type": "reaction_added", "user": "U9", "reaction": "x",
                "item": {"type": "message", "channel": "C1", "ts": "5.0"}, "event_ts": "123.5"}
        base.update(kw)
        return base

    def rows(self):
        return self.store.read("SELECT channel, ts, user, name, epoch FROM reactions_inbox")

    def test_socket_reaction_is_stored(self):
        c = self.make()
        c.on_socket_event("events_api", {"event": self.event()})
        self.assertEqual(self.rows(), [("C1", "5.0", "U9", "x", 123.5)])

    def test_redelivery_is_deduplicated(self):
        c = self.make()
        c.on_reaction(self.event())
        c.on_reaction(self.event())
        self.assertEqual(len(self.rows()), 1)

    def test_bot_own_other_channel_and_non_message_are_ignored(self):
        c = self.make()
        c.on_reaction(self.event(user=BOT_USER))
        c.on_reaction(self.event(item={"type": "message", "channel": "CZ", "ts": "5.0"}))
        c.on_reaction(self.event(item={"type": "file", "channel": "C1", "ts": "5.0"}))
        self.assertEqual(self.rows(), [])

    def test_missing_event_ts_falls_back_to_clock(self):
        c = self.make()
        c.on_reaction(self.event(event_ts=None))
        self.assertEqual(self.rows()[0][4], NOW)


class RunForeverTests(Base):
    def test_second_instance_exits(self):
        holder = self.make()
        rival = self.make()
        ticks = []

        def stop():
            return len(ticks) >= 1

        def sleep_and_try_rival(_):
            ticks.append(1)
            with self.assertRaises(SystemExit) as ctx:
                rival.run_forever(stop=lambda: True)
            self.assertEqual(ctx.exception.code, 1)

        holder.run_forever(stop=stop, sleep=sleep_and_try_rival)
        self.assertEqual(len(ticks), 1)

    def test_loop_processes_beats_and_starts_socket(self):
        started = []
        c = self.make(app_token="xapp", socket_run=lambda *a, **k: started.append(a[0]))
        self.slack.history_result = [msg(ts_at(-10))]
        ticks = []

        def sleep(_):
            ticks.append(1)
            self.now += 5

        c.run_forever(stop=lambda: len(ticks) >= 6, sleep=sleep)
        self.assertEqual(len(self.slack.posts), 1, "first reply goes out once the wave settled")
        self.assertEqual(self.store.last_beat("collector"), NOW)
        self.assertEqual(len(self.slack.history_calls), 1)


if __name__ == "__main__":
    unittest.main()
