"""Task C wiring in the collector: magnitude signal, auto rules, candidates, attachments, feedback."""
import dataclasses
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from alert_doctor import autorules, known, known_store, mentions, schema, tuner
from alert_doctor.collector import Collector
from alert_doctor.config import ChannelSpec, Config, SystemSpec
from alert_doctor.correlate import Candidate
from alert_doctor.models import CheckSpec, ElkSpec, Evidence
from alert_doctor.parse import parse_message
from alert_doctor.rules import Rule
from alert_doctor.signals import Signal
from alert_doctor.slack_io import SlackError
from alert_doctor.store import Store

NOW = 1_760_000_000.0
CHANNELS = ("C1", "C2", "C3", "C4")


def alert_text(message="連線逾時", code="ORS1", title="[L3] 訂單檢查", task_id="t1"):
    return f"{title}\n{{'code': '{code}', 'task_id': '{task_id}', 'result': {{'level': 3, 'message': '{message}'}}}}"


def ts_at(offset, n=0):
    return f"{NOW + offset:.0f}.{n:06d}"


LOUD = Signal(ok=True, errors=500, total=None, rate=None, duration_minutes=30, hosts=3)
QUIET = Signal(ok=True, errors=1, total=None, rate=None, duration_minutes=1, hosts=1)
FAILED = Signal(ok=False, errors=None, total=None, rate=None, duration_minutes=0, hosts=0, error="timeout")


class FakeSlack:
    def __init__(self):
        self.posts, self.reactions, self.downloads = [], [], []
        self.users = {}
        self.post_errors = []

    def auth_test(self, token):
        return {"user_id": "UBOT", "bot_id": "BBOT"}

    def post_message(self, token, channel, text, thread_ts=None):
        if self.post_errors:
            raise self.post_errors.pop(0)
        self.posts.append((channel, text, thread_ts))
        return f"{NOW + 5000 + len(self.posts):.0f}.000001"

    def add_reaction(self, token, channel, ts, name):
        self.reactions.append((channel, ts, name))

    def remove_reaction(self, token, channel, ts, name):
        pass

    def history(self, token, channel, oldest, limit=200):
        return []

    def lookup_user_by_email(self, token, email):
        return self.users.get(email)

    def download_file(self, token, url, max_bytes=2_000_000):
        self.downloads.append(url)
        return b"Traceback\nValueError: boom\n"


class FakeElk:
    def __init__(self):
        self.calls = []

    def gather(self, spec, until, variables):
        self.calls.append(until)
        return Evidence(False, "a", "b", error="no elk in tests")


class Base(unittest.TestCase):
    def setUp(self):
        mentions.clear_cache()
        self.addCleanup(mentions.clear_cache)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(
            workspace_url="https://w.slack.com",
            channels=tuple(ChannelSpec(c, f"alerts-{c}", ("sys",)) for c in CHANNELS),
            systems={"sys": SystemSpec("sys", (), ("USYS",), "sys", {}),
                     "other": SystemSpec("other", (), (), "other", {}),
                     "tbd": SystemSpec("tbd", (), (), "", {})},
            db_path=os.path.join(self.tmp.name, "t.db"), runs_dir=os.path.join(self.tmp.name, "runs"),
            archive_db_path=os.path.join(self.tmp.name, "archive.db"),
            watchdog_snapshot_path=os.path.join(self.tmp.name, "none.json"),
            shadow_sample_rate=0.1)
        self.store = Store(":memory:")
        schema.ensure_all(self.store)
        self.slack = FakeSlack()
        self.checks = {"ORS1": CheckSpec(key="ORS1", elk=ElkSpec(index="i", query={}))}
        self.rules = []
        self.signal = QUIET
        self.rng_value = 0.99
        self.candidate_calls = []
        self.candidate_error = None
        self.signal_calls = []
        self.elk = FakeElk()
        self.now = NOW

    def co_erroring(self, elk, systems, until, exclude=""):
        self.candidate_calls.append((sorted(systems), exclude))
        if self.candidate_error:
            raise self.candidate_error
        return [Candidate("other", 50, 1, 25.5)]

    def signal_fn(self, elk, check, until, **kw):
        self.signal_calls.append((until, kw))
        return self.signal

    def make(self, **kw):
        return Collector(self.cfg, self.store, self.slack, self.elk, self.rules, self.checks, "xoxb",
                         clock=lambda: self.now, bot_user_id="UBOT", bot_id="BBOT",
                         signal_fn=self.signal_fn,
                         co_erroring=self.co_erroring, rng=lambda: self.rng_value, **kw)

    def publish(self, c, after=25, rounds=5):
        for i in range(rounds):
            c.publisher.process(self.now + after + i)

    def feed(self, c, ts, text=None, channel="C1", **extra):
        c.on_socket_event("events_api", {"event": {
            "type": "message", "ts": ts, "channel": channel, "text": text or alert_text(), **extra}})

    def fp(self, text=None, channel="C1"):
        return Collector._fingerprint(parse_message(channel, "1.0", text or alert_text()), "sys")

    def active_rule(self, fp=None, kind="noise"):
        rule = autorules.propose_from_human(self.store, fp or self.fp(), NOW - 10 * 86400, "U1")
        with self.store.tx() as db:
            db.execute("UPDATE auto_rules SET state='active', kind=?, expires=? WHERE id=?",
                       (kind, NOW + 86400, rule.id))
        return rule.id

    def rule_state(self, rule_id):
        return self.store.read("SELECT state FROM auto_rules WHERE id=?", (rule_id,))[0][0]

    def row(self, ts, channel="C1"):
        return self.store.read(
            "SELECT category, incident_id FROM messages WHERE channel=? AND ts=?", (channel, ts))[0]

    def incident(self, ts, channel="C1"):
        return self.store.get_incident(self.row(ts, channel)[1])

    def reactions_on(self, ts):
        return [r[2] for r in self.slack.reactions if r[1] == ts]


class AutoRuleTests(Base):
    def test_active_noise_rule_silences_but_still_replies(self):
        self.active_rule()
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "noise")
        self.assertEqual(self.incident(ts).analysis_state, "none")
        self.assertEqual(len(self.slack.posts), 1)
        self.assertIn("自動規則", self.slack.posts[0][1])

    def test_rule_learned_on_a_v1_fingerprint_no_longer_matches(self):
        import hashlib
        from alert_doctor.fingerprint import template
        a = parse_message("C1", "1.0", alert_text())
        v1_fine = hashlib.sha1("|".join((a.check_code, str(a.level), template(a.result_message)))
                               .encode()).hexdigest()
        v1 = hashlib.sha1(f"{v1_fine}|sys".encode()).hexdigest()
        self.assertNotEqual(v1, self.fp())
        self.active_rule(fp=v1)
        tuner.record_observation(self.store, v1, NOW - 86400, 3)
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertEqual(self.row(ts)[0], "new")

    def test_accumulated_is_never_silenced_and_invalidates_rule(self):
        rid = self.active_rule()
        self.signal = LOUD
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "accumulated")
        self.assertEqual(self.rule_state(rid), "revoked")
        incident = self.incident(ts)
        self.assertEqual(incident.analysis_state, "pending")
        evidence = self.store.load_evidence(incident.id)
        self.assertEqual(evidence["signal"]["errors"], 500)
        self.assertEqual(evidence["candidates"][0]["system"], "other")
        self.assertEqual(self.candidate_calls, [(["other", "sys"], "sys")])
        self.assertIn("chart_with_upwards_trend", self.reactions_on(ts))
        self.assertIn("large_orange_circle", self.reactions_on(ts))

    def test_never_silence_check_is_never_silenced_and_invalidates_rule(self):
        rid = self.active_rule()
        self.checks["ORS1"] = CheckSpec(key="ORS1", never_silence=True, owners=("a@b.c",),
                                        elk=ElkSpec(index="i", query={}))
        self.slack.users["a@b.c"] = "UOWNER"
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "critical")
        self.assertEqual(self.rule_state(rid), "revoked")
        self.assertIn("<@UOWNER>", self.slack.posts[0][1])
        self.assertNotIn("<@USYS>", self.slack.posts[0][1])
        self.assertIn("red_circle", self.reactions_on(ts))

    def test_critical_falls_back_to_system_owners(self):
        self.rules = [Rule(id="ns", action="never_silence", match_title="訂單")]
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertIn("<@USYS>", self.slack.posts[0][1])

    def test_never_silence_title_rule_is_never_silenced(self):
        self.active_rule()
        self.rules = [Rule(id="ns", action="never_silence", match_title="訂單")]
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertEqual(self.row(ts)[0], "critical")

    def test_blocked_fingerprint_is_never_silenced(self):
        rid = self.active_rule()
        with self.store.tx() as db:
            db.execute("INSERT INTO fp_blocks (fingerprint, until, reason) VALUES (?,?,?)",
                       (self.fp(), NOW + 86400, "human ❌"))
        self.assertEqual(self.rule_state(rid), "active")
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertEqual(self.row(ts)[0], "new")

    def test_sampled_alert_is_analyzed_and_indexed_as_sample(self):
        rid = self.active_rule()
        self.rng_value = 0.0
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "new")
        incident = self.incident(ts)
        self.assertEqual(incident.analysis_state, "pending")
        reply_ts = self.store.read("SELECT reply_ts FROM messages WHERE ts=?", (ts,))[0][0]
        self.assertEqual(self.store.lookup_reply("C1", reply_ts)[2], "sample")
        self.assertEqual(autorules.sample_rule(self.store, incident.id), rid)
        self.assertIn("抽樣", self.slack.posts[0][1])

    def test_elk_failure_never_yields_auto_noise(self):
        self.active_rule()
        self.signal = FAILED
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertNotEqual(self.row(ts)[0], "noise")
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    def test_shadow_rule_counts_hit_without_silencing(self):
        rule = autorules.propose_from_human(self.store, self.fp(), NOW - 60, "U1")
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertEqual(self.row(ts)[0], "new")
        self.assertEqual(self.store.read("SELECT shadow_hits FROM auto_rules WHERE id=?", (rule.id,)), [(1,)])

    def test_active_known_rule_links_previous_analysis(self):
        fp = self.fp()
        old = parse_message("C2", ts_at(-90000), alert_text())
        self.store.insert_message(old, NOW)
        prev = self.store.create_incident(old, fp, "g", source_system="sys")
        self.store.request_analysis(prev.id, now=NOW - 90000)
        self.store.claim_incident("w", NOW - 90000)
        self.store.complete_analysis(prev.id, {"category": "infra"}, "m", NOW - 90000)
        self.active_rule(fp, kind="known")
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "known")
        self.assertIn(self.cfg.permalink("C2", old.ts), self.slack.posts[0][1])


KNOWN_TOML = """
[[known]]
id = "ddsc-afternoon"
title = "廠商甲主機重啟"
description = "測試用維護窗"
action = "{action}"
windows = [{{ start = "16:50", end = "17:00", label = "62 號主機重啟" }}]

[known.match]
systems = ["sys"]
check_codes = ["ORS1"]
any_regex = ["P999", "連線逾時"]
"""
EXAMPLE_KNOWN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "known.example.toml")
COUPON_P999 = ("['Pxy', 'PE']服務中出現異常關鍵字「['P999']」,請立即查看系統狀況!"
               "「[取得折抵金優惠券]失敗 ino='F1' 原因: 經管錯誤 經管回傳 code: P999, error message: None」")


class KnownWindowTests(Base):
    """NOW is 2025-10-09 16:53:20 Taipei, inside the 16:50–17:00 test window."""

    def write_known(self, action="known"):
        path = os.path.join(self.tmp.name, "known.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(KNOWN_TOML.format(action=action))
        self.cfg = dataclasses.replace(self.cfg, known_path=path)
        return path

    def handle(self, c, ts, text=None):
        self.feed(c, ts, text)
        c.process_pending()

    def test_known_window_replies_without_analysis_but_still_counts(self):
        self.write_known()
        c = self.make()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "known")
        self.assertEqual(self.incident(ts).analysis_state, "none")
        self.assertIn("固定維護窗", self.slack.posts[0][1])
        self.assertIn("16:50 62 號主機重啟", self.slack.posts[0][1])
        self.assertEqual(self.elk.calls, [])
        self.assertEqual(self.candidate_calls, [])
        self.assertEqual(self.store.read("SELECT alerts FROM fp_hourly"), [(1,)])

    def test_never_silence_check_wins_over_known_window(self):
        self.write_known()
        self.checks = {"ORS1": CheckSpec(key="ORS1", never_silence=True, elk=ElkSpec(index="i", query={}))}
        c = self.make()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.assertEqual(self.row(ts)[0], "critical")
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    def test_accumulated_magnitude_beats_known_window(self):
        self.write_known()
        self.signal = LOUD
        c = self.make()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "accumulated")
        self.assertEqual(self.incident(ts).analysis_state, "pending")
        self.assertIn("量級異常", self.slack.posts[0][1])
        self.assertIn("廠商甲主機重啟", self.slack.posts[0][1])
        self.assertTrue(self.elk.calls)

    def test_outside_window_is_analysed(self):
        self.write_known()
        self.now = NOW + 3600
        c = self.make()
        ts = ts_at(3590)
        self.handle(c, ts)
        self.assertEqual(self.row(ts)[0], "new")
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    def test_context_entry_does_not_change_classification(self):
        self.write_known(action="context")
        c = self.make()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.assertEqual(self.row(ts)[0], "new")

    def test_known_window_skips_auto_rules(self):
        self.write_known()
        rule = autorules.propose_from_human(self.store, self.fp(), NOW - 60, "U1")
        c = self.make()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.assertEqual(self.row(ts)[0], "known")
        self.assertEqual(self.store.read("SELECT shadow_hits FROM auto_rules WHERE id=?", (rule.id,)), [(0,)])

    def test_edits_apply_without_restart(self):
        c = self.make(known=known.KnownSource(os.path.join(self.tmp.name, "later.toml")))
        first = ts_at(-20)
        self.handle(c, first)
        self.assertEqual(self.row(first)[0], "new")
        with open(os.path.join(self.tmp.name, "later.toml"), "w", encoding="utf-8") as f:
            f.write(KNOWN_TOML.format(action="known"))
        later = ts_at(-5)
        self.handle(c, later, alert_text(message="P999 again"))
        self.assertEqual(self.row(later)[0], "known")

    def test_1021_coupon_p999_is_analysed_with_host_62_context(self):
        epoch = 1792523100.0
        self.now = epoch + 5
        c = self.make(known=known.load_known(EXAMPLE_KNOWN))
        ts = f"{epoch:.0f}.548429"
        self.handle(c, ts, alert_text(message=COUPON_P999, code="MDl"))
        self.publish(c)
        self.assertNotEqual(self.row(ts)[0], "known")
        self.assertEqual(self.incident(ts).analysis_state, "pending")
        self.assertNotIn("固定維護窗", self.slack.posts[0][1])


class KnownLinkTests(Base):
    """The error-identity cache: a linked error is answered from its entry, never analysed."""

    def setUp(self):
        super().setUp()
        self.cfg = dataclasses.replace(self.cfg, known_path=os.path.join(self.tmp.name, "none.toml"),
                                       known_editors=("U1",))

    def handle(self, c, ts, text=None):
        self.feed(c, ts, text)
        c.process_pending()

    def mention(self, c, text, thread_ts=None, ts="1760000100.000001", user="U1", channel="C1"):
        event = {"type": "app_mention", "channel": channel, "user": user, "text": text, "ts": ts}
        if thread_ts:
            event["thread_ts"] = thread_ts
        c.on_socket_event("events_api", {"event": event})

    def feedback_posts(self):
        return [(json.loads(p)["text"], t) for p, t in self.store.read(
            "SELECT payload, thread_ts FROM outbox WHERE kind='feedback' ORDER BY id")]

    def test_mention_links_thread_alert_and_later_alerts_hit_the_cache(self):
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.assertEqual(self.row(first)[0], "new")
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first)
        [(text, thread)] = self.feedback_posts()
        self.assertTrue(text.startswith("已將此錯誤樣式連結到【訂單逾時】,之後相同錯誤直接回覆不再分析"))
        self.assertEqual(thread, first)
        self.now = NOW + 7200
        later = ts_at(7190)
        self.handle(c, later, alert_text(task_id="t2"))
        self.publish(c)
        self.assertEqual(self.row(later)[0], "known")
        self.assertEqual(self.incident(later).analysis_state, "none")
        self.assertTrue(any("固定錯誤*:訂單逾時" in p[1] for p in self.slack.posts))

    def test_unlink_restores_analysis(self):
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first)
        self.mention(c, "<@UBOT> 取消固定", thread_ts=first, ts="1760000100.000002")
        self.assertIn("已取消", self.feedback_posts()[-1][0])
        self.now = NOW + 7200
        later = ts_at(7190)
        self.handle(c, later, alert_text(task_id="t2"))
        self.assertEqual(self.row(later)[0], "new")

    def test_never_silence_beats_linked_error(self):
        self.checks = {"ORS1": CheckSpec(key="ORS1", never_silence=True, elk=ElkSpec(index="i", query={}))}
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first)
        self.now = NOW + 7200
        later = ts_at(7190)
        self.handle(c, later, alert_text(task_id="t2"))
        self.assertEqual(self.row(later)[0], "critical")

    def test_link_wins_over_window(self):
        path = os.path.join(self.tmp.name, "known.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(KNOWN_TOML.format(action="known"))
        c = self.make(known=known.KnownSource(path))
        known_store.add_entry(self.store, "x", "連結的固定錯誤", now=NOW)
        alert = parse_message("C1", "1.0", alert_text())
        known_store.link(self.store, known_store.alert_error_key(alert, source_system="sys"), "x",
                         now=NOW)
        ts = ts_at(-10)
        self.handle(c, ts)
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "known")
        self.assertIn("連結的固定錯誤", self.slack.posts[0][1])

    def test_non_editor_cannot_link(self):
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first, user="U9")
        self.assertIn("known_editors", self.feedback_posts()[0][0])
        self.assertEqual(known_store.list_entries(self.store), [])

    def test_hits_are_counted_and_expired_links_resume_analysis(self):
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時 1天", thread_ts=first)
        later = ts_at(-60)
        self.handle(c, later, alert_text(task_id="t2"))
        self.assertEqual(self.row(later)[0], "known")
        [link] = known_store.links_of(self.store, "訂單逾時")
        self.assertEqual((link["hit_count"], link["last_hit_at"]), (1, float(later)))
        self.now = NOW + 2 * 86400
        expired = ts_at(2 * 86400 - 10)
        self.handle(c, expired, alert_text(task_id="t3"))
        self.assertEqual(self.row(expired)[0], "new")
        self.assertEqual(known_store.links_of(self.store, "訂單逾時")[0]["hit_count"], 1)

    def test_linked_error_from_another_system_is_not_a_hit(self):
        self.cfg = dataclasses.replace(self.cfg, channels=(
            *self.cfg.channels[:1], dataclasses.replace(self.cfg.channels[1], systems=("other",)),
            *self.cfg.channels[2:]))
        c = self.make()
        first = ts_at(-3000)
        self.handle(c, first)
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first)
        other = ts_at(-60)
        self.feed(c, other, alert_text(task_id="t2"), channel="C2")
        c.process_pending()
        self.assertEqual(self.row(other, "C2")[0], "new")

    def test_truncated_alert_cannot_be_linked_and_says_so(self):
        c = self.make()
        first = ts_at(-3000)
        cut = "[L3] 訂單檢查\n{'code': 'ORS1', 'task_id': 't1', 'result': {'level': 3, 'message': '連線逾時 xxx"
        self.handle(c, first, cut)
        self.publish(c)
        self.assertIn("原文超過 Slack 長度上限被截斷,尾段不可得", self.slack.posts[0][1])
        self.mention(c, "<@UBOT> 固定錯誤 訂單逾時", thread_ts=first)
        self.assertIn("無法固定", self.feedback_posts()[0][0])

    def test_search_mention_replies_in_place(self):
        c = self.make()
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        self.mention(c, "<@UBOT> 查 廠商甲")
        [(text, thread)] = self.feedback_posts()
        self.assertIn("`ddsc`", text)
        self.assertEqual(thread, "1760000100.000001")

    def test_link_outside_alert_thread_explains(self):
        c = self.make()
        self.mention(c, "<@UBOT> 固定錯誤 x")
        self.assertEqual(self.feedback_posts()[0][0], known_store.NEED_THREAD)

    def test_ignored_mentions(self):
        c = self.make()
        self.mention(c, "<@UBOT> 查 x", channel="COTHER")
        self.mention(c, "<@UBOT> 查 x", user="UBOT")
        self.mention(c, "<@UBOT> 你好")
        self.assertEqual(self.feedback_posts(), [])

    def test_redelivered_mention_replies_once(self):
        c = self.make()
        self.mention(c, "<@UBOT> 查 x")
        self.mention(c, "<@UBOT> 查 x")
        self.assertEqual(len(self.feedback_posts()), 1)

    def test_reply_is_delivered_by_publisher(self):
        c = self.make()
        self.mention(c, "<@UBOT> 查 x")
        self.publish(c, after=1)
        self.assertEqual(self.slack.posts[-1][2], "1760000100.000001")
        self.assertIn("找不到", self.slack.posts[-1][1])


class SignalAndObservationTests(Base):
    def test_observation_recorded_with_signal_errors(self):
        self.signal = Signal(ok=True, errors=3, total=None, rate=None, duration_minutes=1, hosts=1)
        c = self.make()
        self.feed(c, ts_at(-10))
        c.process_pending()
        self.assertEqual(self.store.read("SELECT alerts, errors FROM fp_hourly"), [(1, 3)])

    def test_signal_cached_per_fingerprint_minute(self):
        calls = []
        c = self.make()
        c._signal_fn = lambda elk, check, until, **kw: calls.append(until) or QUIET
        self.feed(c, ts_at(-10, 1))
        self.feed(c, ts_at(-10, 2))
        c.process_pending()
        self.assertEqual(len(calls), 1)

    def test_no_signal_without_elk_check(self):
        self.checks = {}
        calls = []
        c = self.make()
        c._signal_fn = lambda *a, **kw: calls.append(a) or QUIET
        self.feed(c, ts_at(-10))
        c.process_pending()
        self.assertEqual(calls, [])
        self.assertEqual(self.store.read("SELECT errors FROM fp_hourly"), [(None,)])

    def test_new_incident_gets_candidates_without_unknown_projects(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.assertEqual(self.candidate_calls, [(["other", "sys"], "sys")])
        self.assertIn("candidates", self.store.load_evidence(self.incident(ts).id))

    def test_candidate_failure_does_not_block_reply(self):
        c = self.make()

        def boom(*a, **k):
            raise OSError("elk down")
        c._co_erroring = boom
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "new")
        self.assertEqual(len(self.slack.posts), 1)


class AttachmentTests(Base):
    def test_files_downloaded_into_run_dir_and_summarised(self):
        c = self.make()
        ts = ts_at(-10)
        files = [{"name": "../trace.log", "url_private": "https://files/1", "size": 30, "mimetype": "text/plain"}]
        self.feed(c, ts, subtype="file_share", files=files)
        c.process_pending()
        incident = self.incident(ts)
        path = os.path.join(self.cfg.runs_dir, str(incident.id), "attachments", "trace.log")
        self.assertTrue(os.path.exists(path))
        summary = self.store.load_evidence(incident.id)["attachments"][0]
        self.assertEqual(summary["path"], "attachments/trace.log")
        self.assertIn("ValueError", summary["head"])

    def test_oversize_file_only_noted(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts, files=[{"name": "huge.log", "url_private": "u", "size": 5_000_000}])
        c.process_pending()
        self.assertEqual(self.slack.downloads, [])
        summary = self.store.load_evidence(self.incident(ts).id)["attachments"][0]
        self.assertFalse(summary["saved"])


class EveryOccurrenceRepliedTests(Base):
    def test_four_channels_shared_task_and_auto_rule_all_replied(self):
        self.checks["N1"] = CheckSpec(key="N1", elk=ElkSpec(index="i", query={}))
        self.active_rule(self.fp(alert_text("雜訊", code="N1", task_id="n1")))
        c = self.make()
        sent = [
            ("C1", ts_at(-50), alert_text("逾時", task_id="shared")),
            ("C2", ts_at(-40), alert_text("逾時", task_id="shared")),
            ("C3", ts_at(-30), alert_text("雜訊", code="N1", task_id="n1")),
            ("C4", ts_at(-20), "不是告警格式"),
            ("C1", ts_at(-10), alert_text("別的錯", code="X9", task_id="x")),
        ]
        for channel, ts, text in sent:
            self.feed(c, ts, text, channel=channel)
        c.process_pending()
        self.publish(c)
        replied = {(ch, thread) for ch, _, thread in self.slack.posts}
        self.assertEqual(replied, {(ch, ts) for ch, ts, _ in sent})
        self.assertEqual(self.incident(ts_at(-50)).id, self.incident(ts_at(-40), "C2").id)
        self.assertEqual(self.row(ts_at(-30), "C3")[0], "noise")


class FeedbackLoopTests(Base):
    def test_process_feedback_handles_inbox(self):
        c = self.make()
        ts = ts_at(-10)
        self.feed(c, ts)
        c.process_pending()
        c.on_reaction({"type": "reaction_added", "user": "U9", "reaction": "mute",
                       "item": {"type": "message", "channel": "C1", "ts": ts}, "event_ts": str(NOW)})
        self.assertEqual(c.process_feedback(), 1)
        self.assertEqual(self.store.read("SELECT state, source FROM auto_rules"), [("shadow", "human")])


class ReviewFixTests(Base):
    """Fixes from the v2 review: evidence before silencing, cost control, consistency."""

    def handle(self, c, ts, text=None, channel="C1"):
        self.feed(c, ts, text, channel=channel)
        c.process_pending()

    def test_sustained_spike_reanalyses_at_most_once_per_half_hour(self):
        self.signal = LOUD
        c = self.make()
        self.handle(c, ts_at(-900))
        incident_id = self.store.read("SELECT id FROM incidents")[0][0]
        self.store.complete_analysis(incident_id, {"category": "infra"}, "sonnet", NOW)
        self.now = NOW + 60
        for i in range(10):
            self.handle(c, ts_at(-800 + i))
        self.assertEqual(self.store.read("SELECT analysis_state FROM incidents WHERE id=?", (incident_id,)),
                         [("done",)])
        self.now = NOW + 1801
        self.handle(c, ts_at(-5))
        self.assertEqual(self.store.read("SELECT analysis_state FROM incidents WHERE id=?", (incident_id,)),
                         [("pending",)])

    def test_datasource_alert_skips_elk_analysis_and_baseline(self):
        self.rules = [Rule(id="elk", action="datasource", match_message="ES連線出現異常")]
        c = self.make()
        for i in range(5):
            self.handle(c, ts_at(-100 + i), alert_text(message="ES連線出現異常:[10.0.0.100] Connection timed out"))
        self.assertEqual(len(self.store.read("SELECT 1 FROM messages WHERE status='handled'")), 5)
        self.assertEqual((self.signal_calls, self.elk.calls, self.candidate_calls), ([], [], []))
        self.assertEqual(self.store.read("SELECT 1 FROM incidents WHERE analysis_state!='none'"), [])
        self.assertEqual(self.store.read("SELECT 1 FROM fp_hourly"), [])
        self.assertTrue(all("ELK 查詢失敗" in text for _, text, _ in self.slack.posts))

    def test_never_silence_datasource_alert_is_critical_and_says_elk_failed(self):
        self.rules = [Rule(id="elk", action="datasource", match_message="ES連線出現異常")]
        self.checks = {"ORS1": CheckSpec(key="ORS1", never_silence=True, elk=ElkSpec(index="i", query={}))}
        c = self.make()
        ts = ts_at(-100)
        self.handle(c, ts, alert_text(message="ES連線出現異常:[10.0.0.100] Connection timed out"))
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "critical")
        self.assertEqual(self.incident(ts).analysis_state, "pending")
        self.assertIn("重要告警", self.slack.posts[0][1])
        self.assertIn("ELK 查詢失敗", self.slack.posts[0][1])

    # fix 1
    def test_auto_rule_without_elk_check_does_not_silence(self):
        self.checks = {}
        self.active_rule()
        ts = ts_at(-10)
        self.handle(self.make(), ts)
        self.assertEqual(self.row(ts)[0], "new")
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    def test_auto_known_rule_does_not_silence_on_failed_signal(self):
        self.active_rule(kind="known")
        self.signal = FAILED
        ts = ts_at(-10)
        self.handle(self.make(), ts)
        self.assertEqual(self.row(ts)[0], "new")

    def test_auto_rule_does_not_silence_during_spike(self):
        self.active_rule()
        ts = ts_at(-10)
        with mock.patch.object(Collector, "_spike", return_value=True):
            self.handle(self.make(), ts)
        self.assertEqual(self.row(ts)[0], "spike")
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    # fix 2
    def spy_requests(self, accepts_fresh=True):
        calls = []
        self.priorities = []
        original = self.store.request_analysis

        def with_fresh(incident_id, *, min_interval=0, now=None, fresh=False, priority=2):
            calls.append(fresh)
            self.priorities.append(priority)
            original(incident_id, min_interval=min_interval, now=now)

        def without_fresh(incident_id, *, min_interval=0, now=None):
            calls.append(None)
            original(incident_id, min_interval=min_interval, now=now)
        self.store.request_analysis = with_fresh if accepts_fresh else without_fresh
        return calls

    def test_accumulated_requests_fresh_analysis(self):
        calls = self.spy_requests()
        self.signal = LOUD
        self.handle(self.make(), ts_at(-10))
        self.assertEqual(calls, [True])

    def test_spike_requests_fresh_analysis(self):
        calls = self.spy_requests()
        with mock.patch.object(Collector, "_spike", return_value=True):
            self.handle(self.make(), ts_at(-10))
        self.assertEqual(calls, [True])

    def test_new_requests_normal_analysis(self):
        calls = self.spy_requests()
        self.handle(self.make(), ts_at(-10))
        self.assertEqual(calls, [False])

    def test_fresh_falls_back_when_store_lacks_it(self):
        calls = self.spy_requests(accepts_fresh=False)
        self.signal = LOUD
        ts = ts_at(-10)
        self.handle(self.make(), ts)
        self.assertEqual(calls, [None])
        self.assertEqual(self.incident(ts).analysis_state, "pending")

    # fix 4
    def test_signal_receives_vkwargs(self):
        text = ("[L3] 訂單檢查\n{'code': 'ORS1', 'task_id': 't1', 'vkwargs': {'order': 'A1'},"
                " 'result': {'level': 3, 'message': 'x'}}")
        self.handle(self.make(), ts_at(-10), text)
        self.assertEqual(self.signal_calls[0][1], {"variables": {"order": "A1"}})

    # fix 5
    def test_task_linked_alert_feeds_incident_series(self):
        self.signal = Signal(ok=True, errors=3, total=None, rate=None, duration_minutes=1, hosts=1)
        c = self.make()
        first = alert_text("連線逾時", task_id="shared")
        second = alert_text("查無資料", task_id="shared")
        self.assertNotEqual(self.fp(first), self.fp(second, "C2"))
        with mock.patch("alert_doctor.collector.tuner.baseline_for", return_value=None) as spy:
            self.handle(c, ts_at(-20), first)
            self.handle(c, ts_at(-10), second, channel="C2")
        incident = self.incident(ts_at(-20))
        self.assertEqual(self.incident(ts_at(-10), "C2").id, incident.id)
        self.assertEqual({call.args[1] for call in spy.call_args_list}, {incident.fingerprint})
        self.assertEqual(self.store.read("SELECT fingerprint, alerts FROM fp_hourly"),
                         [(incident.fingerprint, 2)])

    def test_task_linked_alert_matches_incident_auto_rule(self):
        first = alert_text("連線逾時", task_id="shared")
        second = alert_text("查無資料", task_id="shared")
        c = self.make()
        self.handle(c, ts_at(-20), first)
        self.active_rule(self.fp(first))
        self.handle(c, ts_at(-10), second, channel="C2")
        self.assertEqual(self.row(ts_at(-10), "C2")[0], "noise")

    # fix 6
    def done_incident(self, verdict):
        c = self.make()
        anchor = ts_at(-600)
        self.handle(c, anchor)
        incident = self.incident(anchor)
        self.store.claim_incident("w", NOW)
        self.store.complete_analysis(incident.id, verdict, "m", NOW - 300)
        return c, incident

    def healthy_hours(self, fp):
        return self.store.read(
            "SELECT hour_epoch, healthy FROM fp_hourly WHERE fingerprint=? ORDER BY hour_epoch", (fp,))

    def test_alert_on_real_problem_incident_marks_hours_unhealthy(self):
        for verdict in ({"category": "infra"}, {"category": "noise", "needs_human": True}):
            with self.subTest(verdict=verdict):
                self.setUp()
                c, incident = self.done_incident(verdict)
                self.handle(c, ts_at(-10))
                hours = self.healthy_hours(incident.fingerprint)
                self.assertTrue(hours)
                self.assertTrue(all(h == 0 for _, h in hours))
                self.assertIn(tuner._hour(NOW - 10 - 3600), [e for e, _ in hours])

    def test_alert_on_noise_incident_stays_healthy(self):
        c, incident = self.done_incident({"category": "noise"})
        self.handle(c, ts_at(-10))
        self.assertTrue(all(h == 1 for _, h in self.healthy_hours(incident.fingerprint)))

    # fix 7
    def test_burst_of_accumulated_alerts_does_constant_elk_work(self):
        self.signal = LOUD
        c = self.make()
        for i in range(30):
            self.feed(c, ts_at(-300 + i * 10))
        c.process_pending()
        self.assertEqual(len(self.store.read("SELECT 1 FROM messages WHERE status='handled'")), 30)
        self.assertEqual(len(self.elk.calls), 1)
        self.assertEqual(len(self.candidate_calls), 1)
        self.assertLessEqual(len(self.signal_calls), 6)

    def test_gather_runs_again_after_ten_minutes(self):
        self.signal = LOUD
        c = self.make()
        self.handle(c, ts_at(-700))
        self.handle(c, ts_at(-690))
        self.assertEqual(len(self.elk.calls), 1)
        self.now = NOW + 600
        self.handle(c, ts_at(-5))
        self.assertEqual(len(self.elk.calls), 2)

    def test_transient_noise_rule_requeries_evidence_older_than_two_minutes(self):
        self.rules = [Rule(id="tmo", action="noise", match_message="逾時", require_transient=True)]
        c = self.make()
        self.handle(c, ts_at(-200))
        self.now = NOW + 60
        self.handle(c, ts_at(-150))
        self.assertEqual(len(self.elk.calls), 1)
        self.now = NOW + 121
        self.handle(c, ts_at(-100))
        self.assertEqual(len(self.elk.calls), 2)

    def test_failed_signal_negative_cache(self):
        self.signal = FAILED
        c = self.make()
        self.handle(c, ts_at(-200))
        self.handle(c, ts_at(-100))
        self.assertEqual(len(self.signal_calls), 1)
        self.now = NOW + 61
        self.handle(c, ts_at(-5))
        self.assertEqual(len(self.signal_calls), 2)

    def test_circuit_breaker_stops_elk_after_five_failures(self):
        self.signal = FAILED
        self.candidate_error = OSError("elk down")
        for i in range(8):
            self.checks[f"K{i}"] = CheckSpec(key=f"K{i}", elk=ElkSpec(index="i", query={}))
        c = self.make()

        def elk_calls():
            return len(self.signal_calls) + len(self.elk.calls) + len(self.candidate_calls)
        for i in range(6):
            self.handle(c, ts_at(-100 + i), alert_text(f"錯誤{i}", code=f"K{i}", task_id=f"k{i}"))
        self.assertEqual(elk_calls(), 5)
        self.assertEqual(len(self.store.read("SELECT 1 FROM messages WHERE status='handled'")), 6)
        self.now = NOW + 121
        self.handle(c, ts_at(-5), alert_text("錯誤6", code="K6", task_id="k6"))
        self.assertEqual(elk_calls(), 6, "half-open: one probe, which fails and re-opens")
        self.handle(c, ts_at(-4), alert_text("錯誤7", code="K7", task_id="k7"))
        self.assertEqual(elk_calls(), 6)

    def test_open_breaker_never_silences(self):
        c = self.make()
        c._elk_open_until = NOW + 100
        self.active_rule()
        ts = ts_at(-10)
        self.handle(c, ts)
        self.assertEqual(self.signal_calls, [])
        self.assertEqual(self.row(ts)[0], "new")

    # fix 8
    def test_sample_decision_survives_post_retry(self):
        rid = self.active_rule()
        self.rng_value = 0.0
        c = self.make()
        ts = ts_at(-10)
        with mock.patch.object(Collector, "_attachments", side_effect=SlackError("internal_error")):
            self.handle(c, ts)
        self.publish(c, rounds=1)
        self.assertEqual(self.slack.posts, [])
        self.assertEqual(self.store.read("SELECT status FROM messages WHERE ts=?", (ts,)), [("received",)])
        self.rng_value = 0.99
        self.now = NOW + 3600
        c.process_pending()
        self.publish(c)
        self.assertEqual(self.row(ts)[0], "new")
        reply_ts = self.store.read("SELECT reply_ts FROM messages WHERE ts=?", (ts,))[0][0]
        self.assertEqual(self.store.lookup_reply("C1", reply_ts)[2], "sample")
        self.assertIn("抽樣", self.slack.posts[0][1])
        self.assertEqual(autorules.sample_rule(self.store, self.incident(ts).id), rid)

    # fix 9
    def test_backfill_beats_per_successful_channel(self):
        def history(token, channel, oldest, limit=200):
            if channel == "C2":
                raise OSError("down")
            return []
        self.slack.history = history
        c = self.make()
        with self.assertRaises(OSError):
            c.backfill()
        for channel in ("C1", "C3", "C4"):
            self.assertEqual(self.store.last_beat(f"backfill:{channel}"), NOW)
        self.assertIsNone(self.store.last_beat("backfill:C2"))

    # fix 10
    def test_start_logs_checks_with_unknown_system(self):
        self.checks["X"] = CheckSpec(key="X", system="nope")
        c = self.make()
        with self.assertLogs("alert_doctor.collector", "ERROR") as logs:
            c.start()
        self.assertIn("nope", logs.output[0])


LOG_CODE = "MDlNB90WVnwW-YUfdtieV"
ABSENCE_CODE = "riJG42iS-Dl7JNwYe5cP5"


def kw_text(pk, message="連線逾時", keywords=True, task_id="t1", code=LOG_CODE):
    vk = f"'crontab_task_pk': {pk}" + (", 'keywords': ['逾時'], 'interval': 10" if keywords else "")
    return (f"[L3] 檢查 log\n{{'code': '{code}', 'task_id': '{task_id}', 'vkwargs': {{{vk}}},"
            f" 'result': {{'level': 3, 'message': '{message}'}}}}")


class FakeSnapshot:
    def __init__(self, tasks):
        self.tasks = tasks

    def task(self, pk):
        return self.tasks.get(pk)

    def task_for_alert(self, alert):
        return self.tasks.get((alert.extra.get("vkwargs") or {}).get("crontab_task_pk"))


def fake_watchdog():
    return SimpleNamespace(
        load_snapshot=lambda path: None,
        alert_label=lambda alert, snap: (snap.task_for_alert(alert).label
                                         if snap.task_for_alert(alert) else alert.check_title),
        elk_query_from_kwargs=lambda kw: {"bool": {"must": [{"match_phrase": {"log.message": k}}
                                                            for k in kw["keywords"]]}}
        if kw.get("keywords") else None,
        elk_index_for=lambda kw: "log*",
        KEYWORD_QUERY_CODES=frozenset({LOG_CODE}))


class V3Base(Base):
    def setUp(self):
        super().setUp()
        self.cfg = dataclasses.replace(self.cfg, default_owners=("UDEF",))

    def outbox(self, kind=None):
        sql = "SELECT kind, priority, due_epoch, status, payload FROM outbox"
        rows = self.store.read(sql + (" WHERE kind=?" if kind else "") + " ORDER BY id",
                               (kind,) if kind else ())
        return rows

    def pending_due(self, kind):
        (due,), = self.store.read("SELECT due_epoch FROM outbox WHERE kind=? AND status='pending'",
                                  (kind,))
        return due

    def wave(self, c, base, n, text=None, channel="C1"):
        for i in range(n):
            self.feed(c, ts_at(base + i, i), text, channel=channel)
        c.process_pending()


class CadenceTests(V3Base):
    def test_first_reply_waits_for_the_wave_then_counts_and_tags_it(self):
        c = self.make()
        self.wave(c, -3, 3)
        self.assertEqual(c.publisher.process(self.now + 5), 0)
        self.assertEqual(c.publisher.process(self.now + 20), 1)
        (channel, text, thread), = self.slack.posts
        self.assertEqual((channel, thread), ("C1", ts_at(-3, 0)))
        self.assertTrue(text.startswith("<@UDEF> <@USYS>"))
        self.assertIn("本分鐘 3 則", text)
        self.assertEqual(len(self.store.read("SELECT 1 FROM messages WHERE status='handled'")), 3)

    def test_critical_first_reply_is_immediate_and_top_priority(self):
        self.checks["ORS1"] = CheckSpec(key="ORS1", never_silence=True, elk=ElkSpec(index="i", query={}))
        c = self.make()
        self.wave(c, -3, 1)
        (kind, priority, due, _, _), = self.outbox("first")
        self.assertEqual((priority, due), (0, self.now))
        self.assertEqual(c.publisher.process(self.now), 1)

    def test_datasource_first_reply_is_immediate(self):
        self.rules = [Rule(id="elk", action="datasource", match_message="ES連線")]
        c = self.make()
        self.wave(c, -3, 1, alert_text(message="ES連線出現異常"))
        self.assertEqual(self.outbox("first")[0][1:3], (0, self.now))

    def test_next_wave_is_one_untagged_update_in_the_report_thread(self):
        c = self.make()
        self.wave(c, -3, 2)
        self.publish(c)
        self.now += 300
        self.wave(c, 297, 3)
        self.publish(c)
        self.assertEqual(len(self.slack.posts), 2)
        _, update, thread = self.slack.posts[1]
        self.assertEqual(thread, ts_at(-3, 0))
        self.assertNotIn("<@", update)
        self.assertIn("3 則(累計 5 則)", update)

    def test_updates_keep_minimum_spacing_unless_magnitude_jumps(self):
        c = self.make()
        self.wave(c, -3, 6)
        self.publish(c)
        sent_at = self.store.get_report(self.incident(ts_at(-3, 0)).id, "C1")["last_update_epoch"]
        self.now += 30
        self.wave(c, 27, 1)
        self.assertEqual(self.pending_due("update"), sent_at + 120)
        self.wave(c, 28, 6)
        self.assertEqual(self.pending_due("update"), self.now)

    def test_tiny_counts_doubling_waits_for_normal_spacing(self):
        c = self.make()
        self.wave(c, -3, 1)
        self.publish(c)
        sent_at = self.store.get_report(self.incident(ts_at(-3, 0)).id, "C1")["last_update_epoch"]
        self.now += 30
        self.wave(c, 27, 2)
        self.assertEqual(self.pending_due("update"), sent_at + 120)

    def test_second_channel_report_is_not_tagged_again(self):
        c = self.make()
        self.wave(c, -5, 1, alert_text(task_id="shared"))
        self.wave(c, -4, 1, alert_text("查無資料", task_id="shared"), channel="C2")
        self.publish(c)
        first, second = self.slack.posts
        self.assertIn("<@UDEF>", first[1])
        self.assertNotIn("<@", second[1])
        self.assertEqual(second[0], "C2")


class BackfillTests(V3Base):
    def insert_late(self, offset, text=None):
        self.store.insert_message(parse_message("C1", ts_at(offset), text or alert_text()), self.now)

    def test_backfilled_occurrences_get_a_summary_not_updates(self):
        c = self.make()
        self.wave(c, -3, 1)
        self.publish(c)
        for i in range(3):
            self.insert_late(-900 + i)
        c.process_pending()
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM messages WHERE backfilled=1"), [(3,)])
        self.assertEqual([r[0] for r in self.outbox() if r[3] == "pending"], ["backfill"])
        self.publish(c, after=60)
        self.assertIn("補撈期間共 3 則", self.slack.posts[-1][1])

    def test_backfilled_new_incident_still_gets_its_first_reply(self):
        c = self.make()
        self.insert_late(-900)
        c.process_pending()
        self.publish(c)
        self.assertEqual(len(self.slack.posts), 1)
        self.assertIn("<@UDEF>", self.slack.posts[0][1])


class OverloadTests(V3Base):
    def test_intake_burst_enters_overload_and_tags_default_owners(self):
        c = self.make()
        self.wave(c, -20, 15)
        self.assertEqual(self.store.get_protection()["state"], "overload")
        (_, priority, _, _, payload), = self.outbox("protection")
        self.assertEqual(priority, 0)
        self.assertEqual(json.loads(payload)["mentions"], ["<@UDEF>"])
        self.assertTrue(json.loads(payload)["entering"])

    def test_overload_degrades_and_folds_updates_into_the_storm_overview(self):
        rule = autorules.propose_from_human(self.store, self.fp(), NOW - 60, "U1")
        c = self.make()
        self.wave(c, -20, 15)
        signals_before, candidates_before = len(self.signal_calls), len(self.candidate_calls)
        ts = ts_at(-1, 99)
        self.feed(c, ts, alert_text("別的錯誤", code="X2", task_id="x2"))
        self.feed(c, ts_at(-1, 98))
        c.process_pending()
        self.assertEqual((len(self.signal_calls), len(self.candidate_calls)),
                         (signals_before, candidates_before))
        self.assertEqual(self.store.read("SELECT degraded FROM messages WHERE ts=?", (ts,)), [(1,)])
        self.assertEqual(self.store.read("SELECT status FROM messages WHERE ts=?", (ts,)), [("handled",)])
        self.assertEqual(self.store.read("SELECT shadow_hits FROM auto_rules WHERE id=?", (rule.id,)),
                         [(15,)], "only the 15 occurrences before overload count")
        self.assertEqual(len(self.outbox("storm")), 1)
        self.assertEqual([r[0] for r in self.outbox("first")], ["first", "first"])

    def test_critical_is_never_folded_into_the_storm(self):
        self.checks["CR"] = CheckSpec(key="CR", never_silence=True)
        c = self.make()
        self.wave(c, -20, 15)
        self.wave(c, -1, 2, alert_text("掛了", code="CR", task_id="cr"))
        self.assertEqual(self.outbox("storm"), [])
        kinds = [(r[0], r[1]) for r in self.outbox() if json.loads(r[4]).get("severity") == "critical"
                 or r[1] == 0 and r[0] != "protection"]
        self.assertEqual(kinds, [("first", 0), ("update", 0)])

    def test_leaving_overload_posts_a_notice(self):
        self.store.set_protection("overload", "x", NOW - 600)
        monitor = SimpleNamespace(observe=lambda now, intake, active, current: ("normal", "恢復"))
        c = self.make(monitor=monitor)
        self.wave(c, -3, 1)
        self.assertEqual(self.store.get_protection()["state"], "normal")
        (_, _, _, _, payload), = self.outbox("protection")
        self.assertFalse(json.loads(payload)["entering"])


class BudgetTests(V3Base):
    def test_exhausted_elk_budget_skips_queries_and_never_silences(self):
        self.active_rule()
        c = self.make()
        c.budgets.elk._shared = 0
        c.budgets.elk._reserve["critical"] = 0
        ts = ts_at(-10)
        self.wave(c, -10, 1)
        self.assertEqual((self.signal_calls, self.elk.calls, self.candidate_calls), ([], [], []))
        self.assertEqual(self.row(ts)[0], "new")
        self.assertGreaterEqual(self.store.counter_sum("elk_skipped", NOW - 60, NOW), 2)

    def test_exhausted_llm_budget_still_requests_analysis(self):
        c = self.make()
        c.budgets.llm._shared = 0
        ts = ts_at(-10)
        self.wave(c, -10, 1)
        self.assertEqual(self.incident(ts).analysis_state, "pending")
        self.assertEqual(self.store.counter_sum("llm_deferred", NOW - 60, NOW), 1)


class WatchdogTests(V3Base):
    def make_with(self, tasks, archive=None):
        return self.make(snapshot=FakeSnapshot(tasks), watchdog=fake_watchdog(), archive=archive)

    def test_label_from_snapshot_and_keyword_query_feeds_evidence_and_signal(self):
        c = self.make_with({42: SimpleNamespace(label="訂單排程", kwargs={})})
        ts = ts_at(-10)
        self.wave(c, -10, 1, kw_text(42))
        self.publish(c)
        self.assertIn("*訂單排程*", self.slack.posts[0][1])
        self.assertEqual(len(self.elk.calls), 1)
        self.assertEqual(len(self.signal_calls), 1)
        self.assertEqual(self.store.counter_sum("unknown_task", NOW - 60, NOW), 0)
        self.assertEqual(self.row(ts)[0], "new")

    def test_keyword_spec_uses_log_index_and_interval(self):
        seen = []
        self.elk.gather = lambda spec, until, variables: seen.append(spec) or Evidence(False, "a", "b")
        c = self.make_with({})
        self.wave(c, -10, 1, kw_text(7))
        self.assertEqual((seen[0].index, seen[0].lookback_minutes), ("log*", 10))
        self.assertIn("match_phrase", str(seen[0].query))

    def test_unknown_task_is_counted(self):
        c = self.make_with({})
        self.wave(c, -10, 1, kw_text(7, keywords=False))
        self.assertEqual(self.store.counter_sum("unknown_task", NOW - 60, NOW), 1)
        self.assertEqual(self.elk.calls, [])

    def test_configured_check_elk_wins_over_keywords(self):
        self.checks[LOG_CODE] = CheckSpec(key=LOG_CODE, elk=ElkSpec(index="mine", query={}))
        seen = []
        self.elk.gather = lambda spec, until, variables: seen.append(spec) or Evidence(False, "a", "b")
        self.wave(self.make_with({}), -10, 1, kw_text(7))
        self.assertEqual(seen[0].index, "mine")

    def test_every_occurrence_is_archived_and_archive_failure_is_harmless(self):
        recorded = []

        class Archive:
            def record_occurrence(self, alert, **kw):
                recorded.append((alert.ts, kw["category"], kw["task_label"], kw["task_pk"]))
                if len(recorded) == 1:
                    raise OSError("disk full")

        c = self.make_with({42: SimpleNamespace(label="訂單排程", kwargs={})}, archive=Archive())
        with self.assertLogs("alert_doctor.collector", "WARNING"):
            self.wave(c, -10, 2, kw_text(42))
        self.assertEqual([r[1:] for r in recorded], [("new", "訂單排程", 42), ("duplicate", "訂單排程", 42)])
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM messages WHERE status='handled'"), [(2,)])

    def test_missing_snapshot_falls_back_to_alert_title(self):
        c = self.make(snapshot=None, watchdog=fake_watchdog(), archive=None)
        self.wave(c, -10, 1, kw_text(42, keywords=False))
        self.publish(c)
        self.assertIn("*[L3] 檢查 log*", self.slack.posts[0][1])
        self.assertEqual(self.store.counter_sum("unknown_task", NOW - 60, NOW), 0)


def m999_text(first_hit, task_id):
    message = ("['SSO']服務中出現異常關鍵字「['M999']」,請立即查看系統狀況!"
               f"「{first_hit}」")
    return ("[SSO] 檢查是否有M999的異常回應\n"
            f"{{'code': '{LOG_CODE}', 'task_id': '{task_id}', 'vkwargs': {{'crontab_task_pk': 118,"
            " 'interval': 5, 'keywords': ['M999'], 'log_tags': ['SSO']},"
            f" 'result': {{'level': 3, 'message': \"{message}\"}}}}")


class TaskIdentityTests(V3Base):
    def test_same_crontab_task_with_different_first_hit_is_one_incident(self):
        c = self.make(snapshot=FakeSnapshot({}), watchdog=fake_watchdog(), archive=None)
        self.wave(c, -300, 1, m999_text("M999 token expired request_path=/token user=a1", "run-1"))
        self.wave(c, -5, 1, m999_text("M999 invalid signature request_path=/login", "run-2"))
        self.assertNotEqual(self.store.read("SELECT fingerprint FROM messages WHERE ts=?", (ts_at(-300),)),
                            self.store.read("SELECT fingerprint FROM messages WHERE ts=?", (ts_at(-5),)))
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM incidents"), [(1,)])
        self.assertEqual(len(self.outbox("first")), 1)

    def test_task_id_still_merges_across_channels(self):
        c = self.make(snapshot=FakeSnapshot({}), watchdog=fake_watchdog(), archive=None)
        self.wave(c, -5, 1, alert_text(task_id="shared"))
        self.wave(c, -4, 1, alert_text("查無資料", task_id="shared"), channel="C2")
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM incidents"), [(1,)])


class KeywordQueryCodeTests(V3Base):
    def test_only_check_log_message_gets_a_derived_query(self):
        from alert_doctor import watchdog
        self.assertEqual(watchdog.KEYWORD_QUERY_CODES, frozenset({LOG_CODE}))
        c = self.make(snapshot=FakeSnapshot({}), watchdog=fake_watchdog(), archive=None)
        self.wave(c, -10, 1, kw_text(7, code=ABSENCE_CODE, task_id="a"))
        self.assertEqual((self.elk.calls, self.signal_calls), ([], []))
        self.wave(c, -5, 1, kw_text(8, code=LOG_CODE, task_id="b"))
        self.assertEqual(len(self.elk.calls), 1)

    def test_absence_check_uses_task_keywords_never(self):
        tasks = {7: SimpleNamespace(label="查不到關鍵字", kwargs={"keywords": ["ok"]})}
        c = self.make(snapshot=FakeSnapshot(tasks), watchdog=fake_watchdog(), archive=None)
        self.wave(c, -10, 1, kw_text(7, keywords=False, code=ABSENCE_CODE))
        self.assertEqual(self.elk.calls, [])


class Monitor:
    def __init__(self):
        self.seen = []
        self.next = None

    def observe(self, now, intake, active, current):
        self.seen.append((intake, active))
        change, self.next = self.next, None
        return change


def distinct(i, critical=False):
    return alert_text(f"錯誤{i}", code="CR" if critical else f"X{i}", task_id=f"x{i}")


class OverloadLlmTests(V3Base):
    def setUp(self):
        super().setUp()
        self.checks["CR"] = CheckSpec(key="CR", never_silence=True)
        self.store.set_protection("overload", "x", NOW - 600)
        self.monitor = Monitor()
        self.requested = []
        original = self.store.request_analysis

        def spy(incident_id, *, priority=2, **kw):
            self.requested.append((incident_id, priority))
            original(incident_id, priority=priority, **kw)
        self.store.request_analysis = spy

    def incident_of(self, i, critical=False):
        rows = self.store.read("SELECT id FROM incidents WHERE check_code=?",
                               ("CR" if critical else f"X{i}",))
        return rows[0][0]

    def test_only_top_three_of_the_episode_are_analysed(self):
        c = self.make(monitor=self.monitor)
        for i in range(3):
            self.wave(c, -50 + i, 1, distinct(i))
        self.wave(c, -40, 1, distinct(3))
        self.wave(c, -30, 1, distinct(4, critical=True))
        ids = [self.incident_of(i) for i in range(4)]
        critical = self.incident_of(4, critical=True)
        self.assertEqual([r[0] for r in self.requested], ids[:3] + [critical])
        self.assertEqual(dict(self.requested)[critical], 0)
        self.assertEqual(self.store.counter_sum("llm_skipped_overload", NOW - 60, NOW), 1)
        self.assertEqual(self.store.get_incident(ids[3]).analysis_state, "none")

    def test_exit_requests_recent_skipped_incidents(self):
        c = self.make(monitor=self.monitor)
        for i in range(3):
            self.wave(c, -50 + i, 1, distinct(i))
        self.wave(c, -900, 1, distinct(9))
        self.wave(c, -40, 1, distinct(3))
        self.requested.clear()
        self.monitor.next = ("normal", "恢復")
        c.process_pending()
        self.assertEqual(self.requested, [(self.incident_of(3), 2)])

    def test_exit_enqueues_catch_up_updates(self):
        c = self.make(monitor=self.monitor)
        self.wave(c, -50, 1, distinct(0))
        self.publish(c)
        incident_id = self.incident_of(0)
        seen = []

        def catchup(since):
            seen.append(since)
            return [(incident_id, "C1")]
        self.store.incidents_needing_catchup = catchup
        self.monitor.next = ("normal", "恢復")
        c.process_pending()
        self.assertEqual(seen, [NOW - 600])
        (kind, _, due, status, _), = self.outbox("update")
        self.assertEqual((due, status), (self.now, "pending"))


class AnalysisPriorityTests(V3Base):
    def spy(self):
        seen = []
        original = self.store.request_analysis

        def spy(incident_id, *, priority=2, **kw):
            seen.append(priority)
            original(incident_id, priority=priority, **kw)
        self.store.request_analysis = spy
        return seen

    def test_priority_by_category(self):
        seen = self.spy()
        self.checks["CR"] = CheckSpec(key="CR", never_silence=True)
        c = self.make()
        self.wave(c, -30, 1, alert_text("一般", code="N1", task_id="n"))
        self.wave(c, -20, 1, alert_text("掛了", code="CR", task_id="cr"))
        with mock.patch.object(Collector, "_spike", return_value=True):
            self.wave(c, -10, 1, alert_text("突增", code="S1", task_id="s"))
        self.assertEqual(seen, [2, 0, 1])


class ProtectionInputTests(V3Base):
    def test_intake_is_the_exact_last_sixty_seconds(self):
        monitor = Monitor()
        windows = []
        self.store.count_received = lambda since, until: windows.append((since, until)) or 7
        c = self.make(monitor=monitor)
        self.wave(c, -5, 1)
        since, until = windows[-1]
        self.assertEqual(since, self.now - 60)
        self.assertTrue(self.now < until < self.now + 1e-3)
        self.assertEqual(monitor.seen[-1][0], 7)

    def test_datasource_incidents_are_not_active_problems(self):
        self.rules = [Rule(id="elk", action="datasource", match_message="ES連線")]
        monitor = Monitor()
        c = self.make(monitor=monitor)
        self.wave(c, -10, 1, alert_text(message="ES連線出現異常", code="D1", task_id="d"))
        self.wave(c, -5, 1)
        self.assertEqual(monitor.seen[-1][1], 1)


if __name__ == "__main__":
    unittest.main()
