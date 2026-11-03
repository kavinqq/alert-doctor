import time
import unittest
from datetime import date, datetime

from alert_doctor.config import ChannelSpec, Config, RepoSpec
from alert_doctor.models import CheckSpec, ParsedAlert
from alert_doctor.report import TAIPEI, build_daily_report, day_bounds, health_problems
from alert_doctor.store import Store

CHANNEL = "C1"
DAY = date(2026, 10, 18)
NOON = day_bounds(DAY)[0] + 12 * 3600


def cfg():
    return Config(channels=(ChannelSpec(CHANNEL, "alerts-a", ("sys",)),), workspace_url="https://x.slack.com")


def alert(ts: float, title="檢查 A"):
    return ParsedAlert(channel=CHANNEL, ts=f"{ts:.6f}", raw_text=title, parse_ok=True,
                       check_title=title, result_message="m")


def add(store, ts, *, handled=True):
    a = alert(ts)
    store.insert_message(a, ts)
    if handled:
        store.mark_handled(CHANNEL, a.ts, category="noise", incident_id=None,
                           fingerprint="f", reply_ts="1.0", handled_epoch=ts)
    return a


class DailyReportTest(unittest.TestCase):
    def test_contains_counts(self):
        store = Store(":memory:")
        for i in range(3):
            add(store, NOON + i)
        add(store, NOON + 10, handled=False)
        a = add(store, NOON + 20, handled=False)
        for _ in range(5):
            store.message_attempt_failed(CHANNEL, a.ts, "boom")
        store.record_llm_call("sonnet", NOON)
        text = build_daily_report(store, cfg(), DAY)
        self.assertIn("2026-10-18", text)
        self.assertIn("alerts-a:5 則", text)
        self.assertIn("已處理 3", text)
        self.assertIn("失敗 1", text)
        self.assertIn("sonnet 1", text)

    def test_other_day_excluded(self):
        store = Store(":memory:")
        add(store, NOON + 86400)
        self.assertIn("alerts-a:0 則", build_daily_report(store, cfg(), DAY))

    def test_day_bounds_are_taipei_midnight(self):
        start, end = day_bounds(DAY)
        self.assertEqual(datetime.fromtimestamp(start, TAIPEI).hour, 0)
        self.assertEqual(end - start, 86400)


class HealthTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.now = NOON

    def beat_all(self):
        self.store.beat("collector", self.now - 10)
        self.store.beat("analyzer", self.now - 10)
        self.store.beat("socket", self.now - 10)
        self.store.beat("tuner", self.now - 10)

    def test_socket_stale(self):
        self.beat_all()
        self.store.beat("socket", self.now - 301)
        problems = health_problems(self.store, cfg(), self.now)
        self.assertEqual(len(problems), 1)
        self.assertIn("socket", problems[0])

    def test_healthy(self):
        self.beat_all()
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])

    def test_never_beat(self):
        problems = health_problems(self.store, cfg(), self.now)
        self.assertEqual(len(problems), 4)
        self.assertIn("collector", problems[0])
        self.assertIn("tuner", problems[3])

    def test_collector_stale(self):
        self.beat_all()
        self.store.beat("collector", self.now - 301)
        problems = health_problems(self.store, cfg(), self.now)
        self.assertEqual(len(problems), 1)
        self.assertIn("collector", problems[0])

    def test_collector_at_limit_is_ok(self):
        self.beat_all()
        self.store.beat("collector", self.now - 300)
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])

    def test_analyzer_threshold_is_an_hour(self):
        self.beat_all()
        self.store.beat("analyzer", self.now - 3000)
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])
        self.store.beat("analyzer", self.now - 3601)
        self.assertIn("analyzer", health_problems(self.store, cfg(), self.now)[0])

    def test_old_pending_message(self):
        self.beat_all()
        add(self.store, self.now - 601, handled=False)
        problems = health_problems(self.store, cfg(), self.now)
        self.assertEqual(len(problems), 1)
        self.assertIn("待處理訊息", problems[0])

    def test_fresh_pending_message_ok(self):
        self.beat_all()
        add(self.store, self.now - 100, handled=False)
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])

    def test_stale_pending_analysis(self):
        # request_analysis stamps wall-clock time, so this test cannot use the fixed NOON.
        now = time.time()
        self.store.beat("collector", now + 4 * 3600)
        self.store.beat("analyzer", now + 4 * 3600)
        self.store.beat("socket", now + 4 * 3600)
        self.store.beat("tuner", now + 4 * 3600)
        incident = self.store.create_incident(alert(now - 20000), "fp", "g")
        self.store.request_analysis(incident.id)
        self.assertEqual(health_problems(self.store, cfg(), now + 3600), [])
        problems = health_problems(self.store, cfg(), now + 4 * 3600 + 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("分析積壓", problems[0])

    def test_failed_today(self):
        self.beat_all()
        a = add(self.store, self.now - 100, handled=False)
        for _ in range(5):
            self.store.message_attempt_failed(CHANNEL, a.ts, "boom")
        problems = health_problems(self.store, cfg(), self.now)
        self.assertTrue(any("處理失敗" in p for p in problems))

    def test_failed_yesterday_ignored(self):
        self.beat_all()
        a = add(self.store, self.now - 86400, handled=False)
        for _ in range(5):
            self.store.message_attempt_failed(CHANNEL, a.ts, "boom")
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])


if __name__ == "__main__":
    unittest.main()


class ComponentHealthTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.now = NOON
        for c in ("collector", "analyzer", "socket", "tuner"):
            self.store.beat(c, self.now - 10)

    def problems(self, config=None, checks=None):
        return health_problems(self.store, config or cfg(), self.now, checks=checks)

    def test_backfill_stale_after_fifteen_minutes(self):
        self.store.beat(f"backfill:{CHANNEL}", self.now - 900)
        self.assertEqual(self.problems(), [])
        self.store.beat(f"backfill:{CHANNEL}", self.now - 901)
        self.assertIn("alerts-a", self.problems()[0])

    def test_backfill_missing_only_flagged_once_collector_ran_fifteen_minutes(self):
        self.assertEqual(self.problems(), [])
        self.store.beat("collector_started", self.now - 600)
        self.assertEqual(self.problems(), [])
        self.store.beat("collector_started", self.now - 901)
        self.assertIn("alerts-a", self.problems()[0])

    def test_mirror_stale_after_an_hour(self):
        config = Config(channels=cfg().channels, workspace_url="https://x", repos={"r": RepoSpec("r", "/r")})
        self.assertIn("r", self.problems(config)[0])
        self.store.beat("mirror:r", self.now - 3600)
        self.assertEqual(self.problems(config), [])
        self.store.beat("mirror:r", self.now - 3601)
        self.assertIn("mirror", self.problems(config)[0])

    def test_tuner_stale_after_two_hours(self):
        self.store.beat("tuner", self.now - 7200)
        self.assertEqual(self.problems(), [])
        self.store.beat("tuner", self.now - 7201)
        self.assertIn("tuner", self.problems()[0])

    def test_check_with_unknown_system_flagged(self):
        problems = self.problems(checks={"X": CheckSpec(key="X", system="nope"),
                                         "Y": CheckSpec(key="Y")})
        self.assertEqual(len(problems), 1)
        self.assertIn("nope", problems[0])


class FailedAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.now = NOON
        for c in ("collector", "analyzer", "socket", "tuner"):
            self.store.beat(c, self.now - 10)

    def failed_incident(self, requested):
        inc = self.store.create_incident(alert(self.now - 100), "fp", "g")
        self.store.request_analysis(inc.id, now=requested)
        self.store._db.execute("UPDATE incidents SET analysis_state='failed'")
        return inc

    def test_failed_analysis_flagged(self):
        inc = self.failed_incident(self.now - 3600)
        problems = health_problems(self.store, cfg(), self.now)
        self.assertEqual(len(problems), 1)
        self.assertIn(f"#{inc.id}", problems[0])

    def test_old_failed_analysis_ignored(self):
        self.failed_incident(self.now - 25 * 3600)
        self.assertEqual(health_problems(self.store, cfg(), self.now), [])

    def test_expired_lease_flagged(self):
        inc = self.store.create_incident(alert(self.now - 100), "fp", "g")
        self.store.request_analysis(inc.id, now=self.now - 7200)
        self.store.claim_incident("w", self.now - 3600, lease_seconds=60)
        problems = health_problems(self.store, cfg(), self.now)
        self.assertTrue(any("租約" in p for p in problems))

    def test_daily_report_lists_failed_analyses(self):
        self.failed_incident(NOON)
        self.assertIn("分析失敗:1", build_daily_report(self.store, cfg(), DAY))


class WeeklyReportTest(unittest.TestCase):
    def setUp(self):
        from alert_doctor import autorules, schema
        self.ar = autorules
        self.store = Store(":memory:")
        schema.ensure_all(self.store)
        self.now = NOON + 7 * 86400
        self.since = self.now - 7 * 86400

    def incident(self, ts, fp, severity=None, category="new", title="檢查 A"):
        a = alert(ts, title)
        self.store.insert_message(a, ts)
        inc = self.store.create_incident(a, fp, "g")
        self.store.mark_handled(CHANNEL, a.ts, category=category, incident_id=inc.id,
                                fingerprint=fp, reply_ts=f"{ts + 1:.6f}", handled_epoch=ts)
        if severity:
            self.store.request_analysis(inc.id, now=ts)
            self.store.claim_incident("w", ts)
            self.store.complete_analysis(inc.id, {"severity": severity, "category": "infra"}, "sonnet", ts + 5)
        return inc

    def feedback(self, incident_id, kind, epoch):
        with self.store.tx() as db:
            db.execute("INSERT INTO feedback (incident_id, user, kind, epoch) VALUES (?,?,?,?)",
                       (incident_id, "U1", kind, epoch))

    def test_sections(self):
        from alert_doctor.report import build_weekly_report
        t = self.since + 3600
        crit = self.incident(t, "fp-crit", "critical", title="下單失敗")
        self.incident(t + 10, "fp-low", "low")
        for i in range(3):
            self.incident(t + 20 + i, "fp-noisy", category="noise", title="吵鬧檢查")
        self.incident(self.since - 3600, "fp-old", "high", title="上週的")
        self.feedback(crit.id, "agree", t + 100)
        self.feedback(crit.id, "agree", t + 101)
        self.feedback(crit.id, "reject", t + 102)
        self.feedback(crit.id, "reject", self.since - 10)
        self.ar.propose_from_human(self.store, "fp-noisy", t, "U1")
        active = self.ar.propose_from_human(self.store, "fp-low", self.since - 20 * 86400, "U1")
        with self.store.tx() as db:
            db.execute("UPDATE auto_rules SET state='active', activated=?, expires=? WHERE id=?",
                       (t, self.now + 86400, active.id))
        self.ar.revoke(self.store, "fp-x", "human ❌", t)
        self.store.record_llm_call("sonnet", t)
        self.store.record_llm_call("opus", self.since - 5)
        text = build_weekly_report(self.store, cfg(), self.now, audit="request_id 稽核內容")
        self.assertIn("週報", text)
        self.assertIn("🔴 critical 1", text)
        self.assertIn("下單失敗", text)
        self.assertNotIn("上週的", text)
        self.assertIn("回饋準確率 67%(✅ 2 / ❌ 1)", text)
        self.assertIn("shadow 1", text)
        self.assertIn("active 1", text)
        self.assertIn("本週新增 1", text)
        self.assertIn("本週轉正 1", text)
        self.assertIn("本週 ❌ 撤銷 1", text)
        self.assertIn("sonnet 1", text)
        self.assertNotIn("opus 1", text)
        self.assertIn("吵鬧檢查", text)
        self.assertLess(text.index("吵鬧檢查"), text.index("request_id 稽核內容"))
        self.assertIn("noise 3", text)

    def test_empty_week(self):
        from alert_doctor.report import build_weekly_report
        text = build_weekly_report(self.store, cfg(), self.now)
        self.assertIn("回饋準確率 —(尚無回饋)", text)
        self.assertNotIn("request_id", text)


class V3ReportTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.now = NOON
        for c in ("collector", "analyzer", "socket", "tuner"):
            self.store.beat(c, self.now - 10)

    def problems(self, **kw):
        return health_problems(self.store, cfg(), self.now, **kw)

    def enqueue(self, kind="first", priority=1, due=None, key=None):
        return self.store.enqueue_reply(incident_id=1, channel=CHANNEL, kind=kind, priority=priority,
                                        due_epoch=self.now if due is None else due,
                                        payload={"text": "x"}, dedupe_key=key)

    def test_daily_splits_normal_degraded_published_deferred(self):
        a, b = alert(NOON), alert(NOON + 1)
        inc = self.store.create_incident(a, "fp", "g")
        for x, degraded in ((a, False), (b, True)):
            self.store.insert_message(x, NOON)
            self.store.mark_handled(CHANNEL, x.ts, category="new", incident_id=inc.id,
                                    fingerprint="fp", reply_ts=None, handled_epoch=NOON,
                                    degraded=degraded)
        sent = self.enqueue(due=NOON)
        self.store.complete_outbox(sent, "9.1", NOON + 2)
        self.enqueue(kind="update", priority=2, due=NOON + 3)
        self.store.bump_counter("elk_skipped", 7, NOON)
        self.store.bump_counter("llm_deferred", 2, NOON)
        text = build_daily_report(self.store, cfg(), DAY)
        self.assertIn("分類 正常 1 · 降級 1 · 已發布 2 · 待發 1", text)
        self.assertIn("ELK 查詢跳過 7", text)
        self.assertIn("LLM 延後 2", text)
        self.assertIn("目前為正常模式", text)

    def test_weekly_has_protection_section(self):
        from alert_doctor import schema
        from alert_doctor.report import build_weekly_report
        schema.ensure_all(self.store)
        self.store.set_protection("overload", "intake 2000/分", self.now - 60)
        text = build_weekly_report(self.store, cfg(), self.now)
        self.assertIn("過載模式", text)
        self.assertIn("intake 2000/分", text)
        self.assertIn("分類 正常 0 · 降級 0", text)

    def test_quiet_outbox_and_protection_are_healthy(self):
        self.enqueue(due=self.now - 10)
        self.enqueue(kind="update", priority=2, due=self.now + 3600, key="u")
        self.store.set_protection("overload", "r", self.now - 600)
        self.assertEqual(self.problems(), [])

    def test_critical_first_late_after_thirty_seconds(self):
        self.enqueue(priority=0, due=self.now - 30)
        self.assertEqual(self.problems(), [])
        self.enqueue(priority=0, due=self.now - 31, key="k")
        [problem] = self.problems()
        self.assertIn("CRITICAL", problem)

    def test_normal_first_late_after_five_minutes(self):
        self.enqueue(due=self.now - 301)
        [problem] = self.problems()
        self.assertIn("一般首則", problem)

    def test_outbox_oldest_after_ten_minutes(self):
        self.enqueue(kind="update", priority=2, due=self.now - 601)
        [problem] = self.problems()
        self.assertIn("outbox 最老待發", problem)

    def set_enqueued(self, item, epoch):
        with self.store.tx() as db:
            db.execute("UPDATE outbox SET enqueued_epoch=? WHERE id=?", (epoch, item))

    def test_row_retried_every_thirty_seconds_for_an_hour_alarms(self):
        from alert_doctor.store import MAX_OUTBOX_ATTEMPTS
        item = self.enqueue(due=self.now - 3600)
        self.set_enqueued(item, self.now - 3600)
        for step in range(MAX_OUTBOX_ATTEMPTS - 1):
            self.store.retry_outbox(item, "boom", self.now - 30 + step)
        problems = self.problems()
        self.assertTrue(any("持續發送失敗" in p for p in problems), problems)
        self.assertTrue(any("一般首則" in p for p in problems), problems)

    def test_erroring_pending_row_quiet_before_ten_minutes(self):
        item = self.enqueue(kind="update", priority=2, due=self.now - 500)
        self.set_enqueued(item, self.now - 500)
        self.store.retry_outbox(item, "boom", self.now - 10)
        self.assertEqual(self.problems(), [])

    def test_recently_failed_outbox_row_flagged(self):
        from alert_doctor.store import MAX_OUTBOX_ATTEMPTS
        item = self.enqueue(kind="update", priority=2, due=self.now + 100)
        for _ in range(MAX_OUTBOX_ATTEMPTS):
            self.store.retry_outbox(item, "boom", self.now - 100)
        [problem] = self.problems()
        self.assertIn("發送失敗", problem)
        self.now += 2 * 86400
        for c in ("collector", "analyzer", "socket", "tuner"):
            self.store.beat(c, self.now - 10)
        self.assertEqual(self.problems(), [])

    def test_overload_longer_than_ten_minutes(self):
        self.store.set_protection("overload", "活躍 incident 12 件", self.now - 601)
        [problem] = self.problems()
        self.assertIn("過載保護已持續 10 分鐘", problem)
        self.assertIn("活躍 incident 12 件", problem)

    def test_unknown_task_seen_in_last_day(self):
        self.store.bump_counter("unknown_task", 3, self.now - 3600)
        [problem] = self.problems()
        self.assertIn("3 則", problem)
        self.assertIn("快照", problem)

    def test_snapshot_missing_old_fresh_and_unparsable(self):
        from types import SimpleNamespace
        self.assertIn("快照不存在", self.problems(snapshot=None)[0])
        fresh = datetime.fromtimestamp(self.now - 29 * 86400, TAIPEI).isoformat()
        self.assertEqual(self.problems(snapshot=SimpleNamespace(exported_at=fresh)), [])
        old = datetime.fromtimestamp(self.now - 31 * 86400, TAIPEI).isoformat()
        self.assertIn("31 天", self.problems(snapshot=SimpleNamespace(exported_at=old))[0])
        self.assertIn("看不懂", self.problems(snapshot=SimpleNamespace(exported_at="昨天"))[0])


class PurgedSectionTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        a = alert(NOON)
        self.store.insert_message(a, NOON)
        self.iid = self.store.create_incident(a, "fp", "g").id

    def purge(self, channels, state, at=NOON, cause="Redis 連線瞬斷後自行恢復,不影響下單" * 3):
        verdict = {"severity": "low", "action": "observe", "cause": cause}
        ids = self.store.complete_analysis_with_purge(
            self.iid, verdict, "m", at, channels=list(channels), analysis_text="")
        for n, pid in enumerate(ids):
            channel = channels[n]
            self.store.add_purge_targets(pid, channel, "alert", [f"{channel}-1", f"{channel}-2"])
            self.store.add_purge_targets(pid, channel, "fragment", [f"{channel}-f"])
            self.store.add_purge_targets(pid, channel, "reply", [f"{channel}-r"])
            self.store.set_purge(pid, state=state, finished_epoch=at)

    def test_daily_report_lists_purged(self):
        self.purge(("C1", "C2"), "done")
        text = build_daily_report(self.store, cfg(), DAY)
        self.assertIn("🟢 綠燈已刪除 1 件", text)
        line = next(l for l in text.split("\n") if l.startswith(f"• #{self.iid} "))
        self.assertIn("檢查 A ×6 — Redis 連線瞬斷後自行恢復", line)
        self.assertLessEqual(len(line.split(" — ", 1)[1]), 60)

    def test_daily_report_fallback_count(self):
        self.purge(("C1",), "fallback")
        text = build_daily_report(self.store, cfg(), DAY)
        self.assertIn("刪除失敗、改回覆分析 1 件", text)
        self.assertNotIn("🟢 綠燈已刪除", text)

    def test_section_omitted_when_none_or_other_day(self):
        self.purge(("C1",), "done", at=NOON + 86400)
        text = build_daily_report(self.store, cfg(), DAY)
        self.assertNotIn("綠燈", text)
        self.assertNotIn("刪除失敗", text)
