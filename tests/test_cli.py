import contextlib
import io
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from alert_doctor import __main__ as cli
from alert_doctor.dryrun import DryRunSlack
from alert_doctor.store import Store

REPO = Path(__file__).resolve().parent.parent
CHANNEL = "C0TEST"
CHANNEL2 = "C0TEST2"


def alert_text(code, message, title="檢查 X"):
    extra = {"task_id": "t", "code": code, "vargs": [], "vkwargs": {},
             "check_script": title, "result": {"level": 40, "message": message}}
    return f"{title}\n{extra!r}"


class FakeSlack:
    def __init__(self, messages=(), other=()):
        self.messages = list(messages)
        self.other = list(other)
        self.posts = []

    def history(self, token, channel, oldest, limit=200):
        return {CHANNEL: self.messages, CHANNEL2: self.other}.get(channel, [])

    def post_message(self, token, channel, text, thread_ts=None):
        self.posts.append((channel, text, thread_ts))
        return "1.0"


SETTLE = 20


class FakeCollector:
    """Stands in for alert_doctor.collector: classifies and queues, never posts."""

    def __init__(self, cfg, store, slack, elk, rules, checks, bot_token, clock=time.time, **kw):
        self.store, self.slack, self.cfg, self.elk, self.clock = store, slack, cfg, elk, clock

    def start(self):
        pass

    def on_socket_event(self, kind, payload):
        from alert_doctor.parse import parse_message
        event = payload["event"]
        alert = parse_message(event["channel"], event["ts"], event["text"])
        now = self.clock()
        if self.store.insert_message(alert, now):
            self.store.bump_counter("intake", 1, now)

    def process_pending(self):
        done = 0
        for alert in self.store.pending_messages(now=float("inf")):
            self.store.enqueue_reply(
                incident_id=None, channel=alert.channel, kind="first", priority=1,
                due_epoch=self.clock() + SETTLE, thread_ts=alert.ts,
                payload={"text": f"收到 {alert.check_title}", "reactions_on_root": ["mag"]})
            self.store.mark_handled(alert.channel, alert.ts, category="new", incident_id=None,
                                    fingerprint=None, reply_ts=None, handled_epoch=0)
            done += 1
        return done


class FakePublisher:
    instances = []

    def __init__(self, cfg, store, slack, bot_token, budgets, clock, archive=None):
        self.store, self.slack, self.clock, self.budgets = store, slack, clock, budgets
        self.calls = []
        FakePublisher.instances.append(self)

    def process(self, now):
        self.calls.append((now, self.clock()))
        items = self.store.claim_outbox(now)
        for item in items:
            ts = self.slack.post_message("t", item.channel, item.payload["text"], item.thread_ts)
            for name in item.payload.get("reactions_on_root", ()):
                self.slack.add_reaction("t", item.channel, item.thread_ts, name)
            self.store.index_reply(item.channel, ts, item.thread_ts, item.incident_id, item.kind)
            self.store.complete_outbox(item.id, ts, now)
        return len(items)


def fake_modules():
    FakePublisher.instances.clear()
    return {"alert_doctor.collector": types.SimpleNamespace(Collector=FakeCollector),
            "alert_doctor.publisher": types.SimpleNamespace(Publisher=FakePublisher)}


def fresh_snapshot():
    from datetime import datetime, timezone
    return types.SimpleNamespace(exported_at=datetime.now(timezone.utc).isoformat(), tasks=lambda: [])


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = os.path.join(self.tmp.name, "config.toml")
        Path(self.config).write_text(
            f'workspace_url = "https://x.slack.com"\n'
            f'report_channel = "CREPORT"\n'
            f'rules_path = "{REPO / "rules.example.toml"}"\n'
            f'checks_path = "{REPO / "checks.example.toml"}"\n'
            f'[[channels]]\nid = "{CHANNEL}"\nname = "alerts-a"\nsystems = ["sys"]\n'
            f'[[channels]]\nid = "{CHANNEL2}"\nname = "alerts-b"\nsystems = ["sys"]\n'
            f'[systems.sys]\nrepos = ["r"]\nelk_project = "p"\n'
            f'[repos.r]\npath = "/tmp/r"\n')
        patcher = mock.patch.object(cli, "get_secret", return_value="tok")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.snapshot = fresh_snapshot()
        snap = mock.patch.object(cli, "_load_snapshot", side_effect=lambda cfg: self.snapshot)
        snap.start()
        self.addCleanup(snap.stop)

    def run_cli(self, *argv, slack=None, elk=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([*argv, "--config", self.config], slack=slack, elk=elk)
        return code, out.getvalue(), err.getvalue()

    def db(self):
        path = os.path.join(self.tmp.name, "data", "alert_doctor.db")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return Store(path)


class DiscoverTest(CliTestCase):
    def test_groups_by_check_code_and_counts(self):
        now = time.time()
        slack = FakeSlack([
            {"ts": f"{now - 300:.6f}", "text": alert_text("c_a", "5xx 37")},
            {"ts": f"{now - 200:.6f}", "text": alert_text("c_a", "5xx 40")},
            {"ts": f"{now - 100:.6f}", "text": alert_text("c_b", "boom", "檢查 B")},
            {"ts": f"{now - 50:.6f}", "text": "hello\nnot a dict"},
        ])
        code, out, _ = self.run_cli("discover", slack=slack)
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], f"== alerts-a ({CHANNEL})")
        self.assertEqual(lines[4], f"== alerts-b ({CHANNEL2})")
        self.assertEqual(lines[5], "這段時間沒有訊息")
        lines = lines[1:4]
        self.assertTrue(lines[0].startswith("c_a\t2 則"))
        self.assertIn("5xx 40", lines[0])
        self.assertTrue(any(line.startswith("hello\t1 則") for line in lines))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "data")))

    def test_second_channel_listed_under_its_name(self):
        now = time.time()
        slack = FakeSlack(other=[{"ts": f"{now - 100:.6f}", "text": alert_text("c_z", "zzz")}])
        _, out, _ = self.run_cli("discover", slack=slack)
        lines = out.strip().splitlines()
        self.assertEqual(lines[1], "這段時間沒有訊息")
        self.assertEqual(lines[2], f"== alerts-b ({CHANNEL2})")
        self.assertTrue(lines[3].startswith("c_z\t1 則"))

    def test_empty(self):
        code, out, _ = self.run_cli("discover", slack=FakeSlack())
        self.assertEqual(code, 0)
        self.assertIn("沒有訊息", out)


class ReplayTest(CliTestCase):
    def write_jsonl(self, items):
        path = os.path.join(self.tmp.name, "r.jsonl")
        Path(path).write_text("\n".join(json.dumps(i) for i in items), encoding="utf-8")
        return path

    def test_prints_outbox_posts_without_network(self):
        path = self.write_jsonl([{"ts": "1700000000.000100", "text": alert_text("c_a", "x")},
                                 {"ts": "1700000001.000100", "text": alert_text("c_b", "y", "檢查 B")}])
        slack = FakeSlack()
        with mock.patch.dict(sys.modules, fake_modules()):
            code, out, _ = self.run_cli("replay", path, "--no-elk", slack=slack)
        self.assertEqual(code, 0, out)
        self.assertIn("ts 1700000000.000100", out)
        self.assertIn("category=new", out)
        self.assertIn("收到 檢查 X", out)
        self.assertIn("📤 06:13:40 alerts-a · first · thread 1700000000.000100", out)
        self.assertIn("reactions: +mag on 1700000000.000100", out)
        self.assertIn("=== 統計:2 則告警 · Slack 發文 2 則(有 tag 0)", out)
        self.assertIn("outbox 待發 0", out)
        self.assertEqual(slack.posts, [])

    def test_replay_goes_through_intake_counter_not_backfill(self):
        path = self.write_jsonl([{"ts": f"170000000{i}.000100", "text": alert_text("c_a", "x")}
                                 for i in range(3)])
        with mock.patch.dict(sys.modules, fake_modules()):
            code, out, _ = self.run_cli("replay", path, "--no-elk", slack=FakeSlack())
        self.assertEqual(code, 0, out)
        self.assertIn("intake 3", out)

    def test_publisher_runs_on_the_replay_clock_at_due_times(self):
        path = self.write_jsonl([{"ts": "1700000000.0", "text": alert_text("c_a", "x")},
                                 {"ts": "1700000100.0", "text": alert_text("c_b", "y")}])
        with mock.patch.dict(sys.modules, fake_modules()):
            code, out, _ = self.run_cli("replay", path, "--no-elk", slack=FakeSlack())
        self.assertEqual(code, 0)
        [publisher] = FakePublisher.instances
        times = [now for now, _ in publisher.calls]
        self.assertEqual(times, sorted(times))
        self.assertIn(1700000000.0 + SETTLE, times)
        self.assertIn(1700000100.0 + SETTLE, times)
        self.assertTrue(all(now == clock for now, clock in publisher.calls))
        self.assertLess(out.index("收到 檢查 X"), out.index("ts 1700000100.0"))

    def test_channel_field_selects_channel_and_defaults_to_first(self):
        path = self.write_jsonl([
            {"ts": "1700000000.000100", "text": alert_text("c_a", "x")},
            {"ts": "1700000001.000100", "text": alert_text("c_b", "y", "檢查 B"), "channel": CHANNEL2}])
        with mock.patch.dict(sys.modules, fake_modules()):
            code, out, _ = self.run_cli("replay", path, "--no-elk", slack=FakeSlack())
        self.assertEqual(code, 0, out)
        self.assertIn("--- alerts-a · ts 1700000000.000100", out)
        self.assertIn("--- alerts-b · ts 1700000001.000100", out)
        self.assertIn("category=new", out.split("--- alerts-b")[1])

    def test_unknown_channel_rejected(self):
        path = self.write_jsonl([{"ts": "1.0", "text": alert_text("c", "x"), "channel": "CNOPE"}])
        code, _, err = self.run_cli("replay", path, "--no-elk")
        self.assertEqual(code, 2)
        self.assertIn("CNOPE", err)

    def test_empty_file(self):
        path = self.write_jsonl([])
        Path(path).write_text("")
        code, _, err = self.run_cli("replay", path, "--no-elk")
        self.assertEqual(code, 2)
        self.assertIn("空的", err)


class DryRunSlackTest(unittest.TestCase):
    def test_records_and_returns_fake_ts(self):
        dry = DryRunSlack()
        ts = dry.post_message("t", "C", "hi", "1.0")
        self.assertEqual(dry.calls[0][1]["ts"], ts)
        dry.add_reaction("t", "C", "1.0", "mag")
        self.assertTrue(ts)
        self.assertEqual(dry.replies_to("1.0"), ["hi"])
        self.assertEqual(dry.reactions_on("1.0"), ["mag"])
        self.assertEqual(dry.replies_to("1.0", "OTHER"), [])
        self.assertEqual(dry.reactions_on("1.0", "OTHER"), [])


class BackfillTest(CliTestCase):
    def test_backfill_only_inserts_and_never_processes(self):
        fake = mock.Mock()
        fake.backfill.return_value = 3
        with mock.patch.object(cli, "_build_collector", return_value=fake):
            code, out, _ = self.run_cli("backfill", "--hours", "5", slack=FakeSlack())
        self.assertEqual(code, 0)
        fake.process_pending.assert_not_called()
        since = fake.backfill.call_args.kwargs["since"]
        self.assertAlmostEqual(time.time() - since, 5 * 3600, delta=60)
        self.assertIn("新增 3 則", out)
        self.assertIn("collector", out)


class ReportHealthTest(CliTestCase):
    def test_report_post(self):
        slack = FakeSlack()
        code, out, _ = self.run_cli("report", "--date", "2026-10-18", "--post", slack=slack)
        self.assertEqual(code, 0)
        self.assertIn("2026-10-18", out)
        self.assertEqual(slack.posts[0][0], "CREPORT")

    def test_health_unhealthy_exits_1_and_notifies(self):
        slack = FakeSlack()
        with mock.patch.object(cli.subprocess, "run") as run:
            code, out, _ = self.run_cli("health", "--post", slack=slack)
        self.assertEqual(code, 1)
        self.assertIn("健康檢查異常", out)
        self.assertEqual(slack.posts[0][0], "CREPORT")
        self.assertEqual(run.call_args.args[0][0], "osascript")

    def test_health_does_not_repost_unchanged_problems(self):
        slack = FakeSlack()
        with mock.patch.object(cli.subprocess, "run"):
            self.run_cli("health", "--post", slack=slack)
            code, _, _ = self.run_cli("health", "--post", slack=slack)
        self.assertEqual(code, 1)
        self.assertEqual(len(slack.posts), 1)

    def use_checks(self, text):
        checks = os.path.join(self.tmp.name, "checks.toml")
        Path(checks).write_text(text, encoding="utf-8")
        config = Path(self.config).read_text().replace(str(REPO / "checks.example.toml"), checks)
        Path(self.config).write_text(config)

    def beat_everything(self):
        store = self.db()
        for component in ("collector", "analyzer", "socket", "tuner", "mirror:r"):
            store.beat(component, time.time())

    def test_health_ok(self):
        self.use_checks('[checks."c"]\nsystem = "sys"\n')
        self.beat_everything()
        code, out, _ = self.run_cli("health")
        self.assertEqual((code, out.strip()), (0, "ok"))

    def test_health_flags_check_with_undefined_system(self):
        self.use_checks('[checks."c"]\nsystem = "nope"\n')
        self.beat_everything()
        code, out, _ = self.run_cli("health")
        self.assertEqual(code, 1)
        self.assertIn("nope", out)

    def test_health_reports_unreadable_checks(self):
        self.use_checks('[checks."c"\n')
        self.beat_everything()
        code, out, _ = self.run_cli("health")
        self.assertEqual(code, 1)
        self.assertIn("checks.toml", out)

    def test_health_flags_missing_snapshot(self):
        self.use_checks('[checks."c"]\nsystem = "sys"\n')
        self.beat_everything()
        self.snapshot = None
        code, out, _ = self.run_cli("health")
        self.assertEqual(code, 1)
        self.assertIn("watchdog 快照不存在", out)

    def test_missing_config_is_friendly(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["health", "--config", "/nonexistent.toml"])
        self.assertEqual(code, 2)
        self.assertIn("錯誤", err.getvalue())


def _publisher_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("alert_doctor.publisher") is not None


@unittest.skipUnless(_publisher_available(), "alert_doctor.publisher 尚未存在")
class ReplayRealCollectorTest(CliTestCase):
    def test_real_collector_two_channels_shared_task_and_never_silence(self):
        items = [
            {"ts": "1700000000.000100", "text": alert_text("c_a", "boom")},
            {"ts": "1700000001.000100", "text": alert_text("c_a", "boom"), "channel": CHANNEL2},
            {"ts": "1700000002.000100", "text": alert_text("c_t", "x", "下單檢查")},
        ]
        path = os.path.join(self.tmp.name, "r.jsonl")
        Path(path).write_text("\n".join(json.dumps(i) for i in items), encoding="utf-8")
        code, out, err = self.run_cli("replay", path, "--no-elk", slack=FakeSlack())
        self.assertEqual(code, 0, err)
        headers = [line for line in out.splitlines() if line.startswith("--- ")]
        self.assertEqual([h.rsplit("category=", 1)[1] for h in headers],
                         ["new", "duplicate", "critical"])
        # CRITICAL goes out immediately; the others wait for the batch to settle.
        self.assertLess(out.index("📤"), out.index("thread 1700000000.000100"))
        self.assertIn("· thread 1700000002.000100", out[:out.index("thread 1700000000.000100")])
        self.assertIn("同一事件已在", out)
        self.assertIn("+red_circle on 1700000002.000100", out)
        self.assertIn("=== 統計:3 則告警 · Slack 發文 3 則", out)


class TunerCommandTest(CliTestCase):
    def seed_noise_verdicts(self, store):
        now = time.time()
        for i in range(3):
            with store.tx() as db:
                db.execute(
                    "INSERT INTO incidents (fingerprint, group_fp, check_title, channel, anchor_ts,"
                    " first_epoch, last_epoch, count, analysis_state, verdict, completed_epoch)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    ("fp-noise", "g", "t", CHANNEL, str(i), now, now, 1, "done",
                     json.dumps({"category": "noise", "confidence": 0.9}), now - 3600))

    def test_tuner_proposes_and_reports(self):
        self.seed_noise_verdicts(self.db())
        code, out, err = self.run_cli("tuner")
        self.assertEqual(code, 0, err)
        self.assertIsNotNone(self.db().last_beat("tuner"))
        self.assertIn("基線", out)
        self.assertIn("新增 shadow 規則 1", out)
        self.assertIn("fp-noise"[:8], out)

    def test_tuner_lists_promotions(self):
        from alert_doctor import autorules, schema
        store = self.db()
        schema.ensure_all(store)
        created = time.time() - 8 * 86400
        rule = autorules.propose_from_human(store, "fp-promote", created, "U1")
        for i in range(12):
            autorules.record_shadow_hit(store, rule.id, incident_id=i,
                                        epoch=created + (i % 8) * 86400 + 3600)
        code, out, _ = self.run_cli("tuner")
        self.assertEqual(code, 0)
        self.assertIn(f"轉正 #{rule.id}", out)

    def test_rollback(self):
        from alert_doctor import schema
        store = self.db()
        schema.ensure_all(store)
        with store.tx() as db:
            for version in (1, 2, 3):
                db.execute("INSERT INTO baselines VALUES (?,?,?,?,?,?,?)", (version, "f", 1, 1.0, 2.0, 5, 0.0))
        code, out, _ = self.run_cli("tuner", "--rollback", "1")
        self.assertEqual(code, 0)
        self.assertIn("回滾到第 1 版", out)
        self.assertIn("--unpin", out)
        self.assertEqual(store.read("SELECT MAX(version) FROM baselines"), [(1,)])

    def test_unpin(self):
        from alert_doctor import schema
        store = self.db()
        schema.ensure_all(store)
        with mock.patch("alert_doctor.tuner.unpin_baselines") as unpin:
            code, out, _ = self.run_cli("tuner", "--unpin")
        self.assertEqual(code, 0)
        unpin.assert_called_once()
        self.assertIn("解除", out)

    def test_tuner_lists_revoked(self):
        from alert_doctor import autorules
        from alert_doctor.autorules import AutoRule
        rule = AutoRule(7, "fp-revoked", "noise", "verdict", "revoked", 0.0, None, None,
                        0, 0, 0, 0, "❌ 率過高")
        result = {"promoted": [], "expired": [], "revoked": [rule]}
        with mock.patch.object(autorules, "promote_and_expire", return_value=result):
            code, out, _ = self.run_cli("tuner")
        self.assertEqual(code, 0)
        self.assertIn("撤銷 #7", out)


class WeeklyAuditMirrorsTest(CliTestCase):
    def test_report_weekly_post(self):
        slack = FakeSlack()
        elk = mock.Mock()
        elk.search.side_effect = OSError("down")
        code, out, _ = self.run_cli("report", "--weekly", "--post", slack=slack, elk=elk)
        self.assertEqual(code, 0)
        self.assertIn("週報", out)
        self.assertIn("request_id 稽核", out)
        self.assertEqual(slack.posts[0][0], "CREPORT")

    def test_report_weekly_no_elk_skips_audit(self):
        code, out, _ = self.run_cli("report", "--weekly", "--no-elk", slack=FakeSlack())
        self.assertEqual(code, 0)
        self.assertNotIn("request_id 稽核", out)

    def test_audit_request_id(self):
        elk = mock.Mock()
        elk.search.return_value = {"hits": {"hits": [], "total": {"value": 0}}}
        slack = FakeSlack()
        code, out, _ = self.run_cli("audit-request-id", "--post", slack=slack, elk=elk)
        self.assertEqual(code, 0)
        self.assertIn("request_id 稽核", out)
        self.assertEqual(slack.posts[0][0], "CREPORT")

    def test_mirrors(self):
        with mock.patch("alert_doctor.mirrors.refresh_all", return_value={"r": ("/m/r/abc", "a" * 40)}) as ra:
            code, out, _ = self.run_cli("mirrors")
        self.assertEqual(code, 0)
        self.assertIn("r\taaaaaaaa\t/m/r/abc", out)
        self.assertIn("on_change", ra.call_args.kwargs)

    def test_mirrors_failure_exit_1(self):
        with mock.patch("alert_doctor.mirrors.refresh_all", return_value={}):
            code, out, _ = self.run_cli("mirrors")
        self.assertEqual(code, 1)
        self.assertIn("r\t失敗", out)


class V3CommandsTest(CliTestCase):
    def test_outbox_lists_pending_and_failed(self):
        from alert_doctor.store import MAX_OUTBOX_ATTEMPTS
        store = self.db()
        now = time.time()
        store.enqueue_reply(incident_id=4, channel=CHANNEL, kind="first", priority=0,
                            due_epoch=now - 45, payload={"text": "x"})
        failed = store.enqueue_reply(incident_id=5, channel=CHANNEL2, kind="analysis", priority=1,
                                     due_epoch=now, payload={"text": "y"})
        for _ in range(MAX_OUTBOX_ATTEMPTS):
            store.retry_outbox(failed, "channel_not_found\n詳細", now - 10)
        store.set_protection("overload", "intake 30/分", now - 120)
        code, out, _ = self.run_cli("outbox")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("outbox 待發 1 · 失敗 1"))
        self.assertIn("最老 CRITICAL 4", lines[0])
        self.assertIn("保護狀態:過載", out)
        self.assertIn("intake 30/分", out)
        pending = next(line for line in lines if line.startswith("⏳"))
        self.assertIn("first p0 · alerts-a · incident #4 · 已等 4", pending)
        failed_line = next(line for line in lines if line.startswith("❌"))
        self.assertIn("analysis p1 · alerts-b · incident #5", failed_line)
        self.assertIn("channel_not_found 詳細", failed_line)

    def test_outbox_empty(self):
        code, out, _ = self.run_cli("outbox")
        self.assertEqual(code, 0)
        self.assertIn("沒有待發或失敗的貼文", out)

    def test_archive_report_uses_real_archive(self):
        from alert_doctor.archive import Archive
        from alert_doctor.models import Incident
        path = os.path.join(self.tmp.name, "arch.db")
        Path(self.config).write_text(Path(self.config).read_text().replace(
            "[[channels]]", f'archive_db_path = "{path}"\n[[channels]]', 1))
        archive = Archive(path)
        now = time.time()
        incident = Incident(id=7, fingerprint="fp-abcdef123", group_fp="g", check_code="c",
                            check_title="t", channel=CHANNEL, anchor_ts="1.0",
                            first_epoch=now - 60, last_epoch=now - 30, count=3,
                            analysis_state="done")
        archive.record_verdict(incident, {"category": "code_bug", "evidence": [
            {"type": "code", "repo": "r", "file": "app/x.py", "line": 3}]}, "sonnet", {"r": "a" * 40}, now)
        code, out, _ = self.run_cli("archive-report", "--days", "7")
        self.assertEqual(code, 0, out)
        self.assertIn("熱點檔案(近 7 天", out)
        self.assertIn("1. r:app/x.py · 1 個 incident", out)
        self.assertIn("重複發生的錯誤", out)

    def test_archive_report_without_archive_file(self):
        Path(self.config).write_text(Path(self.config).read_text().replace(
            "[[channels]]", f'archive_db_path = "{self.tmp.name}/none.db"\n[[channels]]', 1))
        code, out, _ = self.run_cli("archive-report")
        self.assertEqual(code, 1)
        self.assertIn("還不存在", out)

    def test_watchdog_snapshot_info(self):
        task = types.SimpleNamespace(enabled=True)
        self.snapshot = types.SimpleNamespace(exported_at="2026-10-20T05:37:02+00:00",
                                              tasks=lambda: [task, types.SimpleNamespace(enabled=False)])
        self.db().bump_counter("unknown_task", 2, time.time())
        code, out, _ = self.run_cli("watchdog-snapshot-info")
        self.assertEqual(code, 0)
        self.assertIn("匯出時間:2026-10-20T05:37:02+00:00", out)
        self.assertIn("排程:2 支(啟用 1)", out)
        self.assertIn("快照裡沒有的排程 ID:2 次", out)

    def test_watchdog_snapshot_info_missing(self):
        self.snapshot = None
        code, out, _ = self.run_cli("watchdog-snapshot-info")
        self.assertEqual(code, 1)
        self.assertIn("找不到", out)

    def test_snapshot_path_resolution(self):
        from alert_doctor.config import load_config
        cfg = load_config(self.config)
        self.assertEqual(os.path.realpath(cli._snapshot_path(cfg)),
                         os.path.realpath(os.path.join(self.tmp.name, "watchdog_snapshot", "tasks.json")))



class ElkQueryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []

    def runner(self, stdout="10/20 14:00:01 | boom\n", stderr="# note\n", code=0):
        def run(cmd, **kw):
            self.calls.append((cmd, kw))
            return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        return run

    def query(self, argv, run):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_elk_query(argv, run=run, cli_path="/x/elk.py", cwd=self.tmp.name)
        return code, out.getvalue(), err.getvalue()

    def results(self):
        return Path(self.tmp.name, "elk_results.txt").read_text()

    def test_runs_elk_cli_prints_and_appends_with_header(self):
        argv = ["recent", "T+1 notify", "--from", "2026-10-20T14:00:00+08:00", "--size", "5"]
        code, out, err = self.query(argv, self.runner())
        self.assertEqual(code, 0)
        self.assertEqual(out, "10/20 14:00:01 | boom\n")
        self.assertEqual(err, "# note\n")
        self.assertEqual(self.calls[0][0], [sys.executable, "/x/elk.py", *argv])
        self.assertEqual(self.results(),
                         "$ elk-query recent 'T+1 notify' --from 2026-10-20T14:00:00+08:00 --size 5\n"
                         "10/20 14:00:01 | boom\n# note\n\n")
        self.query(["count", "x"], self.runner(stdout="3\n", stderr=""))
        self.assertTrue(self.results().endswith("$ elk-query count x\n3\n\n"))
        self.assertIn("boom", self.results())

    def test_failure_exit_code_passed_through_and_recorded(self):
        code, _, _ = self.query(["count", "x"], self.runner(stdout="", stderr="401\n", code=1))
        self.assertEqual(code, 1)
        self.assertIn("401", self.results())

    def test_launch_error_is_recorded_not_raised(self):
        def run(cmd, **kw):
            raise FileNotFoundError("no elk.py")
        code, _, err = self.query(["count", "x"], run)
        self.assertEqual(code, 1)
        self.assertIn("no elk.py", err)
        self.assertIn("no elk.py", self.results())

    def test_unknown_subcommand_refused_without_running(self):
        for argv in ([], ["delete", "x"], ["--from", "now-1h"]):
            code, _, err = self.query(argv, self.runner())
            self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])
        self.assertFalse(Path(self.tmp.name, "elk_results.txt").exists())

    def test_main_passes_args_through_untouched(self):
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, cwd)
        with mock.patch.object(cli, "_elk_cli_path", return_value="/x/elk.py"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["elk-query", "count", "", "--where", "project=cms", "--config", "y"],
                            elk_runner=self.runner())
        self.assertEqual(code, 0)
        self.assertEqual(self.calls[0][0][2:], ["count", "", "--where", "project=cms", "--config", "y"])
        self.assertIn("$ elk-query count '' --where project=cms", self.results())

    def test_cli_path_from_config_with_default(self):
        from alert_doctor.config import Config
        self.assertEqual(Config.elk_cli_path,
                         "/Users/you/.claude/skills/elk-logs/scripts/elk.py")
        config = Path(self.tmp.name, "c.toml")
        config.write_text('workspace_url = "https://x"\nelk_cli_path = "/opt/elk.py"\n'
                          '[[channels]]\nid = "C"\nname = "n"\nsystems = []\n')
        with mock.patch.dict(os.environ, {"ALERT_DOCTOR_CONFIG": str(config)}):
            self.assertEqual(cli._elk_cli_path(), "/opt/elk.py")
        with mock.patch.dict(os.environ, {"ALERT_DOCTOR_CONFIG": str(config) + ".missing"}):
            self.assertEqual(cli._elk_cli_path(), Config.elk_cli_path)


def watchdog_text(task_pk, message, level=40, title="[L3] 請求逾時", code="code118"):
    extra = {"task_id": "t", "code": code, "vargs": [],
             "vkwargs": {"crontab_task_pk": task_pk},
             "check_script": title, "result": {"level": level, "message": message}}
    return f"{title}\n{extra!r}"


class ArchiveBackfillTest(CliTestCase):
    def setUp(self):
        super().setUp()
        self.archive_path = os.path.join(self.tmp.name, "arch.db")
        Path(self.config).write_text(Path(self.config).read_text().replace(
            "[[channels]]", f'archive_db_path = "{self.archive_path}"\n[[channels]]', 1))
        labels = {118: "[官網] 請求逾時"}
        self.snapshot = types.SimpleNamespace(
            task_for_alert=lambda alert: types.SimpleNamespace(
                label=labels[alert.extra["vkwargs"]["crontab_task_pk"]])
            if alert.extra.get("vkwargs", {}).get("crontab_task_pk") in labels else None)
        now = time.time()
        self.messages = [
            {"ts": f"{now - 3600:.6f}", "text": watchdog_text(118, "GET /a 逾時 3 秒")},
            {"ts": f"{now - 1800:.6f}", "text": watchdog_text(118, "GET /a 逾時 9 秒")},
            {"ts": f"{now - 900:.6f}", "text": watchdog_text(118, "GET /b 逾時 9 秒")},
            {"ts": f"{now - 600:.6f}", "text": watchdog_text(7, "磁碟 91%", title="[L2] 磁碟")},
            {"ts": f"{now - 300:.6f}", "text": "隨便一句話"},
            {"ts": f"{now - 200:.6f}", "text": "回覆", "thread_ts": f"{now - 3600:.6f}"},
        ]
        self.slack = FakeSlack(self.messages)

    def rows(self):
        import sqlite3
        con = sqlite3.connect(self.archive_path)
        try:
            return con.execute("SELECT channel, task_pk, task_label, category, incident_id, "
                               "error_key, backfilled FROM occurrences ORDER BY epoch").fetchall()
        finally:
            con.close()

    def test_records_parsed_messages_without_incidents_and_prints_summary(self):
        from alert_doctor.archive import error_key
        code, out, err = self.run_cli("archive-backfill", "--days", "30", slack=self.slack)
        self.assertEqual(code, 0, err)
        rows = self.rows()
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0][:5], (CHANNEL, 118, "[官網] 請求逾時", "historical", None))
        self.assertEqual(rows[3][2], "[L2] 磁碟")
        self.assertEqual(rows[0][5], error_key(118, "code118", 40, "GET /a 逾時 3 秒", "sys"))
        self.assertEqual(rows[0][5], rows[1][5])
        self.assertNotEqual(rows[0][5], rows[2][5])
        self.assertEqual({r[6] for r in rows}, {1})
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "data", "alert_doctor.db")))
        self.assertEqual(self.slack.posts, [])
        self.assertIn("== alerts-a", out)
        self.assertIn("訊息 5 則 · 可解析 4 則 · 新增 4 則(已存在 0 則) · 不同錯誤 3 種", out)
        self.assertRegex(out, r"1\. \[官網\] 請求逾時 · 2 次 · [0-9a-f]{8} · GET /a 逾時 <n> 秒")
        self.assertIn("== alerts-b", out)

    def test_key_uses_the_check_system_like_the_collector(self):
        from alert_doctor.archive import error_key
        checks = os.path.join(self.tmp.name, "checks.toml")
        Path(checks).write_text('[checks."code118"]\nsystem = "pe"\n')
        Path(self.config).write_text(Path(self.config).read_text().replace(
            str(REPO / "checks.example.toml"), checks))
        code, _, err = self.run_cli("archive-backfill", "--days", "30", slack=self.slack)
        self.assertEqual(code, 0, err)
        rows = self.rows()
        self.assertEqual(rows[0][5], error_key(118, "code118", 40, "GET /a 逾時 3 秒", "pe"))
        self.assertEqual(rows[3][5], error_key(7, "code118", 40, "磁碟 91%", "pe"))

    def test_rerun_is_idempotent(self):
        self.run_cli("archive-backfill", slack=self.slack)
        code, out, _ = self.run_cli("archive-backfill", slack=self.slack)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.rows()), 4)
        self.assertIn("新增 0 則(已存在 4 則)", out)

    def test_dry_run_writes_nothing(self):
        code, out, _ = self.run_cli("archive-backfill", "--dry-run", slack=self.slack)
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.archive_path))
        self.assertIn("dry-run", out)
        self.assertIn("不同錯誤 3 種", out)

    def test_channel_filter_and_unknown_channel(self):
        code, out, _ = self.run_cli("archive-backfill", "--channel", CHANNEL2, slack=self.slack)
        self.assertEqual(code, 0)
        self.assertNotIn("alerts-a", out)
        self.assertFalse(os.path.exists(self.archive_path) and self.rows())
        code, _, err = self.run_cli("archive-backfill", "--channel", "CNOPE", slack=self.slack)
        self.assertEqual(code, 2)
        self.assertIn("CNOPE", err)

    def test_history_retries_after_rate_limit(self):
        from alert_doctor.slack_io import SlackRateLimited
        calls, slept = [], []

        def history(token, channel, oldest, limit=200):
            calls.append(channel)
            if len(calls) < 3:
                raise SlackRateLimited(7)
            return ["ok"]
        slack = types.SimpleNamespace(history=history)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli._history_with_retry(slack, "t", "C", "0", sleep=slept.append),
                             ["ok"])
        self.assertEqual(slept, [7, 7])

    def test_split_alert_is_reassembled_before_parsing(self):
        from tests.test_fragments import real_messages
        now = time.time()
        split = real_messages(shift=now - 600 - 1_790_000_000.0)
        slack = FakeSlack(split)
        code, out, err = self.run_cli("archive-backfill", "--dry-run", "--channel", CHANNEL,
                                      slack=slack)
        self.assertEqual(code, 0, err)
        self.assertIn("訊息 11 則 · 併回分段 9 則 · 可解析 2 則", out)
        self.assertIn("path=/user/pkms/get_credit_data/", out)
        code, out, err = self.run_cli("archive-backfill", "--channel", CHANNEL, slack=slack)
        self.assertEqual(code, 0, err)
        rows = self.rows()
        self.assertEqual([r[1] for r in rows], [118, 118])
        self.assertNotEqual(rows[0][5], rows[1][5])

    def test_history_oldest_follows_days(self):
        seen = []
        self.slack.history = lambda token, channel, oldest, limit=200: seen.append(float(oldest)) or []
        self.run_cli("archive-backfill", "--days", "3", slack=self.slack)
        self.assertAlmostEqual(seen[0], time.time() - 3 * 86400, delta=60)



class KnownCommandTest(CliTestCase):
    def setUp(self):
        super().setUp()
        Path(self.config).write_text(Path(self.config).read_text().replace(
            "[[channels]]", f'known_path = "{REPO / "known.example.toml"}"\n[[channels]]', 1))

    def test_list_runs_through_main_with_config(self):
        code, out, err = self.run_cli("known", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("資料庫固定錯誤 0 筆", out)
        self.assertIn("ddsc-nightly-restart", out)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "data", "alert_doctor.db")))

    def test_add_then_show_and_missing_entry_exit_code(self):
        code, out, _ = self.run_cli("known", "add", "x1", "--title", "測試固定錯誤")
        self.assertEqual(code, 0)
        self.assertIn("已新增固定錯誤 x1", out)
        code, out, _ = self.run_cli("known", "show", "x1")
        self.assertEqual(code, 0)
        self.assertIn("測試固定錯誤", out)
        code, out, _ = self.run_cli("known", "show", "nope")
        self.assertEqual(code, 1)

    def test_missing_subcommand_is_usage_error(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli("known")
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
