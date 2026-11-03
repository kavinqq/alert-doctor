from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path

from alert_doctor import schema, slack_io
from alert_doctor.analyzer import ELK_FAILED_HEADER, ELK_QUERY_HEADER
from alert_doctor.config import Config, get_secret, load_config
from alert_doctor.models import Evidence
from alert_doctor.parse import parse_message
from alert_doctor.report import TAIPEI, build_daily_report, build_weekly_report, health_problems
from alert_doctor.store import Store

log = logging.getLogger("alert_doctor")
SAMPLE_CHARS = 120
# health runs every 10 minutes; reposting an unchanged problem each time would make
# alert-doctor itself one more noisy channel.
HEALTH_REPOST_SECONDS = 3600
REPLAY_SETTLE_ROUNDS = 5
# After the last alert, keep running the publisher this long so settle/update posts show up.
REPLAY_DRAIN_SECONDS = 15 * 60
REPLAY_MAX_PUMP_STEPS = 100_000
OUTBOX_LIST_LIMIT = 50
BACKFILL_TOP = 10
HISTORY_ATTEMPTS = 4
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ELK_RESULTS_FILE = "elk_results.txt"
ELK_QUERY_LIMIT = 10
# 10 queries x 45 s = 450 s fits inside the default llm_timeout (600 s) with time left to
# read code and write the verdict; one slow query must not eat the whole session.
ELK_QUERY_TIMEOUT = 45
ELK_DEFAULT_INDEX = "logs-generic-default"
PHRASE_SUBCOMMANDS = frozenset({"count", "recent", "timeline"})
# elk.py answers exactly up to this many AND candidates and gives a ⚠ upper bound beyond.
# Its CJK path verifies ~4 candidates/ms in parallel locally, but sparse ones go to ES at
# ~1 ms each, so 50,000 keeps an exact answer inside ELK_QUERY_TIMEOUT in the worst case.
PHRASE_EXACT_LIMIT = 50_000
RECENT_DEFAULT_SIZE = "20"
RECENT_HOST_COLUMN = "log.host|log.extra.server_ip|host.name"
RECENT_MESSAGE_CHARS = "1000"
APPROX_MARK = "⚠ 近似上界"
TIME_FORMAT_HELP = "時間只接受 2026-10-20T14:00:00+08:00(帶 +08:00)或 now / now-2h / now-30m / now-1d"
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uf900-\ufaff\uff00-\uffef]")
_RELATIVE_TIME = re.compile(r"now(?:[+-]\d+[smhd])?(?:/[smhd])?")
_INTERVAL = re.compile(r"\d+[smhd]")
_SUCCESS_HEADER = re.compile(rf"^{re.escape(ELK_QUERY_HEADER)} ", re.M)
# Every elk-logs subcommand only searches; anything else is refused before it reaches ELK.
ELK_SUBCOMMANDS = frozenset({"api", "errors", "count", "timeline", "agg", "recent", "raw", "indices"})


def _fmt_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%m-%d %H:%M")


def _open_store(cfg: Config) -> Store:
    os.makedirs(os.path.dirname(cfg.db_path), exist_ok=True)
    store = Store(cfg.db_path)
    schema.ensure_all(store)
    return store


def _bot_token(cfg: Config) -> str:
    return get_secret(cfg.keychain_service, "bot_token")


def _app_token(cfg: Config) -> str:
    return get_secret(cfg.keychain_service, "app_token")


SOURCE_BOT_ACCOUNT = "watchdog_bot_token"


def _source_bot_token(cfg: Config) -> str | None:
    """Rocket Message Bot's token, only needed to delete green alerts; None turns that off."""
    if not cfg.purge_green:
        return None
    try:
        return get_secret(cfg.keychain_service, SOURCE_BOT_ACCOUNT)
    except RuntimeError as exc:
        logging.getLogger(__name__).warning("綠燈刪除已開啟但讀不到 %s:%s", SOURCE_BOT_ACCOUNT, exc)
        return None


class NoElk:
    """Every query fails, exactly like an ELK outage: nothing may be judged noise on it."""

    def gather(self, spec, until, variables) -> Evidence:
        return Evidence(query_ok=False, window_from="", window_to="", error="--no-elk")

    def search(self, index, body) -> dict:
        raise RuntimeError("--no-elk")


def _make_elk(cfg: Config):
    from alert_doctor.elk_client import ElkClient
    return ElkClient(cfg.elk_url, cfg.elk_user,
                     lambda: get_secret(cfg.elk_keychain_service), cfg.elk_timeout)


def _stop_event() -> threading.Event:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    return stop


def _notify(text: str) -> None:
    script = f'display notification {json.dumps(text, ensure_ascii=False)} with title "alert-doctor"'
    subprocess.run(["osascript", "-e", script], check=False, capture_output=True)


def _build_collector(cfg: Config, store: Store, slack, elk, bot_token: str, clock=time.time,
                     app_token: str | None = None, source_bot_token: str | None = None):
    from alert_doctor.checks import load_checks
    from alert_doctor.collector import Collector
    from alert_doctor.rules import load_rules
    return Collector(cfg, store, slack, elk, load_rules(cfg.rules_path),
                     load_checks(cfg.checks_path), bot_token, clock=clock, app_token=app_token,
                     source_bot_token=source_bot_token)


# ---- wiring that depends on Collector / Analyzer signatures -----------------

def cmd_collector(cfg: Config, args, slack, elk) -> int:
    store = _open_store(cfg)
    collector = _build_collector(cfg, store, slack, elk or _make_elk(cfg), _bot_token(cfg),
                                 app_token=_app_token(cfg),
                                 source_bot_token=_source_bot_token(cfg))
    collector.run_forever(_stop_event().is_set)
    return 0


def cmd_analyzer(cfg: Config, args, slack, elk) -> int:
    from alert_doctor.analyzer import Analyzer
    from alert_doctor.checks import load_checks
    store = _open_store(cfg)
    analyzer = Analyzer(cfg, store, slack, _bot_token(cfg), load_checks(cfg.checks_path),
                        source_bot_token=_source_bot_token(cfg))
    analyzer.run_forever(_stop_event())
    return 0


def cmd_backfill(cfg: Config, args, slack, elk) -> int:
    store = _open_store(cfg)
    collector = _build_collector(cfg, store, slack, elk or _make_elk(cfg), _bot_token(cfg))
    collector.start()
    added = collector.backfill(since=time.time() - args.hours * 3600)
    print(f"backfill 新增 {added} 則;只寫入資料庫,由執行中的 collector 負責處理與回覆")
    return 0


def _categories(store: Store, latest: float) -> dict[str, int]:
    totals: dict[str, int] = {}
    for cov in store.coverage_all(0, latest + 10).values():
        for category, n in cov["by_category"].items():
            totals[category] = totals.get(category, 0) + n
    return totals


class _SimClock:
    """Replay time: jumps from alert to alert and through outbox due times, never sleeps."""

    def __init__(self, start: float):
        self.now = start

    def __call__(self) -> float:
        return self.now


class _PostPrinter:
    """Prints what the dry-run Slack received since the last flush, in order."""

    def __init__(self, cfg: Config, store: Store, dry, clock: _SimClock):
        self.cfg, self.store, self.dry, self.clock = cfg, store, dry, clock
        self.seen = 0
        self.posts = self.tagged = self.reactions = 0

    def _channel_name(self, channel: str) -> str:
        spec = self.cfg.channel(channel)
        return spec.name if spec else channel

    def flush(self) -> None:
        calls, self.seen = self.dry.calls[self.seen:], len(self.dry.calls)
        for name, call in calls:
            if name == "post_message":
                self.posts += 1
                tagged = "<@" in call["text"] or "<!subteam^" in call["text"]
                self.tagged += tagged
                reply = self.store.lookup_reply(call["channel"], call["ts"])
                kind = reply[2] if reply else "?"
                print(f"  📤 {_fmt_clock(self.clock.now)} {self._channel_name(call['channel'])}"
                      f" · {kind} · thread {call['thread_ts'] or '(頻道)'}" + (" · 有 tag" if tagged else ""))
                print(call["text"])
            elif name in ("add_reaction", "remove_reaction"):
                self.reactions += 1
                sign = "+" if name == "add_reaction" else "-"
                print(f"reactions: {sign}{call['name']} on {call['ts']}")


def _fmt_clock(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%H:%M:%S")


def _next_due(store: Store) -> float | None:
    return store.read("SELECT MIN(due_epoch) FROM outbox WHERE status='pending'")[0][0]


def _pump(store: Store, publisher, clock: _SimClock, until: float, printer: _PostPrinter) -> None:
    """Run the publisher at every due time up to `until`, as `run_forever` would each second."""
    for _ in range(REPLAY_MAX_PUMP_STEPS):
        due = _next_due(store)
        if due is None or due > until:
            return
        before = due
        clock.now = max(clock.now, due)
        publisher.process(clock.now)
        printer.flush()
        after = _next_due(store)
        # Leased or spaced-out rows keep their due time; time has to move for them to clear.
        if after is not None and after <= before:
            clock.now += 1
    log.warning("replay:publisher 推進 %d 步仍有待發,停止", REPLAY_MAX_PUMP_STEPS)


def cmd_replay(cfg: Config, args, slack, elk) -> int:
    from alert_doctor.budget import Budgets
    from alert_doctor.dryrun import DryRunSlack
    from alert_doctor.publisher import Publisher
    with open(args.file, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    if not lines:
        print("檔案是空的", file=sys.stderr)
        return 2
    default_channel = cfg.channels[0].id
    for item in lines:
        channel = item.get("channel", default_channel)
        if channel not in cfg.channel_ids:
            print(f"錯誤:replay 資料的頻道 {channel} 不在設定的頻道內", file=sys.stderr)
            return 2
    items = sorted(lines, key=lambda i: float(i["ts"]))
    dry = DryRunSlack()
    store = Store(":memory:")
    clock = _SimClock(float(items[0]["ts"]))
    elk = NoElk() if args.no_elk else (elk or _make_elk(cfg))
    collector = _build_collector(cfg, store, dry, elk, "dry-run-token", clock=clock)
    collector.start()
    # Replay is a simulation: real archive counts would describe production, not the replay.
    publisher = Publisher(cfg, store, dry, "dry-run-token", Budgets(cfg), clock, archive=None)
    printer = _PostPrinter(cfg, store, dry, clock)
    for item in items:
        ts = float(item["ts"])
        _pump(store, publisher, clock, ts, printer)
        clock.now = max(clock.now, ts)
        channel = item.get("channel", default_channel)
        latest = clock.now
        before = _categories(store, latest)
        alert = parse_message(channel, item["ts"], item["text"], redact_pii=cfg.redact_pii)
        collector.on_socket_event("events_api", {"event": {
            "type": "message", "channel": channel, "ts": item["ts"], "text": item["text"]}})
        for _ in range(REPLAY_SETTLE_ROUNDS):
            if not collector.process_pending():
                break
        after = _categories(store, latest)
        category = next((c for c, n in after.items() if n > before.get(c, 0)), "(未處理)")
        print(f"--- {cfg.channel(channel).name} · ts {item['ts']} · {_fmt_clock(ts)}"
              f" · {alert.check_title or '(無標題)'} · category={category}")
        printer.flush()
        publisher.process(clock.now)
        printer.flush()
    _pump(store, publisher, clock, clock.now + REPLAY_DRAIN_SECONDS, printer)
    stats = store.outbox_stats(clock.now)
    protection = store.get_protection()
    counters = " · ".join(f"{name} {store.counter_sum(name, 0, clock.now)}"
                          for name in ("intake", "elk_skipped", "llm_deferred", "unknown_task"))
    print(f"=== 統計:{len(items)} 則告警 · Slack 發文 {printer.posts} 則(有 tag {printer.tagged})"
          f" · reactions {printer.reactions} · outbox 待發 {stats['pending']} / 失敗 {stats['failed']}"
          f" · 保護狀態 {protection['state']} · {counters}")
    return 0


# ---- commands with no Collector / Analyzer dependency -----------------------

def _post_report(cfg: Config, slack, text: str, name: str) -> int:
    """Post to report_channel, or write `<report_dir>/<name>.md` when no channel is set."""
    if cfg.report_channel:
        slack.post_message(_bot_token(cfg), cfg.report_channel, text)
        return 0
    path = Path(cfg.report_dir, f"{name}.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"報告已寫入 {path}", file=sys.stderr)
    return 0


def _audit_text(cfg: Config, elk) -> str:
    from alert_doctor.correlate import audit_request_ids
    try:
        return audit_request_ids(elk, cfg.systems, time.time())
    except Exception as exc:
        return f"稽核失敗:{type(exc).__name__}: {exc}"


def cmd_report(cfg: Config, args, slack, elk) -> int:
    if args.weekly:
        audit = None if args.no_elk else _audit_text(cfg, elk or _make_elk(cfg))
        text = build_weekly_report(_open_store(cfg), cfg, time.time(), audit=audit)
        name = f"weekly-{datetime.now(TAIPEI).date()}"
    else:
        day = date.fromisoformat(args.date) if args.date else datetime.now(TAIPEI).date() - timedelta(days=1)
        text = build_daily_report(_open_store(cfg), cfg, day)
        name = f"daily-{day}"
    print(text)
    return _post_report(cfg, slack, text, name) if args.post else 0


def cmd_audit_request_id(cfg: Config, args, slack, elk) -> int:
    text = "request_id 稽核\n" + _audit_text(cfg, elk or _make_elk(cfg))
    print(text)
    return _post_report(cfg, slack, text, f"audit-{datetime.now(TAIPEI).date()}") if args.post else 0


def _rule_line(rule) -> str:
    return f"#{rule.id} {rule.kind} {rule.fingerprint[:8]}({rule.reason})"


def cmd_tuner(cfg: Config, args, slack, elk) -> int:
    from alert_doctor import autorules, tuner
    store = _open_store(cfg)
    if args.unpin:
        tuner.unpin_baselines(store)
        print("已解除基線釘選,下次 tuner 會重新計算新版本")
        return 0
    if args.rollback is not None:
        tuner.rollback_baselines(store, args.rollback)
        print(f"基線已回滾到第 {args.rollback} 版(刪除較新的版本);"
              "在執行 tuner --unpin 之前不會再產生新基線")
        return 0
    now = time.time()
    version = tuner.recompute_baselines(store, now)
    proposed = autorules.propose_from_verdicts(store, now)
    changed = autorules.promote_and_expire(store, now, ttl_days=cfg.auto_rule_ttl_days)
    print(f"基線版本:{version or '尚無(樣本不足)'}")
    print(f"新增 shadow 規則 {len(proposed)}")
    for rule in proposed:
        print(f"  {_rule_line(rule)}")
    for rule in changed["promoted"]:
        print(f"轉正 {_rule_line(rule)}")
    for rule in changed["expired"]:
        print(f"到期 {_rule_line(rule)}")
    for rule in changed.get("revoked", ()):
        print(f"撤銷 {_rule_line(rule)}")
    store.beat("tuner", time.time())
    return 0


def cmd_mirrors(cfg: Config, args, slack, elk) -> int:
    from alert_doctor.analyzer import refresh_mirrors
    store = _open_store(cfg)
    results = refresh_mirrors(cfg, store, time.time())
    for repo_id in cfg.repos:
        if repo_id in results:
            path, sha = results[repo_id]
            print(f"{repo_id}\t{sha[:8]}\t{path}")
        else:
            print(f"{repo_id}\t失敗(見 log)")
    return 0 if len(results) == len(cfg.repos) else 1


def _snapshot_path(cfg: Config) -> str:
    from alert_doctor.analyzer import DEFAULT_SNAPSHOT_PATH, PROJECT_ROOT
    path = getattr(cfg, "watchdog_snapshot_path", None) or DEFAULT_SNAPSHOT_PATH
    return path if os.path.isabs(path) else str(PROJECT_ROOT / path)


def _load_snapshot(cfg: Config):
    """None when the snapshot file is missing or unreadable."""
    try:
        from alert_doctor.watchdog import load_snapshot
        return load_snapshot(_snapshot_path(cfg))
    except Exception as exc:
        log.warning("watchdog 快照無法讀取:%s", exc)
        return None


def cmd_wipe(cfg: Config, args, slack, elk) -> int:
    """Archive then (with --apply) delete Rocket alerts and our posts in the monitoring channels."""
    from alert_doctor.wipe import wipe_channel
    store = _open_store(cfg)
    bot_token = _bot_token(cfg)
    our_bot_id = slack.auth_test(bot_token)["bot_id"]
    source = get_secret(cfg.keychain_service, SOURCE_BOT_ACCOUNT) if args.apply else None
    stamp = datetime.now(TAIPEI).strftime("%Y-%m-%d-%H%M%S")
    archive_dir = Path(cfg.report_dir, f"wipe-{stamp}")
    names = {c.id: c.name for c in cfg.channels}
    for channel in args.channel or list(names):
        result = wipe_channel(store, slack, cfg, channel, bot_token=bot_token,
                              source_bot_token=source, our_bot_id=our_bot_id,
                              archive_dir=str(archive_dir), apply=args.apply, now=time.time())
        verb = "已刪" if args.apply else "將刪"
        print(f"{names.get(channel, channel)}:{verb} 告警 {result['alerts']} · 我們的訊息 {result['ours']}"
              f" · 保留 {result['kept']}"
              + (f" · 成功 {result['deleted']} · 失敗 {result['failed']}"
                 f" · 期間有人留言而跳過 {result['skipped']}" if args.apply else "")
              + f"\n  封存:{result['archive']}")
    if not args.apply:
        print("預演而已,沒有刪任何訊息;確認後加 --apply")
    return 0


def cmd_health(cfg: Config, args, slack, elk) -> int:
    from alert_doctor import replies
    from alert_doctor.checks import load_checks
    unreadable = []
    try:
        checks = load_checks(cfg.checks_path)
    except Exception as exc:
        checks = None
        unreadable = [f"checks.toml 無法讀取:{type(exc).__name__}: {exc}"]
    if cfg.purge_green and _source_bot_token(cfg) is None:
        unreadable.append(f"綠燈刪除已開啟但讀不到 Keychain {SOURCE_BOT_ACCOUNT},目前照舊回覆分析")
    problems = health_problems(_open_store(cfg), cfg, time.time(), checks=checks,
                               snapshot=_load_snapshot(cfg)) + unreadable
    if not problems:
        print("ok")
        return 0
    text = replies.health_alert(problems)
    print(text)
    if args.post and _health_should_post(cfg, len(problems), time.time()):
        if cfg.report_channel:
            slack.post_message(_bot_token(cfg), cfg.report_channel, text)
        _notify(f"健康檢查異常:{problems[0]}")
    return 1


def _health_should_post(cfg: Config, count: int, now: float) -> bool:
    """Post when the number of problems changed or an hour passed since the last post."""
    path = f"{cfg.db_path}.health.json"
    try:
        with open(path) as f:
            last = json.load(f)
        if last.get("count") == count and now - last.get("at", 0) < HEALTH_REPOST_SECONDS:
            return False
    except (OSError, ValueError):
        pass
    with open(path, "w") as f:
        json.dump({"count": count, "at": now}, f)
    return True


def cmd_outbox(cfg: Config, args, slack, elk) -> int:
    store = _open_store(cfg)
    now = time.time()
    stats = store.outbox_stats(now)
    protection = store.get_protection()
    print(f"outbox 待發 {stats['pending']} · 失敗 {stats['failed']} · "
          f"最老待發 {_fmt_seconds(stats['oldest_pending_age'])} · "
          f"最老 CRITICAL {_fmt_seconds(stats['oldest_critical_age'])}")
    if stats["by_kind"]:
        print("待發種類:" + "、".join(f"{k} {n}" for k, n in sorted(stats["by_kind"].items())))
    state = "過載" if protection["state"] == "overload" else "正常"
    since = f",自 {_fmt_time(protection['since'])}" if protection.get("since") else ""
    print(f"保護狀態:{state}{since}{(' · ' + protection['reason']) if protection.get('reason') else ''}")
    rows = store.read(
        "SELECT id, status, kind, priority, channel, incident_id, due_epoch, attempts, last_error"
        " FROM outbox WHERE status IN ('pending', 'failed')"
        " ORDER BY status='failed', priority, due_epoch, id LIMIT ?", (args.limit,))
    for row_id, status, kind, priority, channel, incident_id, due, attempts, error in rows:
        spec = cfg.channel(channel)
        wait = f"已等 {_fmt_seconds(now - due)}" if due <= now else f"{_fmt_time(due)} 到期"
        line = (f"{'❌ 失敗' if status == 'failed' else '⏳ 待發'} #{row_id} {kind} p{priority}"
                f" · {spec.name if spec else channel} · incident #{incident_id} · {wait}"
                f" · 嘗試 {attempts} 次")
        if error:
            line += f" · {' '.join(error.split())[:120]}"
        print(line)
    if not rows:
        print("沒有待發或失敗的貼文")
    return 0


def _fmt_seconds(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 120:
        return f"{int(seconds)} 秒"
    if seconds < 7200:
        return f"{int(seconds // 60)} 分鐘"
    return f"{seconds / 3600:.1f} 小時"


def _archive_path(cfg: Config) -> str:
    path = getattr(cfg, "archive_db_path", None) or os.path.join(
        os.path.dirname(cfg.db_path), "error_archive.db")
    return os.path.abspath(path)


def cmd_archive_report(cfg: Config, args, slack, elk) -> int:
    path = _archive_path(cfg)
    if not os.path.exists(path):
        print(f"錯誤資料庫還不存在:{path}(collector / analyzer 寫入第一筆後才會建立)")
        return 1
    from alert_doctor.archive import Archive
    archive = Archive(path)
    now = time.time()
    hotspots = archive.hotspots(args.days, now)
    print(f"🔥 熱點檔案(近 {args.days} 天,依 incident 數)")
    for i, row in enumerate(hotspots, 1):
        last = row.get("last_epoch")
        print(f"{i}. {row.get('repo')}:{row.get('file')} · {row.get('incidents')} 個 incident"
              + (f" · 最近 {_fmt_time(last)}" if last else ""))
    if not hotspots:
        print("(沒有引用到程式碼的分析)")
    recurring = archive.recurring(args.days, now)
    print(f"🔁 重複發生的錯誤(近 {args.days} 天)")
    for i, row in enumerate(recurring, 1):
        fp = str(row.get("fingerprint") or "")[:8]
        print(f"{i}. {row.get('task_label') or '(無排程名稱)'} · {fp} · {row.get('weeks')} 週"
              f" · {row.get('occurrences')} 則 · {row.get('incidents')} 個 incident")
    if not recurring:
        print("(沒有跨週重複的錯誤)")
    return 0


def _history_with_retry(slack, token: str, channel: str, oldest: str, sleep=time.sleep) -> list:
    for _ in range(HISTORY_ATTEMPTS - 1):
        try:
            return slack.history(token, channel, oldest)
        except slack_io.SlackRateLimited as exc:
            print(f"Slack 限流,{exc.retry_after} 秒後重試", file=sys.stderr)
            sleep(exc.retry_after)
    return slack.history(token, channel, oldest)


def _task_pk(alert) -> int | None:
    vkwargs = alert.extra.get("vkwargs") if isinstance(alert.extra, dict) else None
    try:
        return int(vkwargs["crontab_task_pk"])
    except (TypeError, KeyError, ValueError):
        return None


def _task_label(alert, snapshot) -> str:
    try:
        task = snapshot.task_for_alert(alert) if snapshot is not None else None
    except Exception as exc:
        log.warning("快照查詢排程失敗:%s", exc)
        task = None
    return task.label if task is not None else alert.check_title


def _is_top_level_alert(message: dict, source_bot_ids=()) -> bool:
    from alert_doctor.collector import ELIGIBLE_SUBTYPES, is_source_message
    thread_ts = message.get("thread_ts")
    return (message.get("subtype") in ELIGIBLE_SUBTYPES and bool(message.get("ts"))
            and (not thread_ts or thread_ts == message.get("ts"))
            and is_source_message(message, source_bot_ids))


def cmd_archive_backfill(cfg: Config, args, slack, elk) -> int:
    """Rebuild occurrence history from Slack into the error archive only: no incidents,
    outbox rows or posts, and the operational store is never opened."""
    from alert_doctor import fragments
    from alert_doctor.archive import Archive, error_key
    from alert_doctor.checks import load_checks, lookup_check
    from alert_doctor.fingerprint import signature
    join_seconds = getattr(cfg, "fragment_join_seconds", fragments.DEFAULT_JOIN_SECONDS)
    channels = args.channel or [c.id for c in cfg.channels]
    unknown = [c for c in channels if c not in cfg.channel_ids]
    if unknown:
        print(f"錯誤:頻道不在設定內:{', '.join(unknown)}", file=sys.stderr)
        return 2
    archive = None if args.dry_run else Archive(_archive_path(cfg))
    snapshot = _load_snapshot(cfg)
    checks = load_checks(cfg.checks_path) if os.path.exists(cfg.checks_path) else {}
    token = _bot_token(cfg)
    oldest = f"{time.time() - args.days * 86400:.6f}"
    if args.dry_run:
        print("(dry-run:只統計,不寫入錯誤資料庫)")
    failed_total = 0
    for channel_id in channels:
        spec = cfg.channel(channel_id)
        channel_system = spec.systems[0] if spec.systems else ""
        messages = [m for m in _history_with_retry(slack, token, channel_id, oldest)
                    if _is_top_level_alert(m, cfg.source_bot_ids)]
        parsed = inserted = failed = 0
        counts: dict[str, int] = {}
        labels: dict[str, str] = {}
        samples: dict[str, str] = {}
        assembled = fragments.reassemble(messages, join_seconds)
        joined = sum(len(a.fragments) for a in assembled)
        for whole in assembled:
            alert = parse_message(channel_id, whole.head["ts"], whole.text,
                                  redact_pii=cfg.redact_pii)
            if not alert.parse_ok:
                continue
            parsed += 1
            task_pk = _task_pk(alert)
            label = _task_label(alert, snapshot)
            # Same rule as Collector._source_system, or the live key and this one would differ.
            check = lookup_check(checks, alert)
            system = check.system if check and check.system else channel_system
            key = error_key(task_pk, alert.check_code, alert.level, alert.result_message, system)
            if key is not None:
                counts[key] = counts.get(key, 0) + 1
                labels.setdefault(key, label)
                samples.setdefault(key, signature(alert.result_message)[:SAMPLE_CHARS])
            if archive is None:
                continue
            result = archive.record_occurrence(
                alert, incident=None, category="historical", severity=None,
                source_system=system, task_label=label, task_pk=task_pk, backfilled=True,
                channel_name=spec.name)
            inserted += result is True
            failed += result is None
        failed_total += failed
        print(f"== {spec.name} ({channel_id})")
        written = ("新增 —(dry-run)" if archive is None
                   else f"新增 {inserted} 則(已存在 {parsed - inserted - failed} 則)")
        line = (f"訊息 {len(messages)} 則"
                + (f" · 併回分段 {joined} 則" if joined else "")
                + f" · 可解析 {parsed} 則 · {written}"
                f" · 不同錯誤 {len(counts)} 種")
        print(line + (f" · 寫入失敗 {failed} 則" if failed else ""))
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], labels[kv[0]], kv[0]))
        for rank, (key, count) in enumerate(ranked[:BACKFILL_TOP], 1):
            print(f"{rank}. {labels[key]} · {count} 次 · {key[:8]} · {samples[key]}")
    return 1 if failed_total else 0


def cmd_watchdog_snapshot_info(cfg: Config, args, slack, elk) -> int:
    path = _snapshot_path(cfg)
    snapshot = _load_snapshot(cfg)
    if snapshot is None:
        print(f"找不到或無法讀取 watchdog 快照:{path}")
        return 1
    exported = getattr(snapshot, "exported_at", "?")
    print(f"快照:{path}")
    try:
        age = (time.time() - datetime.fromisoformat(exported).timestamp()) / 86400
        print(f"匯出時間:{exported}({age:.1f} 天前)")
    except (TypeError, ValueError):
        print(f"匯出時間:{exported}")
    tasks = snapshot.tasks()
    print(f"排程:{len(tasks)} 支(啟用 {sum(1 for t in tasks if t.enabled)})")
    scripts = os.path.join(os.path.dirname(path), "check_scripts")
    if os.path.isdir(scripts):
        print(f"檢查腳本:{len([n for n in os.listdir(scripts) if n.endswith('.py')])} 支")
    now = time.time()
    unknown = _open_store(cfg).counter_sum("unknown_task", now - 86400, now)
    print(f"近 24 小時快照裡沒有的排程 ID:{unknown} 次")
    return 0


def cmd_discover(cfg: Config, args, slack, elk) -> int:
    oldest = f"{time.time() - args.hours * 3600:.6f}"
    found = False
    for channel in cfg.channels:
        groups: dict[str, list] = {}
        for message in slack.history(_bot_token(cfg), channel.id, oldest):
            alert = parse_message(channel.id, message["ts"], message.get("text", ""), redact_pii=cfg.redact_pii)
            groups.setdefault(alert.check_code or alert.check_title or "(無法解析)", []).append(alert)
        print(f"== {channel.name} ({channel.id})")
        if not groups:
            print("這段時間沒有訊息")
            continue
        found = True
        for key, alerts in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            sample = alerts[-1].result_message.replace("\n", " ")[:SAMPLE_CHARS]
            print(f"{key}\t{len(alerts)} 則\t{_fmt_time(alerts[0].epoch)} ~ {_fmt_time(alerts[-1].epoch)}\t{sample}")
    if not found:
        print("所有頻道這段時間都沒有訊息")
    return 0


def _query_config() -> Config | None:
    """elk-query runs from an analyzer run dir, where a relative --config would not resolve."""
    path = os.environ.get("ALERT_DOCTOR_CONFIG") or str(PROJECT_ROOT / "config.toml")
    try:
        return load_config(path)
    except (OSError, ValueError):
        return None


def _elk_cli_path() -> str:
    cfg = _query_config()
    return cfg.elk_cli_path if cfg else Config.elk_cli_path


def _flag_values(argv: list[str], flag: str) -> list[str | None]:
    """Every value given for `flag` (`--f v` or `--f=v`); None when the flag ends argv."""
    values = []
    for i, arg in enumerate(argv):
        if arg == flag:
            values.append(argv[i + 1] if i + 1 < len(argv) else None)
        elif arg.startswith(flag + "="):
            values.append(arg[len(flag) + 1:])
    return values


def _valid_time(value: str | None) -> bool:
    if not value:
        return False
    if _RELATIVE_TIME.fullmatch(value):
        return True
    if "T" not in value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _is_phrase_query(argv: list[str]) -> bool:
    return (argv[0] in PHRASE_SUBCOMMANDS and len(argv) > 1
            and not argv[1].startswith("--") and bool(_CJK.search(argv[1])))


def _argument_problem(argv: list[str]) -> str | None:
    """Arguments that would certainly fail; rejected before running so they cost nothing."""
    for flag in ("--from", "--to"):
        for value in _flag_values(argv, flag):
            if not _valid_time(value):
                # A time without an offset would not fail at all: ES reads it as UTC.
                return f"{flag} {value!r} 格式錯誤。{TIME_FORMAT_HELP}"
    if not _is_phrase_query(argv):
        return None
    if not _flag_values(argv, "--from"):
        return "中文片語查詢需要 --from"
    for value in _flag_values(argv, "--interval"):
        if not value or not _INTERVAL.fullmatch(value):
            return f"--interval {value!r} 格式錯誤,用 5m / 1h / 1d 這類"
    for value in _flag_values(argv, "--where"):
        if not value or "=" not in value:
            return f"--where 格式應為 欄位=值,收到 {value!r}"
    for value in _flag_values(argv, "--size"):
        if not value or not value.isdigit():
            return f"--size 必須是正整數,收到 {value!r}"
    return None


def _without_flags(argv: list[str], *, switches=(), valued=()) -> list[str]:
    """`argv` without `switches` and `valued` flags; a valued flag takes the next token as
    its value only when that token is not itself a flag."""
    kept, skip = [], False
    for arg in argv:
        if skip and not arg.startswith("--"):
            skip = False
            continue
        skip = False
        if arg in switches or any(arg.startswith(f"{flag}=") for flag in valued):
            continue
        if arg in valued:
            skip = True
            continue
        kept.append(arg)
    return kept


def _phrase_argv(argv: list[str]) -> list[str]:
    """elk-logs CLI arguments for a CJK phrase query: count/timeline are exact up to
    PHRASE_EXACT_LIMIT candidates and a marked upper bound beyond; recent is always exact
    and keeps the `time | host | message` lines the prompt documents and the log check
    matches."""
    # The model's own --exact/--parallel would bypass PHRASE_EXACT_LIMIT (and run into the
    # subprocess timeout), --loose would return non-phrase lines; precision is decided here.
    argv = _without_flags(argv, switches=("--exact", "--loose"), valued=("--parallel",))
    extra = ["--exact-limit", str(PHRASE_EXACT_LIMIT)]
    if argv[0] == "recent":
        # Lines from recent are quoted as evidence, so they must match the phrase exactly.
        extra += ["--exact", "--show", RECENT_HOST_COLUMN, "--msg-chars", RECENT_MESSAGE_CHARS]
        if not _flag_values(argv, "--size"):
            extra += ["--size", RECENT_DEFAULT_SIZE]
    return [*argv, *extra]


def _run_phrase_query(argv: list[str], run, cli_path: str | None) -> tuple[str, str, int]:
    out, err, code = _run_elk_cli(_phrase_argv(argv), run, cli_path)
    if code != 0 or argv[0] != "count":
        return out, err, code
    lines = out.split()
    if not lines or not lines[-1].isdigit():
        return out, err, code
    bound = "≤" if APPROX_MARK in err else ""
    suffix = "(近似上界,見下方 ⚠ 說明)" if bound else ""
    return f"count: {bound}{lines[-1]}{suffix}\n", err, code


def _run_elk_cli(argv: list[str], run, cli_path: str | None) -> tuple[str, str, int]:
    cmd = [sys.executable, cli_path or _elk_cli_path(), *argv]
    try:
        done = run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                   timeout=ELK_QUERY_TIMEOUT)
        return done.stdout or "", done.stderr or "", done.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"elk-query 執行失敗:{exc}\n", 1


def cmd_elk_query(argv: list[str], *, run=subprocess.run, cli_path: str | None = None,
                  cwd: str = ".") -> int:
    """Run one read-only ELK query, echo its output and append it to `elk_results.txt` in
    `cwd` (the analyzer's run dir): under ELK_QUERY_HEADER when it succeeded, under
    ELK_FAILED_HEADER otherwise. Only successes count against ELK_QUERY_LIMIT.

    Everything runs through the elk-logs CLI via `run`; CJK phrases for count/recent/timeline
    get the extra arguments of `_phrase_argv`.
    """
    if not argv or argv[0] not in ELK_SUBCOMMANDS:
        print(f"elk-query 只接受:{', '.join(sorted(ELK_SUBCOMMANDS))}", file=sys.stderr)
        return 2
    results = Path(cwd, ELK_RESULTS_FILE)
    text = results.read_text(encoding="utf-8") if results.exists() else ""
    if len(_SUCCESS_HEADER.findall(text)) >= ELK_QUERY_LIMIT:
        # The prompt asks for a plan; this is what actually bounds one analysis.
        print(f"elk-query 已達本次分析上限 {ELK_QUERY_LIMIT} 次,請用手上的結果完成判斷",
              file=sys.stderr)
        return 2
    problem = _argument_problem(argv)
    if problem:
        out, err, code = "", f"elk-query 參數錯誤(未查詢、不計次):{problem}\n", 2
    elif _is_phrase_query(argv):
        out, err, code = _run_phrase_query(argv, run, cli_path)
    else:
        out, err, code = _run_elk_cli(argv, run, cli_path)
    sys.stdout.write(out)
    sys.stderr.write(err)
    header = (f"{ELK_QUERY_HEADER} {shlex.join(argv)}" if code == 0
              else f"{ELK_FAILED_HEADER} elk-query {shlex.join(argv)} (exit {code})")
    with open(results, "a", encoding="utf-8") as f:
        f.write(f"{header}\n{out}{err}\n")
    return code


def cmd_eval(cfg: Config, args, slack, elk) -> int:
    from alert_doctor import evals
    cases = evals.load_cases(only=args.case)
    if not cases:
        print(f"沒有 eval case:{evals.CASES_DIR}", file=sys.stderr)
        return 2
    report = evals.run_eval(
        cases, model=args.model or cfg.model, escalation_model=cfg.escalation_model,
        timeout=cfg.llm_timeout, systems=cfg.systems,
        snapshot_dir=os.path.dirname(_snapshot_path(cfg)), runs=args.runs)
    print(evals.format_report(report))
    return 0 if report["passed"] == report["total"] else 1


COMMANDS = {
    "collector": cmd_collector, "analyzer": cmd_analyzer, "report": cmd_report,
    "health": cmd_health, "backfill": cmd_backfill, "discover": cmd_discover,
    "replay": cmd_replay, "tuner": cmd_tuner, "audit-request-id": cmd_audit_request_id,
    "mirrors": cmd_mirrors, "outbox": cmd_outbox, "archive-report": cmd_archive_report,
    "archive-backfill": cmd_archive_backfill,
    "watchdog-snapshot-info": cmd_watchdog_snapshot_info, "eval": cmd_eval,
    "wipe": cmd_wipe,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alert_doctor")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("file", nargs="?", help="replay 用:每行 {\"ts\",\"text\",可省略的 \"channel\"} 的 jsonl")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--date", help="report 用:YYYY-MM-DD(預設昨天)")
    parser.add_argument("--post", action="store_true")
    parser.add_argument("--hours", type=int)
    parser.add_argument("--no-elk", action="store_true")
    parser.add_argument("--weekly", action="store_true", help="report 用:近 7 天週報")
    parser.add_argument("--rollback", type=int, metavar="VERSION",
                        help="tuner 用:基線回滾到這個版本並釘選,直到 --unpin")
    parser.add_argument("--unpin", action="store_true", help="tuner 用:解除基線釘選")
    parser.add_argument("--days", type=int, default=30,
                        help="archive-report / archive-backfill 用:天數(預設 30)")
    parser.add_argument("--channel", action="extend", nargs="+", metavar="ID",
                        help="archive-backfill / wipe 用:只處理這些頻道(預設全部)")
    parser.add_argument("--apply", action="store_true",
                        help="wipe 用:真的刪除(預設只封存並預演)")
    parser.add_argument("--dry-run", action="store_true",
                        help="archive-backfill 用:只讀 Slack 統計,不寫入錯誤資料庫")
    parser.add_argument("--limit", type=int, default=OUTBOX_LIST_LIMIT,
                        help=f"outbox 用:最多列幾則(預設 {OUTBOX_LIST_LIMIT})")
    parser.add_argument("--case", action="append", help="eval 用:只跑這個 case id(可重複)")
    parser.add_argument("--model", help="eval 用:第一輪模型(預設 config 的 model)")
    parser.add_argument("--runs", type=int, default=1, help="eval 用:每個 case 跑幾次(預設 1)")
    return parser


def main_known(argv: list[str], *, slack, elk) -> int:
    """`known` has its own subcommands, which the flat COMMANDS parser cannot express."""
    from alert_doctor import known_cli
    # Pulled out first so `--config` works after the subcommand too (`known list --config x`).
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", default="config.toml")
    config_args, rest = config_parser.parse_known_args(argv)
    parser = argparse.ArgumentParser(prog="alert_doctor known", parents=[config_parser])
    known_cli.add_arguments(parser)
    args = parser.parse_args(rest)
    args.config = config_args.config
    try:
        cfg = load_config(args.config)
        return known_cli.cmd_known(cfg, args, slack, elk, store=_open_store(cfg))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"錯誤:{exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None, *, slack=None, elk=None,
         elk_runner=subprocess.run) -> int:
    """`slack`, `elk` and `elk_runner` are injection points for tests; production uses
    slack_io, the real ElkClient and subprocess.run."""
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["elk-query"]:
        # Passed straight through: elk-logs flags (--from, --where …) are not ours to parse.
        return cmd_elk_query(argv[1:], run=elk_runner,
                             cwd=os.environ.get("ALERT_DOCTOR_RUN_DIR") or ".")
    if argv[:1] == ["known"]:
        return main_known(argv[1:], slack=slack or slack_io, elk=elk)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "replay" and not args.file:
        parser.error("replay 需要 jsonl 檔案路徑")
    if args.hours is None:
        args.hours = 168 if args.command == "discover" else 1
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        cfg = load_config(args.config)
        return COMMANDS[args.command](cfg, args, slack or slack_io, elk)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"錯誤:{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
