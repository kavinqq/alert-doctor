from __future__ import annotations

import json
import time
from datetime import date, datetime, timedelta, timezone

from alert_doctor import replies
from alert_doctor.config import unknown_check_systems

TAIPEI = timezone(timedelta(hours=8))

COLLECTOR_BEAT_MAX_AGE = 300
SOCKET_BEAT_MAX_AGE = 300
ANALYZER_BEAT_MAX_AGE = 3600
BACKFILL_BEAT_MAX_AGE = 900
MIRROR_BEAT_MAX_AGE = 3600
TUNER_BEAT_MAX_AGE = 2 * 3600
PENDING_MESSAGE_MAX_AGE = 600
PENDING_ANALYSIS_MAX_AGE = 4 * 3600
FAILED_ANALYSIS_WINDOW = 24 * 3600
CRITICAL_FIRST_MAX_DELAY = 30
FIRST_MAX_DELAY = 5 * 60
OUTBOX_MAX_AGE = 10 * 60
OUTBOX_FAILED_WINDOW = 24 * 3600
OVERLOAD_MAX_SECONDS = 10 * 60
UNKNOWN_TASK_WINDOW = 24 * 3600
SNAPSHOT_MAX_AGE_DAYS = 30
COUNTER_LABELS = (("elk_skipped", "ELK 查詢跳過"), ("llm_deferred", "LLM 延後"),
                  ("unknown_task", "快照裡沒有的排程"))
# Default for `health_problems(snapshot=...)`: the caller did not look at the snapshot.
SNAPSHOT_NOT_CHECKED = object()
PURGE_CAUSE_CHARS = 60


def day_bounds(day: date) -> tuple[float, float]:
    start = datetime(day.year, day.month, day.day, tzinfo=TAIPEI)
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


COUNT_KEYS = ("total", "handled", "failed", "pending", "degraded", "published", "deferred")
EMPTY_COVERAGE = {**dict.fromkeys(COUNT_KEYS, 0), "unhandled": [], "by_category": {}}


def _merge_coverage(per_channel: list[dict]) -> dict:
    merged = {**dict.fromkeys(COUNT_KEYS, 0), "unhandled": [], "by_category": {}}
    for cov in per_channel:
        for key in COUNT_KEYS:
            merged[key] += cov.get(key, 0)
        merged["unhandled"].extend(cov["unhandled"])
        for category, n in cov["by_category"].items():
            merged["by_category"][category] = merged["by_category"].get(category, 0) + n
    return merged


def build_daily_report(store, cfg, day: date) -> str:
    start, end = day_bounds(day)
    by_channel = store.coverage_all(start, end)
    per_channel = [by_channel.get(c.id, EMPTY_COVERAGE) for c in cfg.channels]
    llm = {m: store.llm_calls_on(m, start, end) for m in dict.fromkeys((cfg.model, cfg.escalation_model))}
    backlog = len(store.stale_pending_analysis(end))
    failed_analyses = len(store.incidents_in_states(
        ("failed",), requested_since=start, requested_until=end))
    lines = replies.daily_report(
        _merge_coverage(per_channel), llm, backlog, day.isoformat(), failed_analyses).split("\n")
    channel_lines = [
        f"• {c.name}:{cov['total']} 則 · 已處理 {cov['handled']} · 失敗 {cov['failed']} · 待處理 {cov['pending']}"
        f"\n  {_publishing_line(cov)}"
        for c, cov in zip(cfg.channels, per_channel)
    ]
    return "\n".join(lines[:1] + channel_lines + lines[1:]
                     + _protection_section(store, start, end, time.time())
                     + _purge_section(store, start, end))


def _publishing_line(cov: dict) -> str:
    """Degraded classifications skipped ELK and rules sampling; they must not read as analysed."""
    degraded = cov.get("degraded", 0)
    return (f"分類 正常 {cov['handled'] - degraded} · 降級 {degraded} · "
            f"已發布 {cov.get('published', 0)} · 待發 {cov.get('deferred', 0)}")


def _protection_section(store, since: float, until: float, now: float) -> list[str]:
    stats = store.outbox_stats(now)
    protection = store.get_protection()
    lines = ["保護機制:"]
    if protection.get("state") == "overload":
        lines.append(f"🌪️ 目前在過載模式(自 {_fmt_time(protection.get('since'))},"
                     f"{protection.get('reason') or '原因不明'})")
    else:
        lines.append("目前為正常模式")
    lines.append(f"outbox 待發 {stats['pending']} · 失敗 {stats['failed']} · "
                 f"最老待發 {_fmt_age(stats['oldest_pending_age'])} · "
                 f"最老 CRITICAL {_fmt_age(stats['oldest_critical_age'])}")
    lines.append(" · ".join(f"{label} {store.counter_sum(name, since, until)}"
                            for name, label in COUNTER_LABELS))
    return lines


def _purge_section(store, since: float, until: float) -> list[str]:
    """Green incidents deleted from Slack that day: this report is the only place they show."""
    rows = store.read(
        "SELECT p.incident_id, i.check_title, p.verdict,"
        " (SELECT COUNT(*) FROM purge_targets t JOIN purges q ON q.id=t.purge_id"
        "  WHERE q.incident_id=p.incident_id AND q.state='done' AND t.kind IN ('alert','fragment'))"
        " FROM purges p JOIN incidents i ON i.id=p.incident_id"
        " WHERE p.state='done' AND p.finished_epoch>=? AND p.finished_epoch<?"
        " GROUP BY p.incident_id ORDER BY p.incident_id", (since, until))
    fallback = store.read(
        "SELECT COUNT(DISTINCT incident_id) FROM purges"
        " WHERE state='fallback' AND finished_epoch>=? AND finished_epoch<?", (since, until))[0][0]
    lines = []
    if rows:
        lines.append(f"🟢 綠燈已刪除 {len(rows)} 件")
        for incident_id, title, verdict, alerts in rows:
            cause = " ".join(str(json.loads(verdict or "{}").get("cause") or "").split())
            lines.append(f"• #{incident_id} {title} ×{alerts} — {cause[:PURGE_CAUSE_CHARS]}")
    if fallback:
        lines.append(f"刪除失敗、改回覆分析 {fallback} 件")
    return lines


def _fmt_age(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 120:
        return f"{int(seconds)} 秒"
    return f"{int(seconds // 60)} 分鐘"


def _fmt_time(epoch: float | None) -> str:
    if epoch is None:
        return "?"
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%m-%d %H:%M")


def _age_problem(name: str, beat: float | None, now: float, limit: int) -> str | None:
    if beat is None:
        return f"{name} 從未回報心跳"
    age = now - beat
    if age > limit:
        return f"{name} 已 {int(age // 60)} 分鐘沒有心跳(上限 {limit // 60} 分鐘)"
    return None


def _backfill_problems(store, cfg, now: float) -> list[str]:
    started = store.last_beat("collector_started")
    problems = []
    for channel in cfg.channels:
        beat = store.last_beat(f"backfill:{channel.id}")
        if beat is None:
            # A collector that just started has not finished its first pass yet.
            if started is not None and now - started > BACKFILL_BEAT_MAX_AGE:
                problems.append(f"{channel.name} 的 backfill 從未成功")
            continue
        problems.append(_age_problem(f"{channel.name} 的 backfill", beat, now, BACKFILL_BEAT_MAX_AGE))
    return problems


def _outbox_problems(store, now: float) -> list[str]:
    stats = store.outbox_stats(now)
    problems = []
    critical = stats["oldest_critical_age"]
    if critical is not None and critical > CRITICAL_FIRST_MAX_DELAY:
        problems.append(f"CRITICAL 首則/保護通知已延遲 {int(critical)} 秒未發出"
                        f"(上限 {CRITICAL_FIRST_MAX_DELAY} 秒)")
    first_pending = stats["first_pending_age"]
    if first_pending is not None and first_pending > FIRST_MAX_DELAY:
        problems.append(f"一般首則已延遲 {int(first_pending // 60)} 分鐘未發出"
                        f"(上限 {FIRST_MAX_DELAY // 60} 分鐘)")
    oldest = stats["oldest_pending_age"]
    if oldest is not None and oldest > OUTBOX_MAX_AGE:
        problems.append(f"outbox 最老待發已等 {int(oldest // 60)} 分鐘"
                        f"(上限 {OUTBOX_MAX_AGE // 60} 分鐘,共 {stats['pending']} 則待發)")
    erroring = stats["oldest_error_age"]
    if erroring is not None and erroring > OUTBOX_MAX_AGE:
        problems.append(f"有待發訊息持續發送失敗 {int(erroring // 60)} 分鐘"
                        f"(上限 {OUTBOX_MAX_AGE // 60} 分鐘),見 python -m alert_doctor outbox")
    failed = store.read(
        "SELECT COUNT(*) FROM outbox WHERE status='failed' AND due_epoch>=?",
        (now - OUTBOX_FAILED_WINDOW,))[0][0]
    if failed:
        problems.append(f"outbox 有 {failed} 則重試多次仍發送失敗(24 小時內),"
                        "見 python -m alert_doctor outbox")
    return problems


def _protection_problems(store, now: float) -> list[str]:
    protection = store.get_protection()
    since = protection.get("since")
    if protection.get("state") != "overload" or since is None:
        return []
    if now - since <= OVERLOAD_MAX_SECONDS:
        return []
    return [f"過載保護已持續 {int((now - since) // 60)} 分鐘"
            f"(上限 {OVERLOAD_MAX_SECONDS // 60} 分鐘):{protection.get('reason') or '原因不明'}"]


def _snapshot_problems(store, now: float, snapshot) -> list[str]:
    problems = []
    unknown = store.counter_sum("unknown_task", now - UNKNOWN_TASK_WINDOW, now)
    if unknown:
        problems.append(f"24 小時內有 {unknown} 則告警的排程 ID 不在 watchdog 快照裡,請重新匯出快照")
    if snapshot is SNAPSHOT_NOT_CHECKED:
        return problems
    if snapshot is None:
        return problems + ["watchdog 快照不存在或無法讀取,告警標題與檢查腳本不會帶入分析"]
    try:
        exported = datetime.fromisoformat(str(getattr(snapshot, "exported_at", "")))
        if exported.tzinfo is None:
            exported = exported.replace(tzinfo=TAIPEI)
    except ValueError:
        return problems + [f"watchdog 快照的匯出時間看不懂:{getattr(snapshot, 'exported_at', None)!r}"]
    age_days = (now - exported.timestamp()) / 86400
    if age_days > SNAPSHOT_MAX_AGE_DAYS:
        problems.append(f"watchdog 快照已 {int(age_days)} 天沒更新(上限 {SNAPSHOT_MAX_AGE_DAYS} 天),請重新匯出")
    return problems


def health_problems(store, cfg, now: float, checks: dict | None = None,
                    snapshot=SNAPSHOT_NOT_CHECKED) -> list[str]:
    """`checks` (checks.toml) adds a problem for every check pointing at an undefined system.

    `snapshot` is the loaded watchdog snapshot (None = missing/unreadable, which is a
    problem); leave it out to skip the snapshot age check.
    """
    problems = [
        _age_problem("collector", store.last_beat("collector"), now, COLLECTOR_BEAT_MAX_AGE),
        _age_problem("socket", store.last_beat("socket"), now, SOCKET_BEAT_MAX_AGE),
        _age_problem("analyzer", store.last_beat("analyzer"), now, ANALYZER_BEAT_MAX_AGE),
        _age_problem("tuner", store.last_beat("tuner"), now, TUNER_BEAT_MAX_AGE),
    ]
    problems += _backfill_problems(store, cfg, now)
    problems += [_age_problem(f"repo {repo_id} 的 mirror", store.last_beat(f"mirror:{repo_id}"),
                              now, MIRROR_BEAT_MAX_AGE) for repo_id in cfg.repos]
    problems += unknown_check_systems(cfg, checks or {})
    pending = store.pending_messages(limit=1, now=float("inf"))
    if pending and now - pending[0].epoch > PENDING_MESSAGE_MAX_AGE:
        minutes = int((now - pending[0].epoch) // 60)
        problems.append(f"最舊的待處理訊息已等 {minutes} 分鐘(ts {pending[0].ts})")
    stale = store.stale_pending_analysis(now - PENDING_ANALYSIS_MAX_AGE)
    if stale:
        ids = ", ".join(f"#{i.id}" for i in stale[:10])
        problems.append(f"{len(stale)} 個 incident 分析積壓超過 4 小時:{ids}")
    failed_analyses = store.incidents_in_states(
        ("failed",), requested_since=now - FAILED_ANALYSIS_WINDOW)
    if failed_analyses:
        ids = ", ".join(f"#{i.id}" for i in failed_analyses[:10])
        problems.append(f"{len(failed_analyses)} 個 incident 分析失敗(24 小時內):{ids}")
    expired = store.incidents_in_states(("leased",), lease_expired_before=now)
    if expired:
        ids = ", ".join(f"#{i.id}" for i in expired[:10])
        problems.append(f"{len(expired)} 個 incident 分析租約已過期、無人接手:{ids}")
    today_start, _ = day_bounds(datetime.fromtimestamp(now, TAIPEI).date())
    today = store.coverage_all(today_start, now)
    for channel in cfg.channels:
        failed = today.get(channel.id, EMPTY_COVERAGE)["failed"]
        if failed:
            problems.append(f"{channel.name} 今日有 {failed} 則訊息處理失敗(重試 5 次仍失敗)")
    problems += _outbox_problems(store, now)
    problems += _protection_problems(store, now)
    problems += _snapshot_problems(store, now, snapshot)
    return [p for p in problems if p]


WEEK_SECONDS = 7 * 86400
SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_LIST_LIMIT = 5
NOISIEST_LIMIT = 10


def _fmt_day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%m-%d")


def _severity_section(store, cfg, since: float, until: float) -> list[str]:
    rows = store.read(
        "SELECT id, check_title, channel, verdict FROM incidents WHERE analysis_state='done'"
        " AND completed_epoch>=? AND completed_epoch<? AND verdict IS NOT NULL ORDER BY id",
        (since, until))
    grouped: dict[str, list[tuple]] = {}
    for incident_id, title, channel, raw in rows:
        severity = (json.loads(raw) or {}).get("severity") or "unknown"
        grouped.setdefault(severity, []).append((incident_id, title, channel))
    if not grouped:
        return ["嚴重度:本週沒有完成分析的 incident"]
    lines = ["嚴重度(已完成分析的 incident):"]
    for severity in SEVERITY_ORDER + tuple(sorted(set(grouped) - set(SEVERITY_ORDER))):
        items = grouped.get(severity)
        if not items:
            continue
        emoji = replies.SEVERITY_EMOJI.get(severity, replies.UNKNOWN_SEVERITY_EMOJI)
        lines.append(f"{emoji} {severity} {len(items)}")
        if severity in ("critical", "high"):
            for incident_id, title, channel in items[:SEVERITY_LIST_LIMIT]:
                spec = cfg.channel(channel)
                lines.append(f"  • #{incident_id} {title}({spec.name if spec else channel})")
    return lines


def _auto_rule_section(store, since: float, until: float) -> list[str]:
    counts = dict(store.read("SELECT state, COUNT(*) FROM auto_rules GROUP BY state"))
    created = store.read("SELECT COUNT(*) FROM auto_rules WHERE created>=? AND created<?", (since, until))[0][0]
    promoted = store.read(
        "SELECT COUNT(*) FROM auto_rules WHERE activated>=? AND activated<?", (since, until))[0][0]
    expired = store.read(
        "SELECT COUNT(*) FROM auto_rules WHERE state='expired' AND expires>=? AND expires<?",
        (since, until))[0][0]
    rejected = store.read(
        "SELECT COUNT(*) FROM counterexamples WHERE epoch>=? AND epoch<?", (since, until))[0][0]
    return [
        f"自動規則:目前 shadow {counts.get('shadow', 0)} · active {counts.get('active', 0)}",
        f"本週新增 {created} · 本週轉正 {promoted} · 本週到期 {expired} · 本週 ❌ 撤銷 {rejected}",
    ]


def _feedback_section(store, since: float, until: float) -> list[str]:
    rows = store.read(
        "SELECT f.kind, COALESCE(m.category, '?') FROM feedback f"
        " LEFT JOIN incidents i ON i.id=f.incident_id"
        " LEFT JOIN messages m ON m.channel=i.channel AND m.ts=i.anchor_ts"
        " WHERE f.epoch>=? AND f.epoch<?", (since, until))
    agree = sum(1 for kind, _ in rows if kind == "agree")
    reject = sum(1 for kind, _ in rows if kind == "reject")
    if not agree + reject:
        return ["回饋準確率 —(尚無回饋)"]
    lines = [f"回饋準確率 {agree / (agree + reject):.0%}(✅ {agree} / ❌ {reject})"]
    by_category: dict[str, list[int]] = {}
    for kind, category in rows:
        bucket = by_category.setdefault(category, [0, 0])
        bucket[0 if kind == "agree" else 1] += 1
    lines.append("各類別:" + "、".join(
        f"{c} {a / (a + r):.0%}({a}/{a + r})" for c, (a, r) in sorted(by_category.items())))
    return lines


def _noisiest_section(store, cfg, since: float, until: float) -> list[str]:
    rows = store.read(
        "SELECT fingerprint, COUNT(*) AS n, MAX(check_title), MAX(channel) FROM messages"
        " WHERE epoch>=? AND epoch<? AND fingerprint IS NOT NULL GROUP BY fingerprint"
        " ORDER BY n DESC, fingerprint LIMIT ?", (since, until, NOISIEST_LIMIT))
    if not rows:
        return []
    lines = ["最吵的指紋:"]
    for i, (fp, n, title, channel) in enumerate(rows, 1):
        spec = cfg.channel(channel)
        lines.append(f"{i}. {title or '(無標題)'} · {n} 則 · {spec.name if spec else channel} · {fp[:8]}")
    return lines


def build_weekly_report(store, cfg, now: float, audit: str | None = None) -> str:
    """The 7 days ending at `now`; `audit` is a ready request-id audit text, None to omit it."""
    since = now - WEEK_SECONDS
    by_channel = store.coverage_all(since, now)
    per_channel = [by_channel.get(c.id, EMPTY_COVERAGE) for c in cfg.channels]
    merged = _merge_coverage(per_channel)
    lines = [f"📅 *alert-doctor 週報 {_fmt_day(since)} ~ {_fmt_day(now)}*"]
    lines += [f"• {c.name}:{cov['total']} 則 · 已處理 {cov['handled']} · {_publishing_line(cov)}"
              for c, cov in zip(cfg.channels, per_channel)]
    if merged["by_category"]:
        lines.append("分類:" + "、".join(f"{k} {n}" for k, n in sorted(merged["by_category"].items())))
    lines += _severity_section(store, cfg, since, now)
    lines += _auto_rule_section(store, since, now)
    lines += _feedback_section(store, since, now)
    llm = {m: store.llm_calls_on(m, since, now) for m in dict.fromkeys((cfg.model, cfg.escalation_model))}
    lines.append("LLM 呼叫:" + " · ".join(f"{m} {n}" for m, n in llm.items()))
    lines += _noisiest_section(store, cfg, since, now)
    lines += _protection_section(store, since, now, now)
    if audit:
        lines += ["request_id 稽核:", audit]
    return "\n".join(lines)
