"""Drains the durable outbox into Slack under the per-channel pace and the Slack budget.

Payload contract per outbox kind (keys the publisher reads; anything else is ignored):

1. `first`: `decision_text`, `mentions` (list of ready mention strings), `severity`
   ("low".."critical" or None), `reaction`, `severity_reaction`, `reply_kind`, `hosts`.
   Posted in the alert's own thread (`thread_ts` = alert ts), which becomes the report root.
2. `update`: `hosts`, `severity`, `severity_reaction`. Counts are computed at send time.
3. `backfill`: no keys; counts of backfilled occurrences are computed at send time.
4. `storm`: `minute` (epoch // 60 of the minute summarised).
5. `protection`: `entering`, `reason`, `mentions`.
6. `analysis`: `text`, optional `reply_kind`, `reactions_on_root`, `remove_on_root`.
7. `link`: `permalink` (or `text`).
8. `failure` / `feedback` / anything else: `text`, optional `reply_kind`,
   `reactions_on_root`, `remove_on_root`.

Every kind except `first`, `storm` and `protection` goes to `thread_ts` when set, else to
the incident's report root in that channel.

`first` and `analysis` posts end with a `📊 出現次數` section read from the error archive at
send time; it is left out whenever the archive or the occurrence is not there.
"""
from __future__ import annotations

import json
import logging
import math
import os
import time
import urllib.error
from datetime import datetime, timedelta, timezone

from alert_doctor import purge, replies
from alert_doctor.hosts import count_hosts
from alert_doctor.models import SEVERITY_REACTION
from alert_doctor.slack_io import SlackRateLimited

log = logging.getLogger("alert_doctor.publisher")

CHANNEL_GAP_SECONDS = 1.0
NO_BUDGET_RETRY_SECONDS = 5
WAIT_FOR_ROOT_SECONDS = 5
OUTAGE_RETRY_SECONDS = 30
BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 1800
STORM_TOP = 10
NOTICE_BUSIEST_WINDOW_SECONDS = 600
BACKFILL_EPISODE_SECONDS = 1800
TRANSPORT_ERRORS = (urllib.error.URLError, OSError, TimeoutError)
TAIPEI = timezone(timedelta(hours=8))
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_OF_REACTION = {v: k for k, v in SEVERITY_REACTION.items()}


def clock_label(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%H:%M")


def severity_word(reaction: str | None) -> str | None:
    return SEVERITY_OF_REACTION.get(reaction or "")


_UNSET = object()

STORM_NOTE = "🌪️ 告警風暴中,不另行 tag,狀況請看風暴總覽。"

# 1 -> 2 is "doubling" too, but at that size it is noise, not a reason to post early.
MIN_DOUBLING_TOTAL = 10


def report_changes(report: dict, *, total: int, hosts: int | None,
                   severity: str | None) -> list[str]:
    """Changes since the report's last post that justify posting at once."""
    changes = []
    last_count = report.get("last_count") or 0
    if last_count and total >= 2 * last_count and total >= MIN_DOUBLING_TOTAL:
        changes.append("量級翻倍")
    if SEVERITY_RANK.get(severity or "", 0) > SEVERITY_RANK.get(report.get("last_severity") or "", 0):
        emoji = replies.SEVERITY_EMOJI.get(severity, "")
        changes.append(f"嚴重度升級為 {emoji}".rstrip())
    last_hosts = report.get("last_hosts")
    if hosts is not None and last_hosts is not None and hosts > last_hosts:
        changes.append(f"ELK 主機數 {last_hosts} → {hosts} 台")
    return changes


class _Skip(Exception):
    """The row has nothing to post (yet); `retry_at` None means drop it."""

    def __init__(self, reason: str, retry_at: float | None = None):
        super().__init__(reason)
        self.reason = reason
        self.retry_at = retry_at


class Publisher:
    """`slack` exposes the `slack_io` function names. Not thread-safe: one per process."""

    def __init__(self, cfg, store, slack, bot_token: str, budgets, clock=time.time,
                 archive=_UNSET):
        """`archive` None disables the occurrence line; by default it is opened from
        `cfg.archive_db_path` on first use."""
        self.cfg = cfg
        self.store = store
        self.slack = slack
        self.bot_token = bot_token
        self.budgets = budgets
        self.clock = clock
        self._last_post: dict[str, float] = {}
        self._paused_until = float("-inf")
        self._archive = None if archive is _UNSET else archive
        self._archive_discoverable = archive is _UNSET

    def archive(self):
        """The error archive, or None. Only an absolute, existing path is opened: load_config
        makes paths absolute, so a relative one is a bare Config (tests, replay helpers) that
        would otherwise read and migrate whatever archive sits under the current directory."""
        if self._archive is None and self._archive_discoverable:
            path = getattr(self.cfg, "archive_db_path", None) or ""
            if os.path.isabs(path) and os.path.exists(path):
                self._archive_discoverable = False
                try:
                    from alert_doctor.archive import Archive
                    self._archive = Archive(path)
                except Exception as exc:
                    log.warning("錯誤資料庫 %s 無法開啟:%s", path, exc)
        return self._archive

    def _occurrence_section(self, channel: str, ts: str | None, now: float) -> str:
        archive = self.archive()
        if archive is None or not ts:
            return ""
        try:
            found = archive.key_of(channel, ts)
            if found is None:
                return ""
            key, epoch = found
            return replies.occurrence_line(archive.occurrence_stats(key, now, before=epoch))
        except Exception as exc:
            log.warning("出現次數查詢失敗 %s/%s:%s", channel, ts, exc)
            return ""

    def notice_channel(self) -> str:
        """Where protection notices and storm overviews go: the configured report channel,
        else the channel with the most alerts in the last 10 minutes, else the first one."""
        if self.cfg.report_channel:
            return self.cfg.report_channel
        busiest = self.store.busiest_channel(self.clock() - NOTICE_BUSIEST_WINDOW_SECONDS)
        return busiest or self.cfg.channels[0].id

    def _untag_minutes(self) -> int:
        return getattr(self.cfg, "overload_untag_minutes", 30)

    def _silencing_firsts(self, now: float) -> bool:
        """Overload untags non-urgent first posts only for a while: people must not stay
        silenced for hours of a long storm."""
        protection = self.store.get_protection()
        if protection["state"] != "overload":
            return False
        since = protection["since"] if protection["since"] is not None else now
        return now - since < self._untag_minutes() * 60

    def process(self, now: float | None = None) -> int:
        """Send what is due; returns how many messages were posted.

        Budget or pacing refusals and Slack 429 / network outages put the row back without
        spending an attempt; a 429 also pauses every later row for `Retry-After`.
        """
        now = self.clock() if now is None else now
        if now < self._paused_until:
            return 0
        posted = 0
        items = self.store.claim_outbox(now)
        for index, item in enumerate(items):
            if now < self._paused_until:
                for rest in items[index:]:
                    self.store.retry_outbox(rest.id, "Slack 限流暫停", self._paused_until,
                                            count_attempt=False)
                break
            last = self._last_post.get(item.channel)
            if last is not None and now - last < CHANNEL_GAP_SECONDS:
                self.store.retry_outbox(item.id, "同頻道間隔", last + CHANNEL_GAP_SECONDS,
                                        count_attempt=False)
                continue
            try:
                if self._send(item, now):
                    posted += 1
            except _Skip as skip:
                if skip.retry_at is None:
                    self.store.drop_outbox(item.id, skip.reason, now)
                else:
                    self.store.retry_outbox(item.id, skip.reason, skip.retry_at,
                                            count_attempt=False)
            except SlackRateLimited as exc:
                self._paused_until = now + exc.retry_after
                self.store.retry_outbox(item.id, "Slack 429", self._paused_until,
                                        count_attempt=False)
            except TRANSPORT_ERRORS as exc:
                self.store.retry_outbox(item.id, f"{type(exc).__name__}: {exc}"[:300],
                                        now + OUTAGE_RETRY_SECONDS, count_attempt=False)
            except Exception as exc:
                log.warning("outbox %s (%s) failed: %s", item.id, item.kind, exc)
                backoff = min(BACKOFF_BASE_SECONDS * 2 ** item.attempts, BACKOFF_MAX_SECONDS)
                self.store.retry_outbox(item.id, f"{type(exc).__name__}: {exc}"[:300],
                                        now + backoff)
        return posted

    # ---------- per kind ----------

    def _send(self, item, now: float) -> bool:
        if item.kind not in ("storm", "protection") and purge.blocked_thread(
                self.store, item.channel, self._root(item)):
            raise _Skip("告警已刪除(綠燈)")
        if item.kind == "first":
            return self._first(item, now)
        if item.kind == "update":
            return self._update(item, now)
        if item.kind == "backfill":
            return self._backfill(item, now)
        if item.kind == "storm":
            return self._storm(item, now)
        if item.kind == "protection":
            return self._protection(item, now)
        return self._plain(item, now)

    def _budget_class(self, item) -> str:
        if item.priority == 0:
            return "critical"
        return "first" if item.kind in ("first", "analysis") else "normal"

    def _post(self, item, text: str, thread_ts: str | None, now: float) -> str:
        if not self.budgets.slack.take(self._budget_class(item), now):
            raise _Skip("Slack 發文預算不足", now + NO_BUDGET_RETRY_SECONDS)
        reply_ts = self.slack.post_message(self.bot_token, item.channel, text, thread_ts=thread_ts)
        self._last_post[item.channel] = now
        return reply_ts

    def _finish(self, item, reply_ts: str, root_ts: str, now: float, kind: str) -> None:
        """Bookkeeping right after a successful post; the row is completed even if indexing
        fails, because retrying it would post the same message twice."""
        try:
            self.store.index_reply(item.channel, reply_ts, root_ts, item.incident_id, kind)
        finally:
            self.store.complete_outbox(item.id, reply_ts, now)

    def _react(self, channel: str, ts: str, add=(), remove=()) -> None:
        for action, names in ((self.slack.remove_reaction, remove), (self.slack.add_reaction, add)):
            for name in names:
                if not name:
                    continue
                try:
                    action(self.bot_token, channel, ts, name)
                except SlackRateLimited as exc:
                    self._paused_until = max(self._paused_until, self.clock() + exc.retry_after)
                    log.warning("reaction %s on %s rate limited", name, ts)
                except Exception as exc:
                    log.warning("reaction %s on %s failed: %s", name, ts, exc)

    def _total(self, item) -> int:
        return self.store.count_incident_messages(item.incident_id, item.channel, 0, math.inf)

    def _analysis_occurrences(self, item, now: float) -> str:
        if item.incident_id is None:
            return ""
        incident = self.store.get_incident(item.incident_id)
        if incident is None:
            return ""
        return self._occurrence_section(incident.channel, incident.anchor_ts, now)

    def _host_counts(self, item) -> dict:
        """Per-host occurrences for the incident in this channel, from the alerts' own quoted
        log records; falls back to the ELK evidence already gathered. Never queries ELK."""
        try:
            rows = self.store.read(
                "SELECT raw_text FROM messages WHERE incident_id=? AND channel=?"
                " AND COALESCE(category, '') != 'fragment'", (item.incident_id, item.channel))
            counts = count_hosts(r[0] for r in rows)
            if counts:
                return counts
            evidence = self.store.load_evidence(item.incident_id) or {}
            return {str(k): int(v) for k, v in (evidence.get("per_host") or {}).items()}
        except Exception as exc:
            log.warning("host counts for incident %s failed: %s", item.incident_id, exc)
            return {}

    def _first(self, item, now: float) -> bool:
        if self.store.get_report(item.incident_id, item.channel) is not None:
            return self._update(item, now)
        payload = item.payload
        total = self._total(item)
        summary = {"count": total, "hosts": payload.get("hosts"),
                   "host_counts": self._host_counts(item),
                   "window": clock_label(float(item.thread_ts)) if item.thread_ts else "",
                   "severity": payload.get("severity")}
        tags = tuple(payload.get("mentions") or ())
        decision_text = payload.get("decision_text", "")
        # Decided at send time, not enqueue time: the overload verdict for a wave only exists
        # after the whole wave was classified, and the protection notice already tagged people.
        if item.priority != 0 and self._silencing_firsts(now):
            tags = ()
            decision_text = f"{decision_text}\n{STORM_NOTE}"
        text = replies.first_report(decision_text=decision_text, summary=summary, mentions=tags)
        text = replies.append_section(
            text, self._occurrence_section(item.channel, item.thread_ts, now))
        reply_ts = self._post(item, text, item.thread_ts, now)
        try:
            self.store.upsert_report(item.incident_id, item.channel, item.thread_ts, now=now)
            self.store.set_report_state(
                item.incident_id, item.channel, last_update_epoch=now, last_count=total,
                last_hosts=payload.get("hosts"), last_severity=payload.get("severity"),
                last_backfilled=self._backfilled_total(item))
            with self.store.tx() as db:
                db.execute("UPDATE messages SET reply_ts=? WHERE channel=? AND ts=?",
                           (reply_ts, item.channel, item.thread_ts))
        finally:
            self._finish(item, reply_ts, item.thread_ts, now, payload.get("reply_kind") or "triage")
        self._react(item.channel, item.thread_ts,
                    add=(payload.get("reaction"), payload.get("severity_reaction")))
        return True

    def _root(self, item) -> str | None:
        if item.thread_ts:
            return item.thread_ts
        if item.incident_id is None:
            return None
        report = self.store.get_report(item.incident_id, item.channel)
        return report["root_ts"] if report else None

    def _first_pending(self, item) -> bool:
        return bool(self.store.read(
            "SELECT 1 FROM outbox WHERE incident_id=? AND channel=? AND kind='first'"
            " AND status='pending'", (item.incident_id, item.channel)))

    def _report_or_wait(self, item, now: float) -> dict:
        report = self.store.get_report(item.incident_id, item.channel)
        if report is not None:
            return report
        if self._first_pending(item):
            raise _Skip("等首則發出", now + WAIT_FOR_ROOT_SECONDS)
        raise _Skip("此頻道沒有回報串")

    def _update(self, item, now: float) -> bool:
        report = self._report_or_wait(item, now)
        payload = item.payload
        total = self._total(item)
        batch = total - (report.get("last_count") or 0)
        if batch <= 0:
            raise _Skip("沒有新的告警")
        hosts = payload.get("hosts")
        severity = payload.get("severity")
        changes = report_changes(report, total=total, hosts=hosts, severity=severity)
        text = replies.minute_update(incident_id=item.incident_id, window_label=clock_label(now),
                                     batch_count=batch, total=total, hosts=hosts, changes=changes,
                                     host_counts=self._host_counts(item))
        root = report["root_ts"]
        reply_ts = self._post(item, text, root, now)
        upgraded = SEVERITY_RANK.get(severity or "", 0) > SEVERITY_RANK.get(
            report.get("last_severity") or "", 0)
        try:
            self.store.set_report_state(
                item.incident_id, item.channel, last_update_epoch=now, last_count=total,
                last_hosts=hosts, last_severity=severity if upgraded else None,
                last_backfilled=self._backfilled_total(item))
        finally:
            self._finish(item, reply_ts, root, now, "update")
        if upgraded:
            self._react(item.channel, root, add=(payload.get("severity_reaction"),))
        return True

    def _backfilled_total(self, item) -> int:
        return self.store.read(
            "SELECT COUNT(*) FROM messages WHERE incident_id=? AND channel=? AND backfilled=1",
            (item.incident_id, item.channel))[0][0]

    def _backfill(self, item, now: float) -> bool:
        """One summary per (incident, channel) per backfill episode.

        Every post records how many backfilled occurrences its count already covered
        (`last_backfilled`); only those beyond it are summarised, and `last_count` grows by
        exactly them, so live occurrences stay for the next update. Within
        BACKFILL_EPISODE_SECONDS of a sent summary the new ones are folded into it silently.
        """
        report = self._report_or_wait(item, now)
        backfilled = self._backfilled_total(item)
        fresh = backfilled - (report.get("last_backfilled") or 0)
        if fresh <= 0:
            raise _Skip("補撈的告警已在先前的回報中")
        last_count = (report.get("last_count") or 0) + fresh
        if self._backfill_sent_since(item, now - BACKFILL_EPISODE_SECONDS):
            self.store.set_report_state(item.incident_id, item.channel,
                                        last_update_epoch=report["last_update_epoch"],
                                        last_count=last_count, last_backfilled=backfilled)
            raise _Skip("併入 30 分鐘內已發的補撈摘要")
        # Insertion order approximates which backfilled rows are the unaccounted ones.
        first, last = self.store.read(
            "SELECT MIN(epoch), MAX(epoch) FROM (SELECT epoch FROM messages WHERE"
            " incident_id=? AND channel=? AND backfilled=1 ORDER BY rowid DESC LIMIT ?)",
            (item.incident_id, item.channel, fresh))[0]
        text = replies.backfill_summary(count=fresh, first_ts_label=clock_label(first),
                                        last_ts_label=clock_label(last))
        root = report["root_ts"]
        reply_ts = self._post(item, text, root, now)
        try:
            self.store.set_report_state(item.incident_id, item.channel, last_update_epoch=now,
                                        last_count=last_count, last_backfilled=backfilled)
        finally:
            self._finish(item, reply_ts, root, now, "backfill")
        return True

    def _backfill_sent_since(self, item, since: float) -> bool:
        return bool(self.store.read(
            "SELECT 1 FROM outbox WHERE incident_id=? AND channel=? AND kind='backfill'"
            " AND status='sent' AND sent_epoch>=?", (item.incident_id, item.channel, since)))

    def _storm_root(self, item, now: float) -> str | None:
        rows = self.store.read(
            "SELECT reply_ts, channel, payload, status FROM outbox WHERE kind='protection'"
            " AND status IN ('pending','sent') ORDER BY id DESC LIMIT 1")
        if not rows:
            return None
        reply_ts, channel, payload, status = rows[0]
        if status == "pending":
            raise _Skip("等保護通知發出", now + WAIT_FOR_ROOT_SECONDS)
        entering = json.loads(payload).get("entering")
        return reply_ts if entering and channel == item.channel else None

    def _storm(self, item, now: float) -> bool:
        minute = int(item.payload.get("minute", now // 60))
        since, until = minute * 60, minute * 60 + 60
        rows = self.store.read(
            "SELECT m.incident_id, COUNT(*), i.check_title FROM messages m"
            " JOIN incidents i ON i.id=m.incident_id WHERE m.epoch>=? AND m.epoch<?"
            " GROUP BY m.incident_id ORDER BY COUNT(*) DESC, m.incident_id", (since, until))
        if not rows:
            raise _Skip("這一分鐘沒有告警")
        top = []
        for incident_id, count, title in rows[:STORM_TOP]:
            report = self.store.primary_report(incident_id)
            if report is not None:
                link = self.cfg.permalink(report["channel"], report["root_ts"])
            else:
                incident = self.store.get_incident(incident_id)
                link = self.cfg.permalink(incident.channel, incident.anchor_ts)
            top.append({"incident_id": incident_id, "title": title,
                        "count": count, "hosts": report.get("last_hosts") if report else None,
                        "severity": report.get("last_severity") if report else None,
                        "link": link})
        others = [{"incident_id": incident_id, "title": title, "count": count}
                  for incident_id, count, title in rows[STORM_TOP:]]
        text = replies.storm_overview(window_label=clock_label(since), top=top, others=others,
                                      total_incidents=len(rows))
        root = self._storm_root(item, now)
        reply_ts = self._post(item, text, root, now)
        self._finish(item, reply_ts, root or reply_ts, now, "storm")
        return True

    def _protection(self, item, now: float) -> bool:
        payload = item.payload
        text = replies.protection_notice(entering=bool(payload.get("entering")),
                                         reason=payload.get("reason", ""),
                                         mentions=tuple(payload.get("mentions") or ()),
                                         untag_minutes=self._untag_minutes())
        reply_ts = self._post(item, text, None, now)
        self._finish(item, reply_ts, reply_ts, now, "protection")
        return True

    def _plain(self, item, now: float) -> bool:
        payload = item.payload
        root = self._root(item)
        if root is None:
            if item.incident_id is not None and self._first_pending(item):
                raise _Skip("等首則發出", now + WAIT_FOR_ROOT_SECONDS)
            if item.kind not in ("feedback", "analysis"):
                raise _Skip("找不到要回覆的串")
        text = payload.get("text")
        if text is None and payload.get("permalink"):
            text = replies.report_link(payload["permalink"])
        if not text:
            raise _Skip("沒有內容")
        if item.kind == "analysis":
            text = replies.append_section(text, self._analysis_occurrences(item, now))
        reply_ts = self._post(item, text, root, now)
        self._finish(item, reply_ts, root or reply_ts, now, payload.get("reply_kind") or item.kind)
        if (item.kind == "analysis" and item.incident_id is not None
                and self.store.get_report(item.incident_id, item.channel) is None):
            # Green purge left no report here: the analysis' thread (or, with every alert
            # gone, the analysis itself) becomes it, so later updates have somewhere to go.
            self.store.upsert_report(item.incident_id, item.channel, root or reply_ts, now=now)
        report = (self.store.get_report(item.incident_id, item.channel)
                  if item.incident_id is not None else None)
        reaction_root = report["root_ts"] if report else root
        if reaction_root:
            self._react(item.channel, reaction_root, add=payload.get("reactions_on_root") or (),
                        remove=payload.get("remove_on_root") or ())
        return True
