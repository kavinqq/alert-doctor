"""Slack channel collector: socket/backfill intake, then classify and queue the replies.

Classification is immediate; Slack posts go through the durable outbox and are sent by
`publisher.Publisher` (one report thread per incident and channel, batched by watchdog tick).
Delivery is at-least-once. `socket_mode.run_forever` acks an envelope before the
handler runs, so a crash between ack and insert loses the event; `backfill()`
re-reads channel history to close that gap and relies on `insert_message`
ignoring duplicates.
"""
from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import importlib
import json
import logging
import math
import os
import random
import threading
import time
import urllib.error

from alert_doctor import (
    attachments, autorules, correlate, feedback, fragments, known, known_store, mentions, replies,
    schema, signals, slack_io, socket_mode, triage, tuner,
)
from alert_doctor.budget import Budgets, ProtectionMonitor
from alert_doctor.checks import lookup_check
from alert_doctor.config import unknown_check_systems
from alert_doctor.fingerprint import FINGERPRINT_VERSION, fine_fp, group_fp
from alert_doctor.known import as_source as known_source
from alert_doctor.models import Category, CheckSpec, ElkSpec, Evidence, Incident, ParsedAlert
from alert_doctor.parse import parse_message
from alert_doctor.publisher import Publisher, report_changes, severity_word
from alert_doctor.purge import Purger
from alert_doctor.rules import match_rule
from alert_doctor.slack_io import SlackRateLimited

log = logging.getLogger("alert_doctor.collector")

BASELINE_DAYS = 7
DEFAULT_BACKFILL_SECONDS = 3600
MAX_MESSAGE_ATTEMPTS = 5
# The publisher paces Slack at one post per channel per second, so the loop ticks every second.
LOOP_INTERVAL = 1
BACKFILL_INTERVAL = 300
BEAT_INTERVAL = 60
DAY_SECONDS = 86400
# Slack's history endpoint can briefly omit a just-posted message; re-reading a
# window behind the cursor catches it, and inserts are idempotent.
BACKFILL_OVERLAP_SECONDS = 300
REVIVE_INTERVAL = 3600
OUTAGE_RETRY_SECONDS = 30
TRANSPORT_ERRORS = (urllib.error.URLError, OSError, TimeoutError)
TASK_LINK_SECONDS = DAY_SECONDS
FEEDBACK_INTERVAL = 30
# One ELK magnitude query per fingerprint per minute is plenty: a burst of identical alerts
# would otherwise fire the same 60-minute aggregation dozens of times.
SIGNAL_CACHE_SECONDS = 60
SIGNAL_CACHE_MAX = 1000
SIGNAL_FAILURE_CACHE_SECONDS = 60
# Evidence and cross-system candidates describe the incident, not each message: a burst of one
# accumulated fingerprint would otherwise fire both queries once per message.
INCIDENT_ELK_INTERVAL = 600
FRESH_ANALYSIS_INTERVAL = 1800
NOISE_VERDICT_CATEGORIES = ("noise", "transient")
# Evidence that may silence an alert as noise must describe the present, not ten minutes
# ago; only this decision pays for a re-query inside the reuse window.
TRANSIENT_EVIDENCE_MAX_AGE = 120
ELK_BREAKER_THRESHOLD = 5
ELK_BREAKER_SECONDS = 120
ELK_BREAKER_ERROR = "ELK 連續失敗,暫停查詢中"
BREAKER_SIGNAL = signals.Signal(ok=False, errors=None, total=None, rate=None, duration_minutes=0,
                                hosts=0, error=ELK_BREAKER_ERROR)
# A verdict that says "real problem" means the hours around later alerts are an outage, not baseline.
UNHEALTHY_VERDICT_CATEGORIES = ("code_bug", "infra", "config", "external_dependency")
UNHEALTHY_LOOKBACK_SECONDS = 3600
FRESH_ANALYSIS_CATEGORIES = (Category.ACCUMULATED, Category.SPIKE)
ELIGIBLE_SUBTYPES = (None, "", "bot_message", "file_share")


def is_source_message(msg: dict, source_bot_ids) -> bool:
    """Only the configured alert bots count as alerts; people chatting in the channel do not.
    An empty list keeps every message (the pre-filter behaviour)."""
    return not source_bot_ids or msg.get("bot_id") in source_bot_ids
ANALYZED_STATES = ("pending", "leased", "done")
# These never wait for the rest of the wave and never fold into the storm overview.
URGENT_CATEGORIES = (Category.CRITICAL, Category.DATASOURCE)
ELK_BUDGET_ERROR = "ELK 查詢預算用完,本次不查"
BUDGET_SIGNAL = signals.Signal(ok=False, errors=None, total=None, rate=None, duration_minutes=0,
                               hosts=0, error=ELK_BUDGET_ERROR)
ACTIVE_INCIDENT_SECONDS = 600
OVERLOAD_LLM_TOP = 3
# A skipped incident still worth analysing once the storm is over.
CATCHUP_RECENT_SECONDS = 600
PRIORITY_CRITICAL, PRIORITY_MAGNITUDE, PRIORITY_NORMAL = 0, 1, 2
DEFAULT_LOOKBACK_MINUTES = 15
FINGERPRINT_SINCE_BEAT = f"fingerprint_v{FINGERPRINT_VERSION}_since"
_UNSET = object()


class Collector:
    """`slack` exposes the `slack_io` function names (default: the module itself).

    Identity: `bot_user_id` / `bot_id` come from the constructor or from `start()`,
    which calls `auth_test` once. The constructor does no network I/O.
    `run_forever` calls `start()` itself; other entry points (CLI `backfill`) must
    call it first, otherwise the bot's own messages are not filtered.

    `known` (a list of `known.KnownEntry` or a source) defaults to `cfg.known_path`,
    re-read whenever that file changes.
    """

    def __init__(
        self, cfg, store, slack, elk, rules, checks, bot_token, clock=time.time,
        *, app_token: str | None = None, bot_user_id: str | None = None,
        bot_id: str | None = None, socket_run=socket_mode.run_forever,
        signal_fn=signals.gather_signal, co_erroring=correlate.co_erroring, rng=random.random,
        budgets=None, publisher=None, monitor=None, snapshot=_UNSET, archive=_UNSET,
        watchdog=None, known=None, source_bot_token: str | None = None,
    ):
        self.cfg = cfg
        self.store = store
        self.slack = slack if slack is not None else slack_io
        self.elk = elk
        self.rules = rules
        self.checks = checks
        self.bot_token = bot_token
        self.app_token = app_token
        self.clock = clock
        self.bot_user_id = bot_user_id
        self.bot_id = bot_id
        self._socket_run = socket_run
        self._paused_until = 0.0
        self._signal_fn = signal_fn
        self._co_erroring = co_erroring
        self._rng = rng
        self._signals: dict[tuple[str, int], signals.Signal] = {}
        self._signal_failures: dict[str, tuple[float, signals.Signal]] = {}
        self._gathered: dict[int, tuple[float, Evidence]] = {}
        self._candidates_at: dict[int, float] = {}
        self._elk_failures = 0
        self._elk_open_until = float("-inf")
        self._v2_earliest: float | None = None
        self._fp_version_since: float | None = None
        self.budgets = budgets if budgets is not None else Budgets(cfg)
        self.publisher = publisher if publisher is not None else Publisher(
            cfg, store, self.slack, bot_token, self.budgets, clock)
        self.monitor = monitor if monitor is not None else ProtectionMonitor(cfg)
        self.purger = Purger(cfg, store, self.slack, bot_token, source_bot_token, self.budgets,
                             checks, clock)
        self._overload = False
        # Per overload episode, in memory: a restart mid-storm only forgets which incidents were
        # skipped, and those still get analysed on their next occurrence after the storm.
        self._episode_rank: dict[int, tuple] = {}
        self._episode_skipped: set[int] = set()
        # Snapshot and archive are optional companions: loaded by `start()` / the service loop
        # unless injected, and every use tolerates them being absent.
        self._watchdog = watchdog
        self._snapshot = None if snapshot is _UNSET else snapshot
        self._snapshot_pending = snapshot is _UNSET
        self._archive = None if archive is _UNSET else archive
        self._archive_pending = archive is _UNSET
        self._known = known_source(known if known is not None else getattr(cfg, "known_path", ""))
        schema.ensure_all(store)
        known_store.ensure_schema(store)

    def start(self) -> None:
        info = self.slack.auth_test(self.bot_token)
        self.bot_user_id = info.get("user_id")
        self.bot_id = info.get("bot_id")
        mentions.warm(self.slack, self.bot_token, self.cfg, self.checks)
        for problem in unknown_check_systems(self.cfg, self.checks):
            log.error(problem)
        self._load_snapshot()

    def _watchdog_module(self):
        if self._watchdog is None:
            try:
                self._watchdog = importlib.import_module("alert_doctor.watchdog")
            except ImportError as exc:
                log.warning("watchdog 模組無法載入:%s", exc)
                self._watchdog = False
        return self._watchdog or None

    def _load_snapshot(self) -> None:
        if not self._snapshot_pending:
            return
        self._snapshot_pending = False
        module = self._watchdog_module()
        if module is None:
            return
        path = getattr(self.cfg, "watchdog_snapshot_path", "")
        try:
            self._snapshot = module.load_snapshot(path)
        except Exception as exc:
            log.warning("watchdog 快照 %s 載入失敗:%s", path, exc)
        if self._snapshot is None:
            log.warning("沒有 watchdog 快照(%s),排程名稱與 keywords 查詢退回告警本身的資訊", path)

    def _open_archive(self) -> None:
        """Only the service loop records occurrences: replay and CLI runs must not write
        rehearsal data into the long-lived error archive."""
        if not self._archive_pending:
            return
        self._archive_pending = False
        path = getattr(self.cfg, "archive_db_path", "")
        try:
            self._archive = importlib.import_module("alert_doctor.archive").Archive(path)
        except Exception as exc:
            log.warning("錯誤資料庫 %s 無法開啟:%s", path, exc)

    # ---------- intake ----------

    def _eligible(self, msg: dict) -> bool:
        if msg.get("subtype") not in ELIGIBLE_SUBTYPES:
            return False
        thread_ts = msg.get("thread_ts")
        if thread_ts and thread_ts != msg.get("ts"):
            return False
        if self.bot_user_id and msg.get("user") == self.bot_user_id:
            return False
        if self.bot_id and msg.get("bot_id") == self.bot_id:
            return False
        if not is_source_message(msg, getattr(self.cfg, "source_bot_ids", ())):
            return False
        return bool(msg.get("ts"))

    def _insert(self, channel: str, msg: dict) -> bool:
        text = msg.get("text") or ""
        alert = parse_message(channel, msg["ts"], text, redact_pii=self.cfg.redact_pii)
        if msg.get("files"):
            attachments.save_files(self.store, channel, msg["ts"], msg["files"])
        now = self.clock()
        bot_id = msg.get("bot_id")
        inserted = self.store.insert_message(alert, now, bot_id=bot_id, text_len=len(text))
        if not inserted:
            return False
        if bot_id and self._joined_as_fragment(alert, bot_id, now, len(text)):
            return True
        if not self._lagging(alert.epoch, now):
            self.store.bump_counter("intake", 1, now)
        return True

    # ---------- split messages ----------

    def _join_seconds(self) -> float:
        return getattr(self.cfg, "fragment_join_seconds", fragments.DEFAULT_JOIN_SECONDS)

    def _joined_as_fragment(self, alert: ParsedAlert, bot_id: str, now: float,
                            text_len: int) -> bool:
        """Join a just-inserted bot message to the alert Slack split it from (see fragments.py).

        True when it became a fragment. An incomplete head waits `fragment_join_seconds` after
        its last piece; an orphan piece waits as long, since socket events can arrive out of
        order and its head may still claim it. A piece whose head was already handled is
        appended to it (`_late_fragment`). Never raises: joining is best-effort.
        """
        try:
            if fragments.looks_like_head(alert.raw_text):
                if not fragments.is_complete(alert):
                    self._claim_followers(alert, bot_id, now, text_len)
                    self._settle_head(alert.channel, alert.ts, now)
                return False
            head_ts = self._open_head(alert, bot_id)
            if head_ts is None:
                self.store.schedule_message(alert.channel, alert.ts, now + self._join_seconds())
                return False
            handled = self.store.read("SELECT status='handled' FROM messages WHERE channel=? AND ts=?",
                                      (alert.channel, head_ts))[0][0]
            self.store.mark_fragment(alert.channel, alert.ts, head_ts, now)
            if handled:
                try:
                    self._late_fragment(alert, head_ts, now)
                except Exception as exc:
                    log.warning("晚到的分段 %s 補入 %s 失敗:%s", alert.ts, head_ts, exc)
            else:
                self._settle_head(alert.channel, head_ts, now)
            return True
        except Exception as exc:
            log.warning("分段訊息 %s 合併失敗:%s", alert.ts, exc)
            return False

    def _joined_alert(self, channel: str, head_ts: str) -> ParsedAlert | None:
        text = self.store.joined_text(channel, head_ts)
        if text is None:
            return None
        return parse_message(channel, head_ts, text, redact_pii=self.cfg.redact_pii)

    def _open_head(self, alert: ParsedAlert, bot_id: str) -> str | None:
        """ts of the incomplete head whose last piece is within the join window, else None."""
        previous = self.store.bot_message_before(alert.channel, bot_id, alert.ts)
        if (previous is None or alert.epoch - previous["epoch"] > self._join_seconds()
                or not fragments.is_split_piece(previous["text_len"])):
            return None
        head_ts = previous["fragment_of"]
        if head_ts is None:
            if not fragments.looks_like_head(previous["raw_text"]):
                return None
            head_ts = previous["ts"]
        joined = self._joined_alert(alert.channel, head_ts)
        return head_ts if joined is not None and not fragments.is_complete(joined) else None

    def _claim_followers(self, head: ParsedAlert, bot_id: str, now: float, head_len: int) -> None:
        last, last_len = head.epoch, head_len
        for row in self.store.bot_messages_after(head.channel, bot_id, head.ts):
            if (not row["free"] or row["epoch"] - last > self._join_seconds()
                    or not fragments.is_split_piece(last_len)
                    or fragments.looks_like_head(row["raw_text"])):
                return
            self.store.mark_fragment(head.channel, row["ts"], head.ts, now)
            last, last_len = row["epoch"], row["text_len"]

    def _settle_head(self, channel: str, head_ts: str, now: float) -> None:
        joined = self._joined_alert(channel, head_ts)
        if joined is None:
            return
        wait = 0 if fragments.is_complete(joined) else self._join_seconds()
        self.store.schedule_message(channel, head_ts, now + wait)

    def _late_fragment(self, piece: ParsedAlert, head_ts: str, now: float) -> None:
        """Append a piece that arrived after its head was handled and say so in the head's
        report thread. The head is not analysed again; a changed error_key is only recorded
        (archive and the `late_fragment_rekeyed` counter)."""
        channel = piece.channel
        old = self.store.get_message(channel, head_ts)
        assembled, raw_text, incident_id, category = self.store.read(
            "SELECT assembled, raw_text, incident_id, category FROM messages WHERE channel=? AND ts=?",
            (channel, head_ts))[0]
        # Once assembled the head row holds the joined text, so only the new piece is missing.
        text = raw_text + piece.raw_text if assembled else self.store.joined_text(channel, head_ts)
        joined = parse_message(channel, head_ts, text, redact_pii=self.cfg.redact_pii)
        self.store.store_assembled(joined)
        pieces = 1 + self.store.read("SELECT COUNT(*) FROM messages WHERE channel=? AND fragment_of=?",
                                     (channel, head_ts))[0][0]
        task_pk = known_store.task_pk_of(joined)
        source_system = self._source_system(joined, lookup_check(self.checks, joined))
        old_key = known_store.alert_error_key(old, task_pk, source_system)
        new_key = known_store.alert_error_key(joined, task_pk, source_system)
        if old_key != new_key:
            log.info("告警 %s 補入晚到的分段後 error_key %s → %s,不重新分析", head_ts, old_key, new_key)
            self.store.bump_counter("late_fragment_rekeyed", 1, now)
        if self._archive is not None:
            incident = self.store.get_incident(incident_id) if incident_id is not None else None
            try:
                self._archive.record_occurrence(
                    joined, incident=incident, category=category or "", severity=None,
                    source_system=source_system, task_label=self._label(joined, None),
                    task_pk=task_pk)
            except Exception as exc:
                log.warning("錯誤資料庫更新 %s 失敗:%s", head_ts, exc)
        if self.purger.join_fragment(channel, head_ts, piece.ts, now):
            return
        if incident_id is None:
            return
        self.store.enqueue_reply(
            incident_id=incident_id, channel=channel, kind="late_fragment", priority=2,
            due_epoch=now, payload={"text": f"📎 此告警後段晚到,已補入(共 {pieces} 段)"},
            dedupe_key=f"late_fragment:{channel}:{head_ts}", now=now)

    def _assembled(self, alert: ParsedAlert) -> ParsedAlert:
        """The head with its fragments joined in, stored once so a retry does not append twice."""
        if not self.store.has_unassembled_fragments(alert.channel, alert.ts):
            return alert
        joined = self._joined_alert(alert.channel, alert.ts)
        self.store.store_assembled(joined)
        return joined

    def _lagging(self, epoch: float, received: float) -> bool:
        return received - epoch > getattr(self.cfg, "backfill_lag_seconds", 120)

    def _backfilled(self, alert: ParsedAlert) -> bool:
        rows = self.store.read("SELECT received_epoch FROM messages WHERE channel=? AND ts=?",
                               (alert.channel, alert.ts))
        return bool(rows) and self._lagging(alert.epoch, rows[0][0])

    def on_socket_event(self, kind: str, payload: dict) -> None:
        """Parse and insert only; classification happens in `process_pending`."""
        if kind != "events_api":
            return
        event = (payload or {}).get("event") or {}
        if event.get("type") == "reaction_added":
            self.on_reaction(event)
            return
        if event.get("type") == "app_mention":
            self.on_mention(event)
            return
        if event.get("type") != "message" or event.get("channel") not in self.cfg.channel_ids:
            return
        if self._eligible(event):
            self._insert(event["channel"], event)

    def on_mention(self, event: dict) -> None:
        """Known-error commands (`固定錯誤` / `取消固定` / `查`) mentioned in a watched channel.

        Runs in the socket thread, which has already acked the envelope: database work only,
        the reply goes through the outbox. Never raises.
        """
        channel = event.get("channel")
        user = event.get("user")
        if channel not in self.cfg.channel_ids or not user or not event.get("ts"):
            return
        if user == self.bot_user_id or (self.bot_id and event.get("bot_id") == self.bot_id):
            return
        parsed = known_store.parse_command(event.get("text") or "")
        if parsed is None:
            return
        thread_ts = event.get("thread_ts") or event["ts"]
        now = self.clock()
        try:
            alert = self._thread_alert(channel, event.get("thread_ts"))
            source_system = (self._source_system(alert, lookup_check(self.checks, alert))
                             if alert is not None else "")
            text = known_store.handle_command(
                self.store, *parsed, alert=alert, user=user, now=now, source_system=source_system,
                can_edit=user in (getattr(self.cfg, "known_editors", ()) or ()))
            self.store.enqueue_reply(
                incident_id=None, channel=channel, kind="feedback", priority=1, due_epoch=now,
                payload={"text": text}, thread_ts=thread_ts,
                dedupe_key=f"known:{channel}:{event['ts']}", now=now)
        except Exception as exc:
            log.warning("固定錯誤指令 %s 處理失敗:%s", event.get("ts"), exc)

    def _thread_alert(self, channel: str, thread_ts: str | None) -> ParsedAlert | None:
        """The alert a thread hangs off: its root message, else the anchor of the incident
        whose report thread it is."""
        if not thread_ts:
            return None
        found = self.store.get_message(channel, thread_ts)
        if found is not None:
            return found
        reports = self.store.read(
            "SELECT incident_id FROM reports WHERE channel=? AND root_ts=?", (channel, thread_ts))
        return self.store.first_message(reports[0][0]) if reports else None

    def on_reaction(self, event: dict) -> None:
        """Park a `reaction_added` event in the inbox; feedback processing reads it later."""
        item = event.get("item") or {}
        if item.get("type") != "message" or item.get("channel") not in self.cfg.channel_ids:
            return
        user = event.get("user")
        # The bot's own status reactions (mag, repeat, ...) arrive here too.
        if not user or user == self.bot_user_id or not item.get("ts") or not event.get("reaction"):
            return
        try:
            epoch = float(event.get("event_ts"))
        except (TypeError, ValueError):
            epoch = self.clock()
        self.store.add_reaction_inbox(item["channel"], item["ts"], user, event["reaction"], epoch)

    def backfill(self, since: float | None = None) -> int:
        """Insert history of every channel newer than `since` (default: each channel's cursor, else now-1h).

        The cursor advances over every message seen, eligible or not, so ignored
        messages are not refetched. Returns the number of newly inserted messages.
        A failing channel does not stop the others; its error is re-raised at the end.
        """
        added = 0
        failure: Exception | None = None
        for channel in sorted(self.cfg.channel_ids):
            try:
                added += self._backfill_channel(channel, since)
                self.store.beat(f"backfill:{channel}", self.clock())
            except Exception as exc:
                log.warning("backfill %s failed: %s", channel, exc)
                failure = failure or exc
        if failure is not None:
            raise failure
        return added

    def _backfill_channel(self, channel: str, since: float | None) -> int:
        if since is not None:
            oldest = f"{since:.6f}"
        else:
            cursor = self.store.get_cursor(channel)
            start = float(cursor) - BACKFILL_OVERLAP_SECONDS if cursor else self.clock() - DEFAULT_BACKFILL_SECONDS
            oldest = f"{start:.6f}"
        messages = self.slack.history(self.bot_token, channel, oldest)
        added = 0
        for msg in messages:
            if self._eligible(msg) and self._insert(channel, msg):
                added += 1
        if messages:
            self.store.set_cursor(channel, max((m["ts"] for m in messages), key=float))
        return added

    # ---------- processing ----------

    def _spike(self, fp: str, at: float) -> bool:
        window = self.cfg.spike_window_minutes * 60
        # +1: the message being processed is not handled yet, so the store excludes it.
        current = self.store.count_messages(fp, at - window, at) + 1
        # Days before v2 fingerprints existed would read as zero errors and make
        # every burst in the first week look like a spike.
        earliest = max(self._v2_start() or at, self._fingerprint_since(at))
        baseline = [
            self.store.count_messages(fp, at - d * DAY_SECONDS - window, at - d * DAY_SECONDS)
            for d in range(1, BASELINE_DAYS + 1)
            if at - d * DAY_SECONDS - window >= earliest
        ]
        return triage.detect_spike(current, baseline)

    def _v2_start(self) -> float | None:
        """Epoch of the earliest message handled with a v2 fingerprint.

        v1 incidents have an empty source_system and their messages carry v1 fingerprints, so
        an upgraded database must not count those days as a zero baseline. Cached once known:
        it only moves if older history is handled later, which backfill does not do.
        """
        if self._v2_earliest is None:
            self._v2_earliest = self.store.read(
                "SELECT MIN(m.epoch) FROM messages m JOIN incidents i ON i.id = m.incident_id"
                " WHERE m.fingerprint IS NOT NULL AND i.source_system != ''")[0][0]
        return self._v2_earliest

    def _fingerprint_since(self, epoch: float) -> float:
        """Epoch of the first message handled with the current FINGERPRINT_VERSION, set by
        the first call: messages before it carry fingerprints of an older version."""
        if self._fp_version_since is None:
            with self.store.tx() as db:
                db.execute("INSERT OR IGNORE INTO beats (component, at) VALUES (?,?)",
                           (FINGERPRINT_SINCE_BEAT, epoch))
            self._fp_version_since = self.store.last_beat(FINGERPRINT_SINCE_BEAT)
        return self._fp_version_since

    # ---------- ELK cost control ----------

    def _elk_available(self) -> bool:
        return self.clock() >= self._elk_open_until

    def _elk_budget(self, critical: bool) -> bool:
        now = self.clock()
        if self.budgets.elk.take("critical" if critical else "normal", now):
            return True
        self.store.bump_counter("elk_skipped", 1, now)
        return False

    def _elk_outcome(self, ok: bool) -> None:
        if ok:
            self._elk_failures = 0
            return
        self._elk_failures += 1
        if self._elk_failures >= ELK_BREAKER_THRESHOLD:
            self._elk_open_until = self.clock() + ELK_BREAKER_SECONDS
            log.warning("ELK 連續失敗 %d 次,暫停查詢 %d 秒", self._elk_failures, ELK_BREAKER_SECONDS)
            # Half-open once the pause ends: a single further failure pauses again.
            self._elk_failures = ELK_BREAKER_THRESHOLD - 1

    @staticmethod
    def _prune(cache: dict, now: float, max_age: float, stamp=lambda v: v) -> None:
        if len(cache) >= SIGNAL_CACHE_MAX:
            for key in [k for k, v in cache.items() if now - stamp(v) >= max_age]:
                del cache[key]

    @staticmethod
    def _vkwargs(alert: ParsedAlert) -> dict:
        vkwargs = alert.extra.get("vkwargs")
        return vkwargs if isinstance(vkwargs, dict) else {}

    def _known_hit(self, alert: ParsedAlert, source_system: str, task_pk: int | None):
        """The error's linked known entry, else a matching action "known" window, else None.
        A broken knowledge base never blocks intake."""
        try:
            key = known_store.alert_error_key(alert, task_pk, source_system)
            linked = known_store.lookup(self.store, key, alert.epoch)
            if linked is not None:
                return linked
            return known.match_known(self._known.entries(), alert, alert.epoch, source_system,
                                     action="known")
        except Exception as exc:
            log.warning("固定錯誤比對 %s 失敗:%s", alert.ts, exc)
            return None

    def _source_system(self, alert: ParsedAlert, check) -> str:
        if check and check.system:
            return check.system
        channel = self.cfg.channel(alert.channel)
        return channel.systems[0] if channel and channel.systems else ""

    @staticmethod
    def _fingerprint(alert: ParsedAlert, source_system: str) -> str:
        # fingerprint.py stays untouched: the same message text from two systems is two problems.
        return hashlib.sha1(f"{fine_fp(alert)}|{source_system}".encode("utf-8")).hexdigest()

    def _task_incident(self, alert: ParsedAlert) -> Incident | None:
        if not alert.task_id:
            return None
        incident = self.store.incident_for_task(alert.task_id, alert.epoch - TASK_LINK_SECONDS)
        # Guard: a task_id that is reused by a different check must not glue unrelated alerts together.
        if incident and (incident.check_code, incident.check_title) == (alert.check_code, alert.check_title):
            return incident
        return None

    def _incident_for(
        self, alert: ParsedAlert, fp: str, source_system: str, task_pk: int | None = None,
    ) -> tuple[Incident, bool]:
        """Same occurrence > same watchdog run (task_id, across channels) > same crontab task
        (its message text embeds the first ELK hit, so the fingerprint varies) > fingerprint."""
        known_id = self.store.message_incident(alert.channel, alert.ts)
        if known_id is not None:
            incident = self.store.get_incident(known_id)
            return incident, incident.anchor_ts == alert.ts
        by_task = self._task_incident(alert)
        if by_task is not None:
            return self.store.attach(by_task.id, alert), False
        incident = None
        if task_pk is not None:
            incident = self.store.open_incident_for_task(
                task_pk, alert.check_code, alert.level, now=alert.epoch,
                idle_minutes=self.cfg.idle_minutes)
        if incident is None:
            incident = self.store.open_incident(fp, alert.epoch, self.cfg.idle_minutes)
        if incident is None:
            return self.store.create_incident(
                alert, fp, group_fp(alert), source_system=source_system), True
        if incident.anchor_ts == alert.ts:
            return incident, True
        return self.store.attach(incident.id, alert), False

    def _gather(self, alert, check, rule, incident, is_new, spike, critical=False):
        wants = is_new or spike or bool(rule and rule.require_transient)
        if not (wants and check and check.elk):
            return None
        now = self.clock()
        recent = self._gathered.get(incident.id)
        max_age = TRANSIENT_EVIDENCE_MAX_AGE if rule and rule.require_transient else INCIDENT_ELK_INTERVAL
        if recent is not None and now - recent[0] < max_age:
            return recent[1]
        if not self._elk_available():
            return Evidence(query_ok=False, window_from="", window_to="", error=ELK_BREAKER_ERROR)
        if not self._elk_budget(critical):
            return Evidence(query_ok=False, window_from="", window_to="", error=ELK_BUDGET_ERROR)
        evidence = self.elk.gather(check.elk, alert.epoch, self._vkwargs(alert))
        self._elk_outcome(evidence.query_ok)
        self._prune(self._gathered, now, INCIDENT_ELK_INTERVAL, stamp=lambda v: v[0])
        self._gathered[incident.id] = (now, evidence)
        existing = self.store.load_evidence(incident.id)
        # A failed query must not overwrite the evidence an earlier alert collected; keys added
        # by the collector itself (candidates, attachments, signal) survive either way.
        if evidence.query_ok or existing is None or "query_ok" not in existing:
            self.store.save_evidence(incident.id, {**(existing or {}), **evidence.to_dict()})
        return evidence

    def _merge_evidence(self, incident_id: int, extra: dict) -> None:
        body = self.store.load_evidence(incident_id) or {}
        body.update(extra)
        self.store.save_evidence(incident_id, body)

    def _signal(self, check, alert: ParsedAlert, fp: str, critical: bool = False):
        if not (check and check.elk):
            return None
        key = (fp, int(alert.epoch // SIGNAL_CACHE_SECONDS))
        cached = self._signals.get(key)
        if cached is not None:
            return cached
        now = self.clock()
        failed = self._signal_failures.get(fp)
        if failed is not None and now < failed[0]:
            return failed[1]
        if not self._elk_available():
            return BREAKER_SIGNAL
        if not self._elk_budget(critical):
            return BUDGET_SIGNAL
        found = self._signal_fn(self.elk, check, alert.epoch, variables=self._vkwargs(alert))
        self._elk_outcome(found.ok)
        if len(self._signals) >= SIGNAL_CACHE_MAX:
            self._signals.clear()
        if found.ok:
            self._signals[key] = found
            self._signal_failures.pop(fp, None)
        else:
            self._prune(self._signal_failures, now, 0, stamp=lambda v: v[0])
            self._signal_failures[fp] = (now + SIGNAL_FAILURE_CACHE_SECONDS, found)
        return found

    def _accumulated(self, signal, check, fp: str, epoch: float, never_silence: bool) -> bool:
        if signal is None or check is None:
            return False
        baseline = tuner.baseline_for(self.store, fp, epoch)
        return tuner.is_accumulated(signal, baseline, min_errors=check.min_errors,
                                    never_silence=never_silence)

    def _previous_analysis_link(self, fingerprint: str, fallback: str) -> str:
        rows = self.store.read(
            "SELECT channel, anchor_ts FROM incidents WHERE fingerprint=? AND analysis_state='done'"
            " ORDER BY completed_epoch DESC, id DESC LIMIT 1", (fingerprint,))
        return self.cfg.permalink(rows[0][0], rows[0][1]) if rows else fallback

    def _candidates(self, incident: Incident, alert: ParsedAlert, source_system: str,
                    critical: bool = False) -> None:
        """Clues for the analyzer; an ELK problem here must never block the reply."""
        systems = correlate.with_elk_project(self.cfg.systems)
        if not systems:
            return
        now = self.clock()
        last = self._candidates_at.get(incident.id)
        if last is not None and now - last < INCIDENT_ELK_INTERVAL:
            return
        if not self._elk_available() or not self._elk_budget(critical):
            return
        self._prune(self._candidates_at, now, INCIDENT_ELK_INTERVAL)
        self._candidates_at[incident.id] = now
        try:
            found = self._co_erroring(self.elk, systems, alert.epoch, exclude=source_system)
        except Exception as exc:
            self._elk_outcome(False)
            log.warning("co_erroring failed for incident %s: %s", incident.id, exc)
            return
        self._elk_outcome(True)
        self._merge_evidence(incident.id, {"candidates": [dataclasses.asdict(c) for c in found]})

    def _attachments(self, incident: Incident, alert: ParsedAlert) -> None:
        files = attachments.files_for(self.store, alert.channel, alert.ts)
        if not files:
            return
        dest = os.path.join(self.cfg.runs_dir, str(incident.id), "attachments")
        summaries = attachments.fetch(self.slack, self.bot_token, files, dest,
                                      redact_pii=self.cfg.redact_pii)
        body = self.store.load_evidence(incident.id) or {}
        merged = {a["name"]: a for a in body.get("attachments") or []}
        merged.update({a["name"]: a for a in summaries})
        self._merge_evidence(incident.id, {"attachments": list(merged.values())})

    def _auto_rule_effect(self, decision, hit, fingerprint: str, incident: Incident,
                          alert: ParsedAlert, accumulated: bool) -> None:
        if hit is None:
            return
        if decision.auto_effect == "invalidate":
            reason = "量級升級" if accumulated else "check 屬 never_silence"
            autorules.invalidate(self.store, fingerprint, reason, self.clock())
        elif decision.auto_effect == "sample":
            autorules.record_sample(self.store, hit.rule.id, incident.id, alert.channel, alert.ts,
                                    self.clock())

    def _persisted_sample(self, hit, alert: ParsedAlert):
        """A retry must keep the sample decision recorded by the failed attempt, not re-roll it."""
        if hit is None or not hit.active or hit.sample:
            return hit
        rows = self.store.read(
            "SELECT rule_id FROM auto_samples WHERE channel=? AND message_ts=?",
            (alert.channel, alert.ts))
        if rows and rows[0][0] == hit.rule.id:
            return dataclasses.replace(hit, sample=True)
        return hit

    def _request_analysis(self, incident_id: int, fresh: bool,
                          priority: int = PRIORITY_NORMAL) -> None:
        now = self.clock()
        state = self.store.read("SELECT analysis_state FROM incidents WHERE id=?", (incident_id,))
        if (state and state[0][0] not in ("pending", "leased")
                and not self.budgets.llm.take("normal", now)):
            # Rate is only observed here: dropping the request would leave the incident
            # unanalysed, and the analyzer's daily quota already caps the cost.
            self.store.bump_counter("llm_deferred", 1, now)
        base = {"min_interval": self.cfg.verdict_reuse_hours * 3600, "now": now}
        kwargs = {**base, "priority": priority}
        if fresh:
            # Every message of a sustained spike asks again. A recent verdict that already calls
            # it a real problem is enough for the window; a recent "noise" verdict is exactly what
            # the spike contradicts, so that one is re-examined at once.
            rows = self.store.read("SELECT completed_epoch, verdict FROM incidents WHERE id=?",
                                   (incident_id,))
            completed, verdict = rows[0] if rows else (None, None)
            verdict = json.loads(verdict) if verdict else {}
            # A green verdict ("low, just observe") is as contradicted by a spike as "noise".
            dismissed = (verdict.get("category") in NOISE_VERDICT_CATEGORIES
                         or (verdict.get("severity"), verdict.get("action")) == ("low", "observe"))
            if completed is not None and now - completed < FRESH_ANALYSIS_INTERVAL and not dismissed:
                fresh = False
        try:
            self.store.request_analysis(incident_id, fresh=fresh, **kwargs)
        except TypeError:
            # A store that predates `fresh` / `priority`; a plain request is still better than none.
            self.store.request_analysis(incident_id, **base)

    @staticmethod
    def _analysis_priority(decision, never_silence: bool, magnitude: bool) -> int:
        if decision.category == Category.CRITICAL or never_silence:
            return PRIORITY_CRITICAL
        if magnitude or decision.category in FRESH_ANALYSIS_CATEGORIES:
            return PRIORITY_MAGNITUDE
        return PRIORITY_NORMAL

    def _overload_rank(self, incident: Incident, priority: int, signal) -> tuple:
        """CRITICAL/never_silence > accumulated or spiking > host count > occurrence count.

        Per-message ELK is off while overloaded, so magnitude and hosts come from what the
        incident showed earlier (message categories, the last reported host count).
        """
        magnitude = priority <= PRIORITY_MAGNITUDE or bool(self.store.read(
            "SELECT 1 FROM messages WHERE incident_id=? AND category IN (?,?) LIMIT 1",
            (incident.id, Category.ACCUMULATED.value, Category.SPIKE.value)))
        if signal is not None and signal.ok:
            hosts = signal.hosts or 0
        else:
            hosts = self.store.read("SELECT COALESCE(MAX(last_hosts), 0) FROM reports"
                                    " WHERE incident_id=?", (incident.id,))[0][0]
        return (priority == PRIORITY_CRITICAL, magnitude, hosts, incident.count)

    def _overload_allows_analysis(self, incident: Incident, rank: tuple) -> bool:
        self._episode_rank[incident.id] = max(self._episode_rank.get(incident.id, rank), rank)
        # Ties go to the earlier incident: it has waited longer.
        top = sorted(self._episode_rank, key=lambda i: (self._episode_rank[i], -i),
                     reverse=True)[:OVERLOAD_LLM_TOP]
        if incident.id in top:
            self._episode_skipped.discard(incident.id)
            return True
        self._episode_skipped.add(incident.id)
        self.store.bump_counter("llm_skipped_overload", 1, self.clock())
        return False

    def _analyse_skipped(self, now: float) -> None:
        for incident_id in sorted(self._episode_skipped):
            incident = self.store.get_incident(incident_id)
            if incident is not None and incident.last_epoch >= now - CATCHUP_RECENT_SECONDS:
                self._request_analysis(incident_id, False, PRIORITY_NORMAL)

    def _enqueue_catchup(self, since: float | None, now: float) -> None:
        """Counts folded into storm overviews land in each incident's own report thread."""
        if since is None:
            return
        for incident_id, channel in self.store.incidents_needing_catchup(since):
            report = self.store.get_report(incident_id, channel) or {}
            self.store.enqueue_reply(
                incident_id=incident_id, channel=channel, kind="update",
                priority=PRIORITY_NORMAL, due_epoch=now,
                dedupe_key=f"update:{incident_id}:{channel}", now=now,
                payload={"hosts": report.get("last_hosts"),
                         "severity": report.get("last_severity"), "severity_reaction": None})

    def _task(self, alert: ParsedAlert):
        """(crontab_task_pk, TaskInfo or None); a pk the snapshot does not know is counted."""
        pk = self._vkwargs(alert).get("crontab_task_pk")
        try:
            pk = int(pk) if pk is not None else None
        except (TypeError, ValueError):
            pk = None
        if self._snapshot is None:
            return pk, None
        try:
            task = self._snapshot.task_for_alert(alert)
        except Exception as exc:
            log.warning("快照查詢排程 %s 失敗:%s", pk, exc)
            task = None
        if pk is not None and task is None:
            self.store.bump_counter("unknown_task", 1, self.clock())
        return pk, task

    def _label(self, alert: ParsedAlert, task) -> str:
        module = self._watchdog_module()
        if module is not None and self._snapshot is not None:
            try:
                return module.alert_label(alert, self._snapshot)
            except Exception as exc:
                log.warning("alert_label 失敗:%s", exc)
        return task.label if task is not None else alert.check_title

    def _with_kwargs_elk(self, check, alert: ParsedAlert, task):
        """Give check_log_message its own ELK query from its keywords when checks.toml
        configures none, so it gets evidence and a magnitude signal too."""
        if check is not None and check.elk is not None:
            return check
        module = self._watchdog_module()
        if module is None or alert.check_code not in getattr(module, "KEYWORD_QUERY_CODES", ()):
            return check
        kwargs = self._vkwargs(alert)
        if not kwargs.get("keywords") and task is not None:
            kwargs = task.kwargs or {}
        if not kwargs.get("keywords"):
            return check
        try:
            query = module.elk_query_from_kwargs(kwargs)
            index = module.elk_index_for(kwargs)
        except Exception as exc:
            log.warning("由 keywords 產生 ELK 查詢失敗:%s", exc)
            return check
        if not query:
            return check
        try:
            lookback = int(kwargs.get("interval") or DEFAULT_LOOKBACK_MINUTES)
        except (TypeError, ValueError):
            lookback = DEFAULT_LOOKBACK_MINUTES
        spec = ElkSpec(index=index, query=query, host_field="auto", lookback_minutes=lookback)
        if check is None:
            return CheckSpec(key=alert.check_code or alert.check_title, elk=spec)
        return dataclasses.replace(check, elk=spec)

    def _handle(self, alert: ParsedAlert) -> None:
        cfg = self.cfg
        alert = self._assembled(alert)
        overload = self._overload
        backfilled = self._backfilled(alert)
        task_pk, task = self._task(alert)
        check = self._with_kwargs_elk(lookup_check(self.checks, alert), alert, task)
        source_system = self._source_system(alert, check)
        fp = self._fingerprint(alert, source_system)
        incident, is_new = self._incident_for(alert, fp, source_system, task_pk)
        anchor_link = cfg.permalink(incident.channel, incident.anchor_ts)
        # Task-linked alerts from other channels join this incident, so its fingerprint is the
        # one series that magnitude, baselines and auto rules must all use.
        series_fp = incident.fingerprint
        rule = match_rule(self.rules, alert, self.clock())
        # A datasource failure never reached the system: no ELK, magnitude or auto-rule work.
        datasource = bool(rule and rule.action == "datasource")
        never_silence = bool((check and check.never_silence) or (rule and rule.action == "never_silence"))
        known_hit = None if datasource or never_silence else self._known_hit(alert, source_system, task_pk)
        if datasource:
            spike, signal, accumulated, hit = False, None, False, None
        else:
            spike = self._spike(fp, alert.epoch)
            # Overload: no per-message ELK and no auto-rule sampling/shadow writes. Without a
            # signal and a rule hit nothing can be silenced, so degrading stays on the safe side.
            signal = None if overload else self._signal(check, alert, series_fp, never_silence)
            accumulated = self._accumulated(signal, check, series_fp, alert.epoch, never_silence)
            hit = None
            # A maintenance window answers the alert itself; auto rules must neither sample nor
            # count it, or the window would teach them to silence the same error at noon.
            if not overload and known_hit is None:
                hit = autorules.match(self.store, series_fp, self.clock(),
                                      cfg.shadow_sample_rate, self._rng)
                hit = self._persisted_sample(hit, alert)
        auto_link = ""
        if hit is not None and hit.active and hit.rule.kind == "known":
            auto_link = self._previous_analysis_link(incident.fingerprint, anchor_link)
        # A known hit still escalates on magnitude, and that analysis needs its evidence.
        known_silences = known_hit is not None and not (spike or accumulated)
        evidence = None if datasource or known_silences else self._gather(
            alert, check, rule, incident, is_new, spike or accumulated, never_silence)
        # Owners are tagged once, on the incident's first report, never inside the decision text.
        decision = triage.classify(
            alert, is_new_incident=is_new, spike=spike, rule=rule, check=check,
            evidence=evidence, incident=incident, permalink=anchor_link,
            accumulated=accumulated, signal=signal, auto_hit=hit, auto_link=auto_link,
            owners=(), elk_failed=signal is not None and not signal.ok, known_hit=known_hit,
        )
        text, reaction, kind = decision.reply_text, decision.reaction, "triage"
        if spike and not is_new and decision.category == Category.CRITICAL:
            text = f"{text}\n{replies.spike_followup(incident, anchor_link)}"
        elif spike and not is_new and decision.category == Category.SPIKE:
            text = replies.spike_followup(incident, anchor_link)
            reaction = replies.SPIKE_FOLLOWUP_REACTION
        elif (decision.category == Category.ACCUMULATED and not is_new
              and incident.analysis_state in ANALYZED_STATES):
            text = replies.accumulated_followup(incident, anchor_link)
        elif decision.category == Category.DUPLICATE and incident.channel != alert.channel:
            text = f"🔁 同一事件已在 {anchor_link} 分析"
            kind = "followup"
        if decision.auto_effect == "sample":
            kind = feedback.SAMPLE_REPLY_KINDS[0]
        if alert.truncated:
            text = f"{text}\n{replies.TRUNCATED_NOTE}"
        self._auto_rule_effect(decision, hit, incident.fingerprint, incident, alert, accumulated)
        if decision.needs_analysis:
            # Everything the analyzer reads goes in before the request: it may claim at once.
            if (is_new or spike or accumulated) and not overload:
                self._candidates(incident, alert, source_system, never_silence)
            if accumulated:
                self._merge_evidence(incident.id, {"signal": signal.to_dict()})
        self._attachments(incident, alert)
        if decision.needs_analysis:
            priority = self._analysis_priority(decision, never_silence, spike or accumulated)
            if not overload or self._overload_allows_analysis(
                    incident, self._overload_rank(incident, priority, signal)):
                self._request_analysis(incident.id, decision.category in FRESH_ANALYSIS_CATEGORIES,
                                       priority)
        label = self._label(alert, task)
        if not self.purger.join(incident, alert.channel, alert.ts,
                                category=decision.category.value,
                                needs_analysis=decision.needs_analysis, now=self.clock()):
            self._enqueue_post(alert, incident, decision, text=text, reaction=reaction,
                               reply_kind=kind, signal=signal, check=check,
                               source_system=source_system, backfilled=backfilled, label=label)
        self.store.mark_handled(
            alert.channel, alert.ts, category=decision.category.value,
            incident_id=incident.id, fingerprint=fp, reply_ts=None,
            handled_epoch=self.clock(), degraded=overload, backfilled=backfilled)
        self._after_handled(decision, hit, incident, alert, signal)
        self._count_known_hit(known_hit, alert)
        self._record_archive(alert, incident, decision, source_system=source_system,
                             task_pk=task_pk, label=label, backfilled=backfilled)

    # ---------- outbox ----------

    def _first_queued(self, incident_id: int, channel: str) -> bool:
        return bool(self.store.read(
            "SELECT 1 FROM outbox WHERE incident_id=? AND channel=? AND kind='first'"
            " AND status='pending'", (incident_id, channel)))

    def _incident_announced(self, incident_id: int) -> bool:
        return bool(self.store.read(
            "SELECT 1 FROM outbox WHERE incident_id=? AND kind='first'"
            " AND status IN ('pending','sent')", (incident_id,)))

    def _enqueue_post(self, alert: ParsedAlert, incident: Incident, decision, *, text: str,
                      reaction: str, reply_kind: str, signal, check, source_system: str,
                      backfilled: bool, label: str) -> None:
        """Queue this occurrence's share of the incident's report in its channel.

        No report yet -> the report's first message (tags owners if the incident has none
        anywhere yet). Otherwise a backfill summary, a storm overview line (overload) or an
        update; an update waits for the rest of the watchdog wave and keeps the minimum
        spacing unless magnitude, severity or host count changed.
        """
        cfg = self.cfg
        now = self.clock()
        channel = alert.channel
        urgent = decision.category in URGENT_CATEGORIES
        settle = getattr(cfg, "batch_settle_seconds", 20)
        severity = severity_word(decision.severity)
        hosts = signal.hosts if signal is not None and signal.ok else None
        report = self.store.get_report(incident.id, channel)
        if report is None and not self._first_queued(incident.id, channel):
            tags = ()
            if not self._incident_announced(incident.id):
                tags = mentions.resolve_owners(
                    self.slack, self.bot_token,
                    mentions.first_message_owners(cfg, source_system, check))
            self.store.enqueue_reply(
                incident_id=incident.id, channel=channel, kind="first",
                priority=0 if urgent else 1, due_epoch=now if urgent else now + settle,
                thread_ts=alert.ts, dedupe_key=f"first:{incident.id}:{channel}", now=now,
                payload={"decision_text": f"*{label}*\n{text}" if label else text,
                         "mentions": list(tags), "severity": severity, "reaction": reaction,
                         "severity_reaction": decision.severity, "reply_kind": reply_kind,
                         "hosts": hosts})
            return
        if backfilled:
            self.store.enqueue_reply(
                incident_id=incident.id, channel=channel, kind="backfill", priority=2,
                due_epoch=now + settle, dedupe_key=f"backfill:{incident.id}:{channel}",
                payload={}, now=now)
            return
        if self._overload and not urgent:
            minute = int(alert.epoch // 60)
            self.store.enqueue_reply(
                incident_id=None, channel=self.publisher.notice_channel(), kind="storm",
                priority=2, due_epoch=(minute + 1) * 60 + settle, dedupe_key=f"storm:{minute}",
                payload={"minute": minute}, now=now)
            return
        due = now + settle
        if report is not None:
            total = self.store.count_incident_messages(incident.id, channel, 0, math.inf)
            if report_changes(report, total=total, hosts=hosts, severity=severity):
                due = now
            else:
                gap = getattr(cfg, "update_min_interval_minutes", 2) * 60
                due = max(due, report["last_update_epoch"] + gap)
        self.store.enqueue_reply(
            incident_id=incident.id, channel=channel, kind="update",
            priority=0 if urgent else 2, due_epoch=due,
            dedupe_key=f"update:{incident.id}:{channel}", now=now,
            payload={"hosts": hosts, "severity": severity, "severity_reaction": decision.severity})

    def _record_archive(self, alert: ParsedAlert, incident: Incident, decision, *,
                        source_system: str, task_pk, label: str, backfilled: bool) -> None:
        if self._archive is None:
            return
        spec = self.cfg.channel(alert.channel)
        try:
            self._archive.record_occurrence(
                alert, incident=incident, category=decision.category.value,
                severity=severity_word(decision.severity), source_system=source_system,
                task_label=label, task_pk=task_pk, degraded=self._overload,
                backfilled=backfilled, channel_name=getattr(spec, "name", ""))
        except Exception as exc:
            log.warning("錯誤資料庫寫入 %s 失敗:%s", alert.ts, exc)

    def _observe_protection(self) -> None:
        now = self.clock()
        # count_received excludes `until`; a message received at this very instant is intake too.
        intake = self.store.count_received(now - 60, math.nextafter(now, math.inf))
        # A datasource failure fans out into many incidents with one root cause.
        active = self.store.read(
            "SELECT COUNT(DISTINCT incident_id) FROM messages WHERE incident_id IS NOT NULL"
            " AND epoch>=? AND COALESCE(category, '')!=?",
            (now - ACTIVE_INCIDENT_SECONDS, Category.DATASOURCE.value))[0][0]
        protection = self.store.get_protection()
        current = protection["state"]
        change = self.monitor.observe(now, intake, active, current)
        if change is None:
            return
        state, reason = change
        self.store.set_protection(state, reason, now)
        self._overload = state == "overload"
        log.warning("保護狀態 %s → %s:%s", current, state, reason)
        if self._overload:
            self._episode_rank.clear()
            self._episode_skipped.clear()
        elif current == "overload":
            self._analyse_skipped(now)
            self._enqueue_catchup(protection["since"], now)
            self._episode_rank.clear()
            self._episode_skipped.clear()
        tags = mentions.resolve_owners(self.slack, self.bot_token,
                                       getattr(self.cfg, "default_owners", ()))
        self.store.enqueue_reply(
            incident_id=None, channel=self.publisher.notice_channel(), kind="protection",
            priority=0, due_epoch=now, now=now,
            payload={"entering": self._overload, "reason": reason, "mentions": list(tags)})

    def _after_handled(self, decision, hit, incident: Incident, alert: ParsedAlert, signal) -> None:
        """Bookkeeping after the message is marked handled, so a retry cannot double count."""
        if decision.category == Category.DATASOURCE or (decision.rule
                                                         and decision.rule.action == "datasource"):
            return
        try:
            verdict = incident.verdict or {}
            if verdict.get("category") in UNHEALTHY_VERDICT_CATEGORIES or verdict.get("needs_human"):
                tuner.mark_unhealthy(self.store, incident.fingerprint,
                                     alert.epoch - UNHEALTHY_LOOKBACK_SECONDS, alert.epoch)
            errors = signal.errors if signal is not None and signal.ok else None
            tuner.record_observation(self.store, incident.fingerprint, alert.epoch, errors)
            if decision.auto_effect == "shadow" and hit is not None:
                autorules.record_shadow_hit(self.store, hit.rule.id, incident_id=incident.id,
                                            epoch=alert.epoch)
        except Exception as exc:
            log.warning("observation bookkeeping for %s failed: %s", alert.ts, exc)

    def _count_known_hit(self, known_hit, alert: ParsedAlert) -> None:
        if not isinstance(known_hit, known_store.LinkHit):
            return
        try:
            known_store.record_hit(self.store, known_hit.error_key, alert.epoch)
        except Exception as exc:
            log.warning("固定錯誤命中次數 %s 記錄失敗:%s", alert.ts, exc)

    def process_feedback(self) -> int:
        return feedback.process_inbox(self.store, self.cfg, self.slack, self.bot_token,
                                      self.clock(), checks=self.checks)

    def process_pending(self) -> int:
        """Handle queued messages oldest first; returns how many were handled.

        A message error counts one attempt (5 -> `failed`) and backs off exponentially.
        Slack 429 and network errors only reschedule the message: they say nothing
        about the message itself. A 429 also stops the round and pauses further
        rounds for `Retry-After`.
        """
        if self.clock() < self._paused_until:
            return 0
        self._overload = self.store.get_protection()["state"] == "overload"
        handled = 0
        for alert in self.store.pending_messages(now=self.clock()):
            try:
                self._handle(alert)
                handled += 1
            except Exception as exc:
                log.warning("message %s failed: %s", alert.ts, exc)
                error = f"{type(exc).__name__}: {exc}"[:300]
                if isinstance(exc, SlackRateLimited):
                    self._paused_until = self.clock() + exc.retry_after
                    self.store.message_retry_later(
                        alert.channel, alert.ts, error, retry_in=exc.retry_after, now=self.clock())
                    break
                if isinstance(exc, TRANSPORT_ERRORS):
                    self.store.message_retry_later(
                        alert.channel, alert.ts, error, retry_in=OUTAGE_RETRY_SECONDS, now=self.clock())
                else:
                    self.store.message_attempt_failed(
                        alert.channel, alert.ts, error, MAX_MESSAGE_ATTEMPTS, now=self.clock())
            self.store.beat("collector", self.clock())
        try:
            self._observe_protection()
        except Exception:
            log.exception("protection observation failed")
        return handled

    def publish(self) -> int:
        return self.publisher.process(self.clock())

    def purge(self) -> int:
        return self.purger.step(self.clock())

    # ---------- service loop ----------

    def run_forever(self, stop=lambda: False, sleep=time.sleep) -> None:
        lock_file = open(f"{self.cfg.db_path}.collector.lock", "w")
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log.error("另一個 collector 正在執行(鎖 %s.collector.lock),結束", self.cfg.db_path)
            lock_file.close()
            raise SystemExit(1)
        try:
            self._serve(stop, sleep)
        finally:
            lock_file.close()

    def _serve(self, stop, sleep) -> None:
        self.start()
        self._open_archive()
        self.store.beat("collector_started", self.clock())
        if self.app_token:
            threading.Thread(
                target=self._socket_run, name="collector-socket", daemon=True,
                args=(self.app_token, self.on_socket_event, stop),
                kwargs={"heartbeat": lambda: self.store.beat("socket", self.clock())},
            ).start()
        last_backfill = last_beat = last_revive = last_feedback = float("-inf")
        while not stop():
            now = self.clock()
            if now - last_backfill >= BACKFILL_INTERVAL:
                last_backfill = now
                self._guarded(self.backfill)
            if now - last_revive >= REVIVE_INTERVAL:
                last_revive = now
                self._guarded(lambda: self.store.revive_failed(self.clock()))
            self._guarded(self.process_pending)
            self._guarded(self.purge)
            self._guarded(self.publish)
            if now - last_feedback >= FEEDBACK_INTERVAL:
                last_feedback = now
                self._guarded(self.process_feedback)
            if now - last_beat >= BEAT_INTERVAL:
                last_beat = now
                self._guarded(lambda: self.store.beat("collector", self.clock()))
            sleep(LOOP_INTERVAL)

    @staticmethod
    def _guarded(fn) -> None:
        try:
            fn()
        except Exception:
            log.exception("collector loop step failed")
