"""Green purge: delete green-verdict alerts (and our replies to them) from Slack.

`Purger.step` runs only in
the collector's main loop, which is a single locked instance, so nothing else deletes or
posts concurrently; the analyzer process and the socket worker thread do write rows, which
is why every round re-validates and the inbox is re-checked before each delete.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error

from alert_doctor import feedback
from alert_doctor.checks import lookup_check
from alert_doctor.slack_io import SlackError, SlackRateLimited

log = logging.getLogger(__name__)

PURGE_BATCH = 5
PROTECTED_CATEGORIES = ("critical", "datasource", "spike", "accumulated")
GONE_ERRORS = ("message_not_found",)
ALERT_KINDS = ("alert", "fragment")
CANCELLED_KINDS = ("update", "backfill", "late_fragment", "link", "analysis")
TRANSPORT_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError, OSError)


def purge_enabled(cfg, source_bot_token: str | None) -> bool:
    return bool(getattr(cfg, "purge_green", False) and source_bot_token)


def _placeholders(values) -> str:
    return ",".join("?" * len(values))


def has_protected(store, incident_id: int) -> bool:
    return bool(store.read(
        f"SELECT 1 FROM messages WHERE incident_id=? AND category IN"
        f" ({_placeholders(PROTECTED_CATEGORIES)}) LIMIT 1",
        (incident_id, *PROTECTED_CATEGORIES)))


def is_green(store, incident_id: int, verdict: dict | None, *, never_silence: bool) -> bool:
    verdict = verdict or {}
    if never_silence:
        return False
    if verdict.get("severity") != "low" or verdict.get("action") != "observe":
        return False
    if verdict.get("needs_human"):
        return False
    return not has_protected(store, incident_id)


def never_silence_for(store, checks: dict, incident_id: int) -> bool:
    alert = store.first_message(incident_id)
    if alert is not None:
        check = lookup_check(checks, alert)
    else:
        row = store.read("SELECT check_code, check_title FROM incidents WHERE id=?", (incident_id,))
        code, title = row[0] if row else ("", "")
        check = checks.get(code or "") or checks.get(title)
    return bool(check is not None and check.never_silence)


def blocked_thread(store, channel: str, ts: str | None) -> bool:
    """True when `ts` is an alert already deleted or about to be: nothing may be posted there."""
    if not ts:
        return False
    return bool(store.read(
        "SELECT 1 FROM purge_targets t JOIN purges p ON p.id=t.purge_id"
        " WHERE t.channel=? AND t.ts=? AND t.kind IN ('alert','fragment','own_root')"
        " AND (t.state IN ('deleted','gone') OR (t.state='pending' AND p.state='pending'))"
        " LIMIT 1", (channel, ts)))


class _StopRound(Exception):
    """Rate limit, budget or network: nothing more this round, everything resumes next round."""


class Purger:
    def __init__(self, cfg, store, slack, bot_token: str, source_bot_token: str | None,
                 budgets, checks: dict, clock=time.time):
        self.cfg, self.store, self.slack = cfg, store, slack
        self.bot_token, self.source_bot_token = bot_token, source_bot_token
        self.budgets, self.checks, self.clock = budgets, checks, clock
        feedback.ensure_schema(store)

    @property
    def enabled(self) -> bool:
        return purge_enabled(self.cfg, self.source_bot_token)

    # ---------- main loop ----------

    def step(self, now: float | None = None) -> int:
        """Run due purges; returns how many Slack delete calls were made (<= PURGE_BATCH)."""
        now = self.clock() if now is None else now
        calls = 0
        for purge in self._due():
            try:
                calls += self._run(purge, now, PURGE_BATCH - calls)
            except _StopRound as stop:
                log.info("綠燈刪除這輪暫停:%s", stop)
                break
            if calls >= PURGE_BATCH:
                break
        return calls

    def _due(self) -> list[dict]:
        return self.store.purge_rows(
            "state='pending' OR (state IN ('void','fallback') AND id IN (SELECT purge_id"
            " FROM purge_targets WHERE kind='fragment' AND state='pending'))")

    def _run(self, purge: dict, now: float, room: int) -> int:
        if purge["state"] in ("void", "fallback"):
            return self._orphans(purge, now, room)
        problem, superseded = self._invalid(purge)
        if problem:
            if not superseded:
                # Evidence the green verdict never saw (e.g. a spike while it was being
                # analysed): nothing was posted for it, so it has to be analysed again.
                # Requested before the void is written: after a crash in between, the next
                # round sees the request and voids as superseded.
                self.store.request_analysis(purge["incident_id"], fresh=True, now=now, priority=1)
            self._finish(purge, "void", now, problem)
            return self._orphans(purge, now, room)
        if not self.enabled:
            self._fallback(purge, now, "綠燈刪除已關閉或讀不到 watchdog token")
            return 0
        roots = self._collect(purge)
        if not self._hide(purge, roots):
            self._finish(purge, "void", now, "收尾前分析已更新")
            return 0
        return self._delete(purge, now, room)

    # ---------- validation ----------

    def _invalid(self, purge: dict) -> tuple[str | None, bool]:
        """(why the purge no longer holds, whether a newer analysis already took over)."""
        rows = self.store.read(
            "SELECT analysis_state, completed_epoch, verdict FROM incidents WHERE id=?",
            (purge["incident_id"],))
        if not rows:
            return "incident 不存在", True
        state, completed, verdict = rows[0]
        if state != "done" or completed != purge["generation"]:
            return "已有更新的分析或分析請求", True
        never_silence = never_silence_for(self.store, self.checks, purge["incident_id"])
        if not is_green(self.store, purge["incident_id"], json.loads(verdict or "{}"),
                        never_silence=never_silence):
            return "已不是綠燈", False
        return None, False

    def _inbox_pending(self, purge: dict) -> bool:
        """Any unprocessed reaction on anything of this incident, in any channel: feedback
        on one channel's copy may change what happens to all of them."""
        return bool(self.store.read(
            "SELECT 1 FROM reactions_inbox r WHERE r.processed=0 AND ("
            " EXISTS (SELECT 1 FROM messages m WHERE m.incident_id=? AND m.channel=r.channel"
            "  AND m.ts=r.ts)"
            " OR EXISTS (SELECT 1 FROM messages f JOIN messages h ON h.channel=f.channel"
            "  AND h.ts=f.fragment_of WHERE h.incident_id=? AND f.channel=r.channel AND f.ts=r.ts)"
            " OR EXISTS (SELECT 1 FROM reply_index x WHERE x.incident_id=? AND x.channel=r.channel"
            "  AND x.reply_ts=r.ts)"
            " OR EXISTS (SELECT 1 FROM outbox o WHERE o.incident_id=? AND o.channel=r.channel"
            "  AND o.reply_ts=r.ts)"
            " OR EXISTS (SELECT 1 FROM purge_targets t JOIN purges p ON p.id=t.purge_id"
            "  WHERE p.incident_id=? AND t.channel=r.channel AND t.ts=r.ts)) LIMIT 1",
            (purge["incident_id"],) * 5))

    # ---------- targets ----------

    def _targets(self, purge: dict, kinds, state: str | None = None) -> list[str]:
        sql = (f"SELECT ts FROM purge_targets WHERE purge_id=?"
               f" AND kind IN ({_placeholders(kinds)})")
        args = [purge["id"], *kinds]
        if state is not None:
            sql += " AND state=?"
            args.append(state)
        return [row[0] for row in self.store.read(sql + " ORDER BY ts", tuple(args))]

    def _collect(self, purge: dict) -> set[str]:
        """Add every current target; returns the alert ts set (the threads our replies are in)."""
        iid, channel = purge["incident_id"], purge["channel"]
        alerts = [row[0] for row in self.store.read(
            f"SELECT ts FROM messages WHERE incident_id=? AND channel=? AND status='handled'"
            f" AND fragment_of IS NULL AND (category IS NULL OR category NOT IN"
            f" ({_placeholders(PROTECTED_CATEGORIES)}))", (iid, channel, *PROTECTED_CATEGORIES))]
        self.store.add_purge_targets(purge["id"], channel, "alert", alerts)
        roots = set(self._targets(purge, ("alert",)))
        if not roots:
            return roots
        marks = _placeholders(roots)
        fragments = [row[0] for row in self.store.read(
            f"SELECT ts FROM messages WHERE channel=? AND fragment_of IN ({marks})",
            (channel, *roots))]
        self.store.add_purge_targets(purge["id"], channel, "fragment", fragments)
        # reply_index may miss a post (`_finish` keeps the outbox row even when indexing
        # fails), and fixed-error command replies carry no incident, so both are consulted.
        replies = [row[0] for row in self.store.read(
            f"SELECT reply_ts FROM reply_index WHERE channel=? AND message_ts IN ({marks})"
            f" UNION SELECT reply_ts FROM outbox WHERE channel=? AND status IN ('sent','purged')"
            f" AND reply_ts IS NOT NULL AND thread_ts IN ({marks})",
            (channel, *roots, channel, *roots))]
        self.store.add_purge_targets(purge["id"], channel, "reply",
                                     [ts for ts in replies if ts not in roots])
        return roots

    def _hide(self, purge: dict, roots: set[str]) -> bool:
        """Take the report and queued posts off threads that are going away. Done in one
        transaction that re-checks the generation, so an analysis the analyzer process
        commits meanwhile is never cancelled. False = the generation moved on."""
        iid, channel = purge["incident_id"], purge["channel"]
        with self.store.tx() as db:
            current = db.execute(
                "SELECT analysis_state, completed_epoch FROM incidents WHERE id=?",
                (iid,)).fetchone()
            if current is None or current[0] != "done" or current[1] != purge["generation"]:
                return False
            if not roots:
                return True
            report = db.execute(
                "SELECT root_ts FROM reports WHERE incident_id=? AND channel=?",
                (iid, channel)).fetchone()
            if report is not None and report[0] in roots:
                db.execute("DELETE FROM reports WHERE incident_id=? AND channel=?", (iid, channel))
                db.execute("UPDATE purges SET old_root=COALESCE(old_root, ?) WHERE id=?",
                           (report[0], purge["id"]))
            marks = _placeholders(roots)
            db.execute(
                f"UPDATE outbox SET status='purged', lease_expires=NULL WHERE incident_id=?"
                f" AND channel=? AND kind='first' AND status IN ('pending','sent')"
                f" AND thread_ts IN ({marks})", (iid, channel, *roots))
            db.execute(
                f"UPDATE outbox SET status='cancelled', lease_expires=NULL,"
                f" last_error='綠燈刪除' WHERE incident_id=? AND channel=? AND status='pending'"
                f" AND kind IN ({_placeholders(CANCELLED_KINDS)})",
                (iid, channel, *CANCELLED_KINDS))
        return True

    # ---------- deleting ----------

    def _delete(self, purge: dict, now: float, room: int) -> int:
        if any(self._targets(purge, (kind,), "failed") for kind in ALERT_KINDS):
            self._fallback(purge, now, "有告警刪不掉")
            return 0
        calls = 0
        while calls < room:
            if self._inbox_pending(purge):
                return calls
            alerts = [(kind, ts) for kind in ALERT_KINDS
                      for ts in self._targets(purge, (kind,), "pending")]
            pending = alerts or [("reply", ts) for ts in self._targets(purge, ("reply",), "pending")]
            if not pending:
                self._finish(purge, "done", now)
                return calls
            kind, ts = pending[0]
            calls += 1
            outcome = self._call_delete(purge, kind, ts, now)
            if outcome == "fatal":
                self._fallback(purge, now, f"告警 {ts} 刪不掉")
                return calls
        if not (self._targets(purge, ALERT_KINDS + ("reply",), "pending")):
            self._finish(purge, "done", now)
        return calls

    def _call_delete(self, purge: dict, kind: str, ts: str, now: float) -> str:
        if not self.budgets.slack.take("normal", now):
            raise _StopRound("Slack 預算不足")
        token = self.bot_token if kind == "reply" else self.source_bot_token
        try:
            self.slack.delete_message(token, purge["channel"], ts)
        except SlackRateLimited as exc:
            raise _StopRound(f"Slack 429,{exc.retry_after} 秒後再試") from exc
        except SlackError as exc:
            if exc.error in GONE_ERRORS:
                self.store.set_target(purge["id"], kind, ts, "gone", epoch=now)
                return "gone"
            self.store.set_target(purge["id"], kind, ts, "failed", error=exc.error, epoch=now)
            log.warning("綠燈刪除 %s %s 失敗:%s", kind, ts, exc.error)
            return "failed" if kind == "reply" else "fatal"
        except TRANSPORT_ERRORS as exc:
            raise _StopRound(f"{type(exc).__name__}: {exc}") from exc
        self.store.set_target(purge["id"], kind, ts, "deleted", epoch=now)
        return "deleted"

    def _orphans(self, purge: dict, now: float, room: int) -> int:
        """A void purge only finishes fragments whose head is gone: they are orphans whatever
        the incident has become since."""
        deleted = self.store.deleted_ts(purge["channel"])
        calls = 0
        for ts in self._targets(purge, ("fragment",), "pending"):
            head = self.store.read("SELECT fragment_of FROM messages WHERE channel=? AND ts=?",
                                   (purge["channel"], ts))
            if not head or head[0][0] not in deleted:
                self.store.set_target(purge["id"], "fragment", ts, "skipped", epoch=now)
                continue
            if calls >= room or self._inbox_pending(purge):
                break
            calls += 1
            self._call_delete(purge, "fragment", ts, now)
        return calls

    # ---------- endings ----------

    def _finish(self, purge: dict, state: str, now: float, error: str | None = None) -> None:
        if state == "done":
            # The socket worker can add a late fragment between our last check and here.
            with self.store.tx() as db:
                finished = db.execute(
                    "UPDATE purges SET state='done', finished_epoch=?, error=NULL WHERE id=?"
                    " AND NOT EXISTS (SELECT 1 FROM purge_targets WHERE purge_id=?"
                    " AND state='pending')", (now, purge["id"], purge["id"])).rowcount
            if finished:
                purge["state"] = state
            return
        self.store.set_purge(purge["id"], state=state, finished_epoch=now, error=error)
        purge["state"] = state
        if state != "done":
            log.info("綠燈刪除 #%s %s → %s:%s", purge["incident_id"], purge["channel"], state, error)

    def _fallback(self, purge: dict, now: float, reason: str) -> None:
        """Post the analysis after all, on the earliest alert of this channel still there.

        The fallback state is written last: if anything before it fails the purge stays
        pending and the next round does the fallback again (the enqueue is deduplicated)."""
        iid, channel = purge["incident_id"], purge["channel"]
        deleted = self.store.deleted_ts(channel)
        roots = [row[0] for row in self.store.read(
            "SELECT ts FROM messages WHERE incident_id=? AND channel=? AND fragment_of IS NULL"
            " ORDER BY epoch, ts", (iid, channel)) if row[0] not in deleted]
        if not roots:
            self._finish(purge, "fallback", now, f"{reason};沒有留存的告警可回覆")
            return
        self.store.upsert_report(iid, channel, roots[0], now=now)
        self.store.enqueue_reply(
            incident_id=iid, channel=channel, kind="analysis", priority=1, due_epoch=now,
            thread_ts=roots[0], dedupe_key=f"analysis:{iid}:{channel}", now=now,
            payload={"text": purge["analysis_text"]})
        self._finish(purge, "fallback", now, reason)

    # ---------- collector entry points ----------

    def join(self, incident, channel: str, ts: str, *, category: str, needs_analysis: bool,
             now: float) -> bool:
        """Spec §4a: a later occurrence of a green incident is deleted instead of reported."""
        if not self.enabled or needs_analysis or category in PROTECTED_CATEGORIES:
            return False
        rows = self.store.read(
            "SELECT analysis_state, completed_epoch, verdict FROM incidents WHERE id=?",
            (incident.id,))
        if not rows or rows[0][0] != "done":
            return False
        generation = rows[0][1]
        siblings = self.store.purge_rows(
            "incident_id=? AND generation=? AND state IN ('pending','done')",
            (incident.id, generation))
        if not siblings:
            return False
        if not is_green(self.store, incident.id, json.loads(rows[0][2] or "{}"),
                        never_silence=never_silence_for(self.store, self.checks, incident.id)):
            return False
        own = self.store.purge_rows("incident_id=? AND channel=? AND generation=?",
                                    (incident.id, channel, generation))
        if own and own[0]["state"] not in ("pending", "done"):
            return False
        if own:
            purge_id = own[0]["id"]
        else:
            template = siblings[0]
            with self.store.tx() as db:
                purge_id = db.execute(
                    "INSERT INTO purges (incident_id, channel, generation, verdict, analysis_text,"
                    " created_epoch) VALUES (?,?,?,?,?,?)",
                    (incident.id, channel, generation, template["verdict"],
                     template["analysis_text"], now)).lastrowid
        self.store.add_purge_targets(purge_id, channel, "alert", [ts])
        self._reopen(purge_id)
        return True

    def join_fragment(self, channel: str, head_ts: str, fragment_ts: str, now: float) -> bool:
        """Spec §4b: a late fragment of a deleted (or about to be deleted) head goes with it."""
        rows = self.store.read(
            "SELECT p.id, p.state, t.state FROM purge_targets t JOIN purges p ON p.id=t.purge_id"
            " WHERE t.channel=? AND t.ts=? AND t.kind='alert' ORDER BY p.id DESC LIMIT 1",
            (channel, head_ts))
        if not rows:
            return False
        purge_id, purge_state, head_state = rows[0]
        head_deleted = head_state in ("deleted", "gone")
        if not head_deleted and purge_state != "pending":
            return False
        self.store.add_purge_targets(purge_id, channel, "fragment", [fragment_ts])
        # Unconditional: the main thread may have finished the purge since we read its state.
        self._reopen(purge_id)
        return True

    def _reopen(self, purge_id: int) -> None:
        with self.store.tx() as db:
            db.execute("UPDATE purges SET state='pending', finished_epoch=NULL"
                       " WHERE id=? AND state='done'", (purge_id,))
