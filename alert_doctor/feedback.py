from __future__ import annotations

import logging
from typing import Callable

from alert_doctor.config import Config
from alert_doctor.store import Store

log = logging.getLogger(__name__)

# reply_index kind of the triage reply on an alert an active auto rule sampled for re-checking.
SAMPLE_REPLY_KINDS = ("sample",)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user TEXT NOT NULL,
    kind TEXT NOT NULL,
    epoch REAL NOT NULL
)
"""


def ensure_schema(store: Store) -> None:
    with store.tx() as db:
        db.execute(_SCHEMA)
        columns = {r[1] for r in db.execute("PRAGMA table_info(reactions_inbox)")}
        if "processed" not in columns:
            db.execute(
                "ALTER TABLE reactions_inbox ADD COLUMN processed INTEGER NOT NULL DEFAULT 0")


def _record(store: Store, rowid: int, incident_id: int | None, user: str,
            kind: str | None, epoch: float) -> None:
    with store.tx() as db:
        if kind:
            db.execute(
                "INSERT INTO feedback (incident_id, user, kind, epoch) VALUES (?,?,?,?)",
                (incident_id, user, kind, epoch))
        db.execute("UPDATE reactions_inbox SET processed=1 WHERE rowid=?", (rowid,))


def _given(store: Store, incident_id: int, kind: str, user: str | None = None) -> bool:
    if user is None:
        return bool(store.read("SELECT 1 FROM feedback WHERE incident_id=? AND kind=?",
                               (incident_id, kind)))
    return bool(store.read("SELECT 1 FROM feedback WHERE incident_id=? AND kind=? AND user=?",
                           (incident_id, kind, user)))


def _request_fresh(request_analysis, incident_id: int) -> None:
    try:
        request_analysis(incident_id, fresh=True)
    except TypeError:
        # Store versions without `fresh` reuse a recent verdict; still better than no re-run.
        request_analysis(incident_id)


def process_inbox(
    store: Store, cfg: Config, slack, bot_token: str, now: float, *,
    checks: dict | None = None, revoke=None, propose_from_human=None, settle_sample=None,
    revoked_ack=None, request_analysis: Callable[..., None] | None = None,
    mention: Callable[[tuple[str, ...]], str] | None = None, mark_unhealthy=None,
    record_feedback: Callable[[int, str, float], None] | None = None,
) -> int:
    """Handle unprocessed reactions; returns how many caused feedback or a rule action.

    Only ❌/✅ on a reply this bot posted count as feedback, and 🔇 on an alert
    itself proposes a rule; every other reaction is just marked processed.
    A ❌/✅ on any bot reply of an incident that is an auto-rule sample also settles
    that sample (at most once, see `autorules.settle_sample`).
    Each user counts at most one ❌ and one ✅ per incident; only the incident's first ❌
    revokes, marks the hours unhealthy, re-runs analysis and queues the ack (outbox kind
    `feedback`, threaded on the reply's alert). Every recorded ❌/✅ also goes to the error
    archive through `record_feedback(incident_id, kind, now)`, by default
    `archive.Archive(cfg.archive_db_path).record_feedback`.
    """
    from alert_doctor import auto_texts, autorules, mentions, tuner
    revoke = revoke or autorules.revoke
    propose_from_human = propose_from_human or autorules.propose_from_human
    settle_sample = settle_sample or autorules.settle_sample
    revoked_ack = revoked_ack or auto_texts.revoked_ack
    request_analysis = request_analysis or store.request_analysis
    if mark_unhealthy is None:
        tuner.ensure_schema(store)
        mark_unhealthy = tuner.mark_unhealthy
    if mention is None:
        def mention(owners):
            return " ".join(mentions.resolve_owners(slack, bot_token, owners))

    if record_feedback is None:
        record_feedback = _archive_recorder(cfg)
    ensure_schema(store)
    autorules.ensure_schema(store)
    rows = store.read(
        "SELECT rowid, channel, ts, user, name, epoch FROM reactions_inbox"
        " WHERE processed=0 ORDER BY rowid")
    acted = 0
    for rowid, channel, ts, user, name, epoch in rows:
        reply = store.lookup_reply(channel, ts)
        if reply is not None:
            incident_id = reply[1]
            incident = store.get_incident(incident_id) if incident_id is not None else None
            if incident is not None and name in ("x", "white_check_mark"):
                kind = "reject" if name == "x" else "agree"
                if _given(store, incident.id, kind, user):
                    _record(store, rowid, None, user, None, epoch)
                    continue
            if incident is not None and name == "x":
                first_reject = not _given(store, incident.id, "reject")
                settle_sample(store, incident.id, agreed=False)
                if first_reject:
                    revoke(store, incident.fingerprint, "human ❌", now)
                    try:
                        mark_unhealthy(store, incident.fingerprint, incident.first_epoch, now)
                    except Exception:
                        log.warning("marking incident %s unhealthy failed", incident.id,
                                    exc_info=True)
                    _request_fresh(request_analysis, incident.id)
                _record(store, rowid, incident.id, user, "reject", epoch)
                _archive_feedback(record_feedback, incident.id, "reject", now)
                acted += 1
                if not first_reject:
                    continue
                owners = _owners(store, cfg, checks, incident)
                _queue_ack(store, channel, reply[0], incident, now,
                           revoked_ack(incident.fingerprint[:8]), mention(owners) if owners else "")
                continue
            if incident is not None and name == "white_check_mark":
                settle_sample(store, incident.id, agreed=True)
                _record(store, rowid, incident.id, user, "agree", epoch)
                _archive_feedback(record_feedback, incident.id, "agree", now)
                acted += 1
                continue
        elif name == "mute":
            incident_id = store.message_incident(channel, ts)
            incident = store.get_incident(incident_id) if incident_id is not None else None
            if incident is not None:
                propose_from_human(store, incident.fingerprint, now, user)
                _record(store, rowid, incident.id, user, None, epoch)
                acted += 1
                continue
        _record(store, rowid, None, user, None, epoch)
    return acted


def _owners(store: Store, cfg: Config, checks: dict | None, incident) -> tuple[str, ...]:
    from alert_doctor import mentions
    from alert_doctor.checks import lookup_check
    alert = store.first_message(incident.id)
    check = lookup_check(checks or {}, alert) if alert is not None else None
    return mentions.owners_for(cfg, incident.source_system, check)


def _queue_ack(store: Store, channel: str, thread_ts: str, incident, now: float,
               text: str, tag: str) -> None:
    if tag:
        text = f"{text} {tag}"
    try:
        store.enqueue_reply(incident_id=incident.id, channel=channel, kind="feedback",
                            priority=1, due_epoch=now, payload={"text": text},
                            thread_ts=thread_ts, dedupe_key=f"feedback:{incident.id}:{channel}")
    except Exception:
        log.warning("queueing revoke ack failed for incident %s", incident.id, exc_info=True)


_archives: dict[str, object] = {}


def _archive_recorder(cfg: Config):
    """None when no archive is configured or it cannot be opened; feedback goes on without it."""
    path = getattr(cfg, "archive_db_path", None)
    if not path:
        return None
    try:
        if path not in _archives:
            from alert_doctor.archive import Archive
            _archives[path] = Archive(path)
        return _archives[path].record_feedback
    except Exception:
        log.warning("error archive %s unavailable", path, exc_info=True)
        return None


def _archive_feedback(record_feedback, incident_id: int, kind: str, now: float) -> None:
    if record_feedback is None:
        return
    try:
        record_feedback(incident_id, kind, now)
    except Exception:
        log.warning("archive.record_feedback failed for incident %s", incident_id, exc_info=True)
