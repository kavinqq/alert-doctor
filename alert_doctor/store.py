from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

from alert_doctor.models import Incident, ParsedAlert

MAX_ANALYSIS_ATTEMPTS = 3
RETRY_BASE_SECONDS = 30
RETRY_MAX_SECONDS = 1800
MAX_OUTBOX_ATTEMPTS = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    channel TEXT NOT NULL,
    ts TEXT NOT NULL,
    epoch REAL NOT NULL,
    raw_text TEXT NOT NULL,
    parse_ok INTEGER NOT NULL,
    check_title TEXT NOT NULL,
    check_code TEXT,
    task_id TEXT,
    level INTEGER,
    result_message TEXT NOT NULL,
    extra TEXT NOT NULL,
    mentions TEXT NOT NULL,
    received_epoch REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    category TEXT,
    incident_id INTEGER,
    fingerprint TEXT,
    reply_ts TEXT,
    handled_epoch REAL,
    next_attempt_epoch REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (channel, ts)
);
CREATE INDEX IF NOT EXISTS messages_fp ON messages (fingerprint, epoch);
CREATE INDEX IF NOT EXISTS messages_epoch ON messages (epoch);
CREATE INDEX IF NOT EXISTS messages_received ON messages (received_epoch);
CREATE INDEX IF NOT EXISTS messages_task_id ON messages (task_id);
CREATE INDEX IF NOT EXISTS messages_incident ON messages (incident_id, channel, epoch);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    group_fp TEXT NOT NULL,
    check_code TEXT,
    check_title TEXT NOT NULL,
    channel TEXT NOT NULL,
    anchor_ts TEXT NOT NULL,
    first_epoch REAL NOT NULL,
    last_epoch REAL NOT NULL,
    count INTEGER NOT NULL,
    analysis_state TEXT NOT NULL DEFAULT 'none',
    verdict TEXT,
    model TEXT,
    completed_epoch REAL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_owner TEXT,
    lease_expires REAL,
    requested_epoch REAL,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS incidents_fp ON incidents (fingerprint, last_epoch);
CREATE TABLE IF NOT EXISTS evidence (
    incident_id INTEGER PRIMARY KEY,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_calls (
    model TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS llm_calls_model ON llm_calls (model, at);
CREATE TABLE IF NOT EXISTS beats (
    component TEXT PRIMARY KEY,
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cursors (
    channel TEXT PRIMARY KEY,
    ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reply_index (
    channel TEXT NOT NULL,
    reply_ts TEXT NOT NULL,
    message_ts TEXT NOT NULL,
    incident_id INTEGER,
    kind TEXT NOT NULL,
    PRIMARY KEY (channel, reply_ts)
);
CREATE TABLE IF NOT EXISTS reactions_inbox (
    channel TEXT NOT NULL,
    ts TEXT NOT NULL,
    user TEXT NOT NULL,
    name TEXT NOT NULL,
    epoch REAL NOT NULL,
    UNIQUE (channel, ts, user, name, epoch)
);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    channel TEXT NOT NULL,
    kind TEXT NOT NULL,
    priority INTEGER NOT NULL,
    due_epoch REAL NOT NULL,
    thread_ts TEXT,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    dedupe_key TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    lease_expires REAL,
    last_error TEXT,
    reply_ts TEXT,
    sent_epoch REAL
);
DROP INDEX IF EXISTS outbox_dedupe;
CREATE INDEX IF NOT EXISTS outbox_dedupe_key ON outbox (dedupe_key, status);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (status, priority, due_epoch, id);
CREATE INDEX IF NOT EXISTS outbox_incident ON outbox (incident_id, channel, kind, status);
CREATE TABLE IF NOT EXISTS purges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    generation REAL NOT NULL,
    verdict TEXT NOT NULL,
    analysis_text TEXT NOT NULL,
    old_root TEXT,
    state TEXT NOT NULL DEFAULT 'pending',
    created_epoch REAL NOT NULL,
    finished_epoch REAL,
    error TEXT,
    UNIQUE (incident_id, channel, generation)
);
CREATE INDEX IF NOT EXISTS purges_state ON purges (state);
CREATE TABLE IF NOT EXISTS purge_targets (
    purge_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    epoch REAL,
    PRIMARY KEY (purge_id, kind, ts)
);
CREATE INDEX IF NOT EXISTS purge_targets_channel ON purge_targets (channel, state);
CREATE TABLE IF NOT EXISTS reports (
    incident_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    root_ts TEXT NOT NULL,
    created_epoch REAL NOT NULL,
    last_update_epoch REAL NOT NULL,
    last_count INTEGER NOT NULL DEFAULT 0,
    last_hosts INTEGER,
    last_severity TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (incident_id, channel)
);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT NOT NULL,
    minute INTEGER NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (name, minute)
);
CREATE TABLE IF NOT EXISTS protection (
    id INTEGER PRIMARY KEY CHECK (id=1),
    state TEXT NOT NULL,
    since REAL,
    reason TEXT NOT NULL
);
"""

_INCIDENT_COLS = (
    "id, fingerprint, group_fp, check_code, check_title, channel, anchor_ts, "
    "first_epoch, last_epoch, count, analysis_state, verdict, attempts, source_system,"
    " fresh_requested"
)

_MIGRATIONS = (
    ("messages", "next_attempt_epoch", "REAL NOT NULL DEFAULT 0"),
    ("incidents", "source_system", "TEXT NOT NULL DEFAULT ''"),
    ("incidents", "verdict_reused", "INTEGER NOT NULL DEFAULT 0"),
    ("incidents", "fresh_requested", "INTEGER NOT NULL DEFAULT 0"),
    ("messages", "degraded", "INTEGER DEFAULT 0"),
    ("messages", "backfilled", "INTEGER DEFAULT 0"),
    ("messages", "task_pk", "INTEGER"),
    ("outbox", "enqueued_epoch", "REAL"),
    ("incidents", "analysis_priority", "INTEGER NOT NULL DEFAULT 2"),
    ("incidents", "not_before", "REAL"),
    ("reports", "last_backfilled", "INTEGER NOT NULL DEFAULT 0"),
    ("messages", "bot_id", "TEXT"),
    ("messages", "fragment_of", "TEXT"),
    ("messages", "assembled", "INTEGER NOT NULL DEFAULT 0"),
    ("messages", "truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("messages", "text_len", "INTEGER"),
)

# Run once, by whichever process actually added the column, to fill rows written before it.
_BACKFILL_ON_ADD = {
    ("messages", "task_pk"): (
        "UPDATE messages SET task_pk=CASE"
        " WHEN typeof(json_extract(extra, '$.vkwargs.crontab_task_pk'))='integer'"
        " THEN json_extract(extra, '$.vkwargs.crontab_task_pk')"
        " WHEN typeof(json_extract(extra, '$.vkwargs.crontab_task_pk'))='text'"
        " AND json_extract(extra, '$.vkwargs.crontab_task_pk') GLOB '[0-9]*'"
        " AND json_extract(extra, '$.vkwargs.crontab_task_pk') NOT GLOB '*[^0-9]*'"
        " THEN CAST(json_extract(extra, '$.vkwargs.crontab_task_pk') AS INTEGER) END"
        " WHERE json_valid(extra)"),
    ("outbox", "enqueued_epoch"): "UPDATE outbox SET enqueued_epoch=due_epoch",
}

_POST_MIGRATION_INDEXES = (
    "CREATE INDEX IF NOT EXISTS messages_task_pk ON messages (task_pk, epoch)",
    "CREATE INDEX IF NOT EXISTS messages_bot ON messages (channel, bot_id, epoch)",
)

BACKFILL_LAG_SECONDS = 120


def task_pk_of(extra: dict) -> int | None:
    """watchdog's `extra.vkwargs.crontab_task_pk` as an int, or None when absent or not numeric."""
    vkwargs = extra.get("vkwargs") if isinstance(extra, dict) else None
    pk = vkwargs.get("crontab_task_pk") if isinstance(vkwargs, dict) else None
    if isinstance(pk, int) and not isinstance(pk, bool):
        return pk
    if isinstance(pk, str) and pk.isascii() and pk.isdigit():
        return int(pk)
    return None


def _column_names(db: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}


def _incident(row: sqlite3.Row | tuple | None) -> Incident | None:
    if row is None:
        return None
    return Incident(
        id=row[0], fingerprint=row[1], group_fp=row[2], check_code=row[3],
        check_title=row[4], channel=row[5], anchor_ts=row[6], first_epoch=row[7],
        last_epoch=row[8], count=row[9], analysis_state=row[10],
        verdict=json.loads(row[11]) if row[11] else None, attempts=row[12],
        source_system=row[13] or "", fresh_requested=bool(row[14]),
    )


_MESSAGE_COLS = ("channel, ts, raw_text, parse_ok, check_title, check_code, task_id, level,"
                 " result_message, extra, mentions, truncated")


def _parsed(row: tuple) -> ParsedAlert:
    return ParsedAlert(
        channel=row[0], ts=row[1], raw_text=row[2], parse_ok=bool(row[3]),
        check_title=row[4], check_code=row[5], task_id=row[6], level=row[7],
        result_message=row[8], extra=json.loads(row[9]),
        mentions=tuple(json.loads(row[10])), truncated=bool(row[11]),
    )


@dataclass(frozen=True)
class OutboxItem:
    id: int
    incident_id: int | None
    channel: str
    kind: str
    priority: int
    due_epoch: float
    thread_ts: str | None
    payload: dict
    attempts: int
    dedupe_key: str | None


_OUTBOX_COLS = "id, incident_id, channel, kind, priority, due_epoch, thread_ts, payload, attempts, dedupe_key"


def _outbox_item(row: tuple) -> OutboxItem:
    return OutboxItem(
        id=row[0], incident_id=row[1], channel=row[2], kind=row[3], priority=row[4],
        due_epoch=row[5], thread_ts=row[6], payload=json.loads(row[7]),
        attempts=row[8], dedupe_key=row[9])


_REPORT_COLS = (
    "root_ts, created_epoch, last_update_epoch, last_count, last_hosts, last_severity,"
    " is_primary, last_backfilled")


def _report(row: tuple | None) -> dict | None:
    if row is None:
        return None
    return {
        "root_ts": row[0], "created_epoch": row[1], "last_update_epoch": row[2],
        "last_count": row[3], "last_hosts": row[4], "last_severity": row[5],
        "is_primary": bool(row[6]), "last_backfilled": row[7],
    }


class Store:
    """SQLite-backed state shared by the collector and analyzer processes.

    Every public method is a single transaction and safe to call from several
    threads or from several processes opening the same file (WAL, 5s busy timeout).
    """

    def __init__(self, path: str):
        # isolation_level=None: transactions are opened explicitly so that
        # claim_incident can take the write lock up front with BEGIN IMMEDIATE.
        self._db = sqlite3.connect(
            path, isolation_level=None, check_same_thread=False, timeout=5.0)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        for stmt in _SCHEMA.split(";"):
            if stmt.strip():
                self._db.execute(stmt)
        for table, column, decl in _MIGRATIONS:
            self._add_column(table, column, decl)
        for stmt in _POST_MIGRATION_INDEXES:
            self._db.execute(stmt)

    def _add_column(self, table: str, column: str, decl: str) -> None:
        """Collector and analyzer start together and may both migrate the same file."""
        with self.tx() as db:
            if column in _column_names(db, table):
                return
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc):
                    raise
                return
            backfill = _BACKFILL_ON_ADD.get((table, column))
            if backfill:
                db.execute(backfill)

    @contextmanager
    def tx(self):
        """Write transaction on the shared connection; other modules own tables through this."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def read(self, sql: str, args: tuple = ()) -> list:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def insert_message(self, alert: ParsedAlert, received_epoch: float, *,
                       bot_id: str | None = None, text_len: int | None = None) -> bool:
        """`text_len` is the length of the text as Slack sent it, before redaction changed
        it; fragment joining compares it with Slack's split size."""
        with self.tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO messages (channel, ts, epoch, raw_text, parse_ok,"
                " check_title, check_code, task_id, level, result_message, extra,"
                " mentions, received_epoch, task_pk, bot_id, truncated, text_len)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert.channel, alert.ts, alert.epoch, alert.raw_text,
                 int(alert.parse_ok), alert.check_title, alert.check_code,
                 alert.task_id, alert.level, alert.result_message,
                 json.dumps(alert.extra, ensure_ascii=False),
                 json.dumps(list(alert.mentions)), received_epoch, task_pk_of(alert.extra),
                 bot_id, int(alert.truncated), text_len))
            return cur.rowcount == 1

    def get_message(self, channel: str, ts: str) -> ParsedAlert | None:
        rows = self.read(f"SELECT {_MESSAGE_COLS} FROM messages WHERE channel=? AND ts=?",
                         (channel, ts))
        return _parsed(rows[0]) if rows else None

    # ---- split messages (see fragments.py) ----

    def bot_message_before(self, channel: str, bot_id: str, ts: str) -> dict | None:
        """The bot's latest message in `channel` older than `ts`; `text_len` is its length as
        Slack sent it (the stored text's length for rows from before that was recorded)."""
        rows = self.read(
            "SELECT ts, epoch, raw_text, fragment_of, COALESCE(text_len, LENGTH(raw_text))"
            " FROM messages WHERE channel=? AND bot_id=?"
            " AND epoch<? ORDER BY epoch DESC, ts DESC LIMIT 1", (channel, bot_id, float(ts)))
        return (dict(zip(("ts", "epoch", "raw_text", "fragment_of", "text_len"), rows[0]))
                if rows else None)

    def bot_messages_after(self, channel: str, bot_id: str, ts: str, limit: int = 100) -> list[dict]:
        """The bot's messages in `channel` newer than `ts`, oldest first; `free` is True for
        one still waiting to be handled and not yet part of another message. `text_len` as in
        `bot_message_before`."""
        rows = self.read(
            "SELECT ts, epoch, raw_text, status='received' AND fragment_of IS NULL,"
            " COALESCE(text_len, LENGTH(raw_text)) FROM messages"
            " WHERE channel=? AND bot_id=? AND epoch>? ORDER BY epoch, ts LIMIT ?",
            (channel, bot_id, float(ts), limit))
        return [dict(zip(("ts", "epoch", "raw_text", "free", "text_len"), r)) for r in rows]

    def mark_fragment(self, channel: str, ts: str, head_ts: str, now: float) -> None:
        """Handled as a piece of `head_ts` (same channel): no reply of its own."""
        with self.tx() as db:
            db.execute(
                "UPDATE messages SET status='handled', category='fragment', fragment_of=?,"
                " handled_epoch=? WHERE channel=? AND ts=?", (head_ts, now, channel, ts))

    def joined_text(self, channel: str, head_ts: str) -> str | None:
        """The head's text with its fragments appended in ts order (or already appended,
        once assembled); None when the head is not stored."""
        head = self.read("SELECT raw_text, assembled FROM messages WHERE channel=? AND ts=?",
                         (channel, head_ts))
        if not head:
            return None
        if head[0][1]:
            return head[0][0]
        pieces = self.read("SELECT raw_text FROM messages WHERE channel=? AND fragment_of=?"
                           " ORDER BY epoch, ts", (channel, head_ts))
        return head[0][0] + "".join(r[0] for r in pieces)

    def has_unassembled_fragments(self, channel: str, head_ts: str) -> bool:
        return bool(self.read(
            "SELECT 1 FROM messages h JOIN messages f ON f.channel=h.channel AND f.fragment_of=h.ts"
            " WHERE h.channel=? AND h.ts=? AND h.assembled=0 LIMIT 1", (channel, head_ts)))

    def schedule_message(self, channel: str, ts: str, at: float) -> None:
        """Hold a waiting message until `at` (or release it when `at` is now)."""
        with self.tx() as db:
            db.execute("UPDATE messages SET next_attempt_epoch=? WHERE channel=? AND ts=?"
                       " AND status='received'", (at, channel, ts))

    def store_assembled(self, alert: ParsedAlert) -> None:
        """Replace a head's text and parsed fields with those of its joined text."""
        with self.tx() as db:
            db.execute(
                "UPDATE messages SET raw_text=?, parse_ok=?, check_title=?, check_code=?,"
                " task_id=?, level=?, result_message=?, extra=?, mentions=?, task_pk=?,"
                " truncated=?, assembled=1 WHERE channel=? AND ts=?",
                (alert.raw_text, int(alert.parse_ok), alert.check_title, alert.check_code,
                 alert.task_id, alert.level, alert.result_message,
                 json.dumps(alert.extra, ensure_ascii=False), json.dumps(list(alert.mentions)),
                 task_pk_of(alert.extra), int(alert.truncated), alert.channel, alert.ts))

    def count_received(self, since: float, until: float) -> int:
        """Live intake: messages received in [since, until), excluding backfill (those whose
        Slack ts lags their receipt by more than BACKFILL_LAG_SECONDS)."""
        return self.read(
            "SELECT COUNT(*) FROM messages WHERE received_epoch>=? AND received_epoch<?"
            " AND received_epoch-epoch<=? AND fragment_of IS NULL",
            (since, until, BACKFILL_LAG_SECONDS))[0][0]

    def busiest_channel(self, since: float) -> str | None:
        rows = self.read(
            "SELECT channel FROM messages WHERE epoch>=? GROUP BY channel"
            " ORDER BY COUNT(*) DESC, channel LIMIT 1", (since,))
        return rows[0][0] if rows else None

    def pending_messages(
        self, limit: int = 50, now: float | None = None
    ) -> list[ParsedAlert]:
        now = time.time() if now is None else now
        rows = self.read(
            f"SELECT {_MESSAGE_COLS} FROM messages"
            " WHERE status='received' AND next_attempt_epoch<=?"
            " ORDER BY epoch, ts LIMIT ?", (now, limit))
        return [_parsed(r) for r in rows]

    def message_attempt_failed(
        self, channel: str, ts: str, error: str, max_attempts: int = 5,
        *, now: float | None = None, retry_in: float | None = None,
    ) -> None:
        """Count one attempt; at `max_attempts` the message becomes `failed`.

        Without `retry_in` the delay doubles per attempt (30s, 60s, ... capped at 30 min).
        """
        now = time.time() if now is None else now
        with self.tx() as db:
            row = db.execute(
                "SELECT attempts FROM messages WHERE channel=? AND ts=? AND status='received'",
                (channel, ts)).fetchone()
            if row is None:
                return
            attempts = row[0] + 1
            if retry_in is None:
                retry_in = min(RETRY_BASE_SECONDS * 2 ** (attempts - 1), RETRY_MAX_SECONDS)
            db.execute(
                "UPDATE messages SET attempts=?, last_error=?, next_attempt_epoch=?,"
                " status=CASE WHEN ?>=? THEN 'failed' ELSE status END"
                " WHERE channel=? AND ts=?",
                (attempts, error, now + retry_in, attempts, max_attempts, channel, ts))

    def message_retry_later(
        self, channel: str, ts: str, error: str, *, retry_in: float,
        now: float | None = None,
    ) -> None:
        """Reschedule without spending an attempt (outages are not the message's fault)."""
        now = time.time() if now is None else now
        with self.tx() as db:
            db.execute(
                "UPDATE messages SET last_error=?, next_attempt_epoch=?"
                " WHERE channel=? AND ts=? AND status='received'",
                (error, now + retry_in, channel, ts))

    def revive_failed(
        self, now: float, max_age: float = 86400, max_attempts: int = 5
    ) -> int:
        """Give recent `failed` messages one more try (a single failure re-fails them)."""
        with self.tx() as db:
            cur = db.execute(
                "UPDATE messages SET status='received', attempts=?, next_attempt_epoch=?"
                " WHERE status='failed' AND epoch>=?",
                (max_attempts - 1, now, now - max_age))
            return cur.rowcount

    def message_incident(self, channel: str, ts: str) -> int | None:
        rows = self.read(
            "SELECT incident_id FROM messages WHERE channel=? AND ts=?", (channel, ts))
        return rows[0][0] if rows else None

    def mark_handled(
        self, channel: str, ts: str, *, category: str, incident_id: int | None,
        fingerprint: str | None, reply_ts: str | None, handled_epoch: float,
        degraded: bool = False, backfilled: bool = False,
    ) -> None:
        with self.tx() as db:
            db.execute(
                "UPDATE messages SET status='handled', category=?, incident_id=?,"
                " fingerprint=?, reply_ts=?, handled_epoch=?, degraded=?, backfilled=?"
                " WHERE channel=? AND ts=?",
                (category, incident_id, fingerprint, reply_ts, handled_epoch,
                 int(degraded), int(backfilled), channel, ts))

    def open_incident(
        self, fingerprint: str, now: float, idle_minutes: int
    ) -> Incident | None:
        rows = self.read(
            f"SELECT {_INCIDENT_COLS} FROM incidents WHERE fingerprint=?"
            " AND last_epoch>=? ORDER BY last_epoch DESC, id DESC LIMIT 1",
            (fingerprint, now - idle_minutes * 60))
        return _incident(rows[0]) if rows else None

    def create_incident(
        self, alert: ParsedAlert, fingerprint: str, group_fp: str, *, source_system: str = ""
    ) -> Incident:
        with self.tx() as db:
            cur = db.execute(
                "INSERT INTO incidents (fingerprint, group_fp, check_code, check_title,"
                " channel, anchor_ts, first_epoch, last_epoch, count, source_system)"
                " VALUES (?,?,?,?,?,?,?,?,1,?)",
                (fingerprint, group_fp, alert.check_code, alert.check_title,
                 alert.channel, alert.ts, alert.epoch, alert.epoch, source_system))
            db.execute(
                "UPDATE messages SET incident_id=? WHERE channel=? AND ts=?",
                (cur.lastrowid, alert.channel, alert.ts))
            return self._get(db, cur.lastrowid)

    def attach(self, incident_id: int, alert: ParsedAlert) -> Incident:
        """Idempotent per message: a message already bound to an incident is not counted again."""
        with self.tx() as db:
            row = db.execute(
                "SELECT incident_id FROM messages WHERE channel=? AND ts=?",
                (alert.channel, alert.ts)).fetchone()
            if row is not None and row[0] is not None:
                return self._get(db, incident_id)
            db.execute(
                "UPDATE messages SET incident_id=? WHERE channel=? AND ts=?",
                (incident_id, alert.channel, alert.ts))
            db.execute(
                "UPDATE incidents SET count=count+1, last_epoch=MAX(last_epoch, ?)"
                " WHERE id=?", (alert.epoch, incident_id))
            return self._get(db, incident_id)

    def incident_for_task(self, task_id: str, since: float) -> Incident | None:
        """Latest incident owning an occurrence of `task_id` newer than `since`."""
        rows = self.read(
            "SELECT incident_id FROM messages WHERE task_id=? AND epoch>=?"
            " AND incident_id IS NOT NULL ORDER BY epoch DESC, ts DESC LIMIT 1",
            (task_id, since))
        return self.get_incident(rows[0][0]) if rows else None

    def open_incident_for_task(
        self, task_pk: int, check_code: str | None, level: int | None, now: float,
        idle_minutes: int,
    ) -> Incident | None:
        """Most recently active incident holding an occurrence of this watchdog task with the
        same check code and level, if it was active within `idle_minutes`."""
        rows = self.read(
            f"SELECT {', '.join('i.' + c.strip() for c in _INCIDENT_COLS.split(','))}"
            " FROM incidents i WHERE i.last_epoch>=? AND EXISTS (SELECT 1 FROM messages m"
            " WHERE m.task_pk=? AND m.incident_id=i.id AND m.check_code IS ? AND m.level IS ?)"
            " ORDER BY i.last_epoch DESC, i.id DESC LIMIT 1",
            (now - idle_minutes * 60, task_pk, check_code, level))
        return _incident(rows[0]) if rows else None

    def index_reply(
        self, channel: str, reply_ts: str, message_ts: str, incident_id: int | None, kind: str
    ) -> None:
        with self.tx() as db:
            db.execute(
                "INSERT OR REPLACE INTO reply_index (channel, reply_ts, message_ts,"
                " incident_id, kind) VALUES (?,?,?,?,?)",
                (channel, reply_ts, message_ts, incident_id, kind))

    def lookup_reply(self, channel: str, reply_ts: str) -> tuple | None:
        """(message_ts, incident_id, kind) for a bot reply, or None if it is not ours."""
        rows = self.read(
            "SELECT message_ts, incident_id, kind FROM reply_index"
            " WHERE channel=? AND reply_ts=?", (channel, reply_ts))
        return tuple(rows[0]) if rows else None

    def add_reaction_inbox(
        self, channel: str, ts: str, user: str, name: str, epoch: float
    ) -> bool:
        with self.tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO reactions_inbox (channel, ts, user, name, epoch)"
                " VALUES (?,?,?,?,?)", (channel, ts, user, name, epoch))
            return cur.rowcount == 1

    def count_messages(self, fingerprint: str, since: float, until: float) -> int:
        return self.read(
            "SELECT COUNT(*) FROM messages WHERE fingerprint=? AND epoch>=? AND epoch<=?",
            (fingerprint, since, until))[0][0]

    @staticmethod
    def _get(db: sqlite3.Connection, incident_id: int) -> Incident | None:
        return _incident(db.execute(
            f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id=?",
            (incident_id,)).fetchone())

    def get_incident(self, incident_id: int) -> Incident | None:
        rows = self.read(
            f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id=?", (incident_id,))
        return _incident(rows[0]) if rows else None

    def first_message(self, incident_id: int) -> ParsedAlert | None:
        """The incident's anchor message (the one that created it), if stored."""
        rows = self.read(
            "SELECT m.channel, m.ts, m.raw_text, m.parse_ok, m.check_title, m.check_code,"
            " m.task_id, m.level, m.result_message, m.extra, m.mentions, m.truncated FROM incidents i"
            " JOIN messages m ON m.channel=i.channel AND m.ts=i.anchor_ts WHERE i.id=?",
            (incident_id,))
        return _parsed(rows[0]) if rows else None

    def request_analysis(
        self, incident_id: int, *, min_interval: float = 0, now: float | None = None,
        fresh: bool = False, priority: int = 2,
    ) -> None:
        """none/failed -> pending; done -> pending only if completed >= `min_interval` ago.

        pending and leased keep their state; their `priority` (lower is claimed first) drops
        to the given one if that is more urgent. Attempts restart from zero so a failed
        incident can actually be claimed again. `fresh=True` reopens `done` regardless of
        `min_interval` and marks the incident (also when already pending) so the analyzer
        will not reuse an earlier verdict; the mark is cleared by `complete_analysis`.
        """
        now = time.time() if now is None else now
        with self.tx() as db:
            reopened = db.execute(
                "UPDATE incidents SET analysis_state='pending', attempts=0,"
                " requested_epoch=?, analysis_priority=?, not_before=NULL"
                " WHERE id=? AND (analysis_state IN ('none','failed')"
                " OR (analysis_state='done' AND (? OR completed_epoch IS NULL"
                " OR completed_epoch<=?)))",
                (now, priority, incident_id, int(fresh), now - min_interval)).rowcount
            if not reopened:
                db.execute(
                    "UPDATE incidents SET analysis_priority=MIN(analysis_priority, ?)"
                    " WHERE id=? AND analysis_state IN ('pending','leased')",
                    (priority, incident_id))
            if fresh:
                db.execute(
                    "UPDATE incidents SET fresh_requested=1"
                    " WHERE id=? AND analysis_state='pending'", (incident_id,))

    def claim_incident(
        self, owner: str, now: float, lease_seconds: int = 1800,
        max_attempts: int = MAX_ANALYSIS_ATTEMPTS,
    ) -> Incident | None:
        with self.tx() as db:
            # An expired lease that already used up its attempts would otherwise
            # sit in 'leased' forever and never show up as failed.
            db.execute(
                "UPDATE incidents SET analysis_state='failed',"
                " last_error='lease expired after max attempts'"
                " WHERE analysis_state='leased' AND lease_expires<=? AND attempts>=?",
                (now, max_attempts))
            row = db.execute(
                "SELECT id FROM incidents WHERE attempts<? AND (analysis_state='pending'"
                " OR (analysis_state='leased' AND lease_expires<=?))"
                " AND (not_before IS NULL OR not_before<=?)"
                " ORDER BY analysis_priority, id LIMIT 1", (max_attempts, now, now)).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE incidents SET analysis_state='leased', attempts=attempts+1,"
                " lease_owner=?, lease_expires=? WHERE id=?",
                (owner, now + lease_seconds, row[0]))
            return self._get(db, row[0])

    def complete_analysis(
        self, incident_id: int, verdict: dict, model: str, now: float, *, reused: bool = False
    ) -> None:
        """`reused=True` marks a verdict copied from an earlier incident rather than analysed."""
        with self.tx() as db:
            db.execute(
                "UPDATE incidents SET analysis_state='done', verdict=?, model=?,"
                " completed_epoch=?, lease_owner=NULL, lease_expires=NULL,"
                " verdict_reused=?, fresh_requested=0 WHERE id=?",
                (json.dumps(verdict, ensure_ascii=False), model, now, int(reused),
                 incident_id))

    def complete_analysis_with_purge(
        self, incident_id: int, verdict: dict, model: str, now: float, *,
        channels: list[str], analysis_text: str, reused: bool = False,
    ) -> list[int]:
        """`complete_analysis` plus one pending purge per channel, committed together: the
        purge's generation is the completed_epoch written here, so a purge never sees an
        analysis that is not yet marked done. Returns the ids of newly created purges."""
        body = json.dumps(verdict, ensure_ascii=False)
        created = []
        with self.tx() as db:
            db.execute(
                "UPDATE incidents SET analysis_state='done', verdict=?, model=?,"
                " completed_epoch=?, lease_owner=NULL, lease_expires=NULL,"
                " verdict_reused=?, fresh_requested=0 WHERE id=?",
                (body, model, now, int(reused), incident_id))
            for channel in channels:
                cur = db.execute(
                    "INSERT OR IGNORE INTO purges (incident_id, channel, generation, verdict,"
                    " analysis_text, created_epoch) VALUES (?,?,?,?,?,?)",
                    (incident_id, channel, now, body, analysis_text, now))
                if cur.rowcount:
                    created.append(cur.lastrowid)
        return created

    def purge_rows(self, where_sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._db.execute(f"SELECT * FROM purges WHERE {where_sql} ORDER BY id", args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row)) for row in cur.fetchall()]

    def active_purge(self, incident_id: int, channel: str, generation: float) -> dict | None:
        rows = self.purge_rows(
            "incident_id=? AND channel=? AND generation=? AND state IN ('pending','done')",
            (incident_id, channel, generation))
        return rows[0] if rows else None

    def set_purge(self, purge_id: int, **fields) -> None:
        assigns = ", ".join(f"{name}=?" for name in fields)
        with self.tx() as db:
            db.execute(f"UPDATE purges SET {assigns} WHERE id=?", (*fields.values(), purge_id))

    def add_purge_targets(self, purge_id: int, channel: str, kind: str, ts_list) -> int:
        added = 0
        with self.tx() as db:
            for ts in ts_list:
                added += db.execute(
                    "INSERT OR IGNORE INTO purge_targets (purge_id, channel, kind, ts)"
                    " VALUES (?,?,?,?)", (purge_id, channel, kind, ts)).rowcount
        return added

    def set_target(self, purge_id: int, kind: str, ts: str, state: str, *,
                   error: str | None = None, epoch: float) -> None:
        with self.tx() as db:
            db.execute(
                "UPDATE purge_targets SET state=?, error=?, epoch=?"
                " WHERE purge_id=? AND kind=? AND ts=?", (state, error, epoch, purge_id, kind, ts))

    def deleted_ts(self, channel: str) -> set[str]:
        return {row[0] for row in self.read(
            "SELECT ts FROM purge_targets WHERE channel=? AND state IN ('deleted','gone')",
            (channel,))}

    def fail_analysis(self, incident_id: int, error: str, *, final: bool = False) -> None:
        """Back to pending until MAX_ANALYSIS_ATTEMPTS; `final` fails it at once."""
        with self.tx() as db:
            db.execute(
                "UPDATE incidents SET last_error=?, lease_owner=NULL, lease_expires=NULL,"
                " analysis_state=CASE WHEN ? OR attempts>=? THEN 'failed' ELSE 'pending' END"
                " WHERE id=?", (error, int(final), MAX_ANALYSIS_ATTEMPTS, incident_id))

    def defer_analysis(self, incident_id: int, *, not_before: float | None = None) -> None:
        """Hand a leased incident back to the queue without spending one of its attempts;
        `claim_incident` skips it until `not_before` (None: claimable at once)."""
        with self.tx() as db:
            db.execute(
                "UPDATE incidents SET analysis_state='pending', lease_owner=NULL,"
                " lease_expires=NULL, attempts=MAX(attempts-1, 0), not_before=?"
                " WHERE id=? AND analysis_state='leased'", (not_before, incident_id))

    def earliest_message_epoch(self) -> float | None:
        rows = self.read("SELECT MIN(epoch) FROM messages", ())
        return rows[0][0] if rows else None

    def recent_verdict(
        self, fingerprint: str, now: float, within_seconds: int = 86400
    ) -> tuple[dict, str, float] | None:
        rows = self.read(
            "SELECT verdict, model, completed_epoch FROM incidents"
            " WHERE fingerprint=? AND analysis_state='done' AND completed_epoch>=?"
            " AND verdict IS NOT NULL AND verdict_reused=0"
            " ORDER BY completed_epoch DESC LIMIT 1",
            (fingerprint, now - within_seconds))
        if not rows:
            return None
        return json.loads(rows[0][0]), rows[0][1], rows[0][2]

    def record_llm_call(self, model: str, now: float) -> None:
        with self.tx() as db:
            db.execute("INSERT INTO llm_calls (model, at) VALUES (?,?)", (model, now))

    def llm_calls_on(self, model: str, day_start: float, day_end: float) -> int:
        return self.read(
            "SELECT COUNT(*) FROM llm_calls WHERE model=? AND at>=? AND at<?",
            (model, day_start, day_end))[0][0]

    def beat(self, component: str, now: float) -> None:
        with self.tx() as db:
            db.execute(
                "INSERT INTO beats (component, at) VALUES (?,?)"
                " ON CONFLICT(component) DO UPDATE SET at=excluded.at", (component, now))

    def last_beat(self, component: str) -> float | None:
        rows = self.read("SELECT at FROM beats WHERE component=?", (component,))
        return rows[0][0] if rows else None

    def get_cursor(self, channel: str) -> str | None:
        rows = self.read("SELECT ts FROM cursors WHERE channel=?", (channel,))
        return rows[0][0] if rows else None

    def set_cursor(self, channel: str, ts: str) -> None:
        """Advance-only; a smaller ts is ignored."""
        with self.tx() as db:
            row = db.execute(
                "SELECT ts FROM cursors WHERE channel=?", (channel,)).fetchone()
            if row is None or float(ts) > float(row[0]):
                db.execute(
                    "INSERT INTO cursors (channel, ts) VALUES (?,?)"
                    " ON CONFLICT(channel) DO UPDATE SET ts=excluded.ts", (channel, ts))

    def save_evidence(self, incident_id: int, evidence: dict) -> None:
        with self.tx() as db:
            db.execute(
                "INSERT INTO evidence (incident_id, body) VALUES (?,?)"
                " ON CONFLICT(incident_id) DO UPDATE SET body=excluded.body",
                (incident_id, json.dumps(evidence, ensure_ascii=False)))

    def load_evidence(self, incident_id: int) -> dict | None:
        rows = self.read(
            "SELECT body FROM evidence WHERE incident_id=?", (incident_id,))
        return json.loads(rows[0][0]) if rows else None

    def coverage(self, channel: str, since: float, until: float) -> dict:
        """Messages of `channel` whose Slack ts falls in [since, until]; pieces of a split
        message are counted as part of their head only."""
        by_status = dict(self.read(
            "SELECT status, COUNT(*) FROM messages WHERE channel=? AND epoch>=?"
            " AND epoch<=? AND fragment_of IS NULL GROUP BY status", (channel, since, until)))
        unhandled = self.read(
            "SELECT ts, check_title FROM messages WHERE channel=? AND epoch>=?"
            " AND epoch<=? AND fragment_of IS NULL AND status!='handled' ORDER BY epoch, ts",
            (channel, since, until))
        categories = self.read(
            "SELECT category, COUNT(*) FROM messages WHERE channel=? AND epoch>=?"
            " AND epoch<=? AND fragment_of IS NULL AND status='handled' AND category IS NOT NULL"
            " GROUP BY category", (channel, since, until))
        degraded = self.read(
            "SELECT COUNT(*) FROM messages WHERE channel=? AND epoch>=? AND epoch<=?"
            " AND status='handled' AND degraded=1 AND fragment_of IS NULL", (channel, since, until))[0][0]
        published = self.read(
            "SELECT COUNT(*) FROM messages m WHERE m.channel=? AND m.epoch>=?"
            " AND m.epoch<=? AND m.status='handled' AND m.incident_id IS NOT NULL"
            " AND EXISTS (SELECT 1 FROM outbox o WHERE o.incident_id=m.incident_id"
            " AND o.channel=m.channel AND o.status='sent')",
            (channel, since, until))[0][0]
        deferred = self.read(
            "SELECT COUNT(*) FROM outbox WHERE channel=? AND status='pending'",
            (channel,))[0][0]
        return {
            "degraded": degraded,
            "published": published,
            "deferred": deferred,
            "total": sum(by_status.values()),
            "handled": by_status.get("handled", 0),
            "failed": by_status.get("failed", 0),
            "pending": by_status.get("received", 0),
            "unhandled": [(r[0], r[1]) for r in unhandled],
            "by_category": {c: n for c, n in categories},
        }

    def coverage_all(self, since: float, until: float) -> dict[str, dict]:
        channels = self.read(
            "SELECT DISTINCT channel FROM messages WHERE epoch>=? AND epoch<=?", (since, until))
        return {c[0]: self.coverage(c[0], since, until) for c in sorted(channels)}

    def stale_pending_analysis(self, older_than: float) -> list[Incident]:
        """Incidents still `pending` whose analysis was requested before `older_than`."""
        rows = self.read(
            f"SELECT {_INCIDENT_COLS} FROM incidents WHERE analysis_state='pending'"
            " AND requested_epoch<? ORDER BY id", (older_than,))
        return [_incident(r) for r in rows]

    def incidents_in_states(
        self, states: tuple[str, ...], *, requested_since: float | None = None,
        requested_until: float | None = None, lease_expired_before: float | None = None,
    ) -> list[Incident]:
        sql = (f"SELECT {_INCIDENT_COLS} FROM incidents WHERE analysis_state IN"
               f" ({','.join('?' * len(states))})")
        args: list = list(states)
        if requested_since is not None:
            sql += " AND requested_epoch>=?"
            args.append(requested_since)
        if requested_until is not None:
            sql += " AND requested_epoch<?"
            args.append(requested_until)
        if lease_expired_before is not None:
            sql += " AND lease_expires<?"
            args.append(lease_expired_before)
        return [_incident(r) for r in self.read(sql + " ORDER BY id", tuple(args))]

    def enqueue_reply(
        self, *, incident_id: int | None, channel: str, kind: str, priority: int,
        due_epoch: float, payload: dict, thread_ts: str | None = None,
        dedupe_key: str | None = None, now: float | None = None,
    ) -> int | None:
        """Queue a Slack post. An unsent, unleased row with the same `dedupe_key` is merged
        instead: payload replaced by the new one, due kept at the earlier time, priority at
        the more urgent one; its id is returned.

        A row whose lease is still running at `now` (default: wall clock) may be mid-post, so
        a merge into it could be lost; a new row is inserted instead and the older one yields
        to it if it ever returns to the queue (see `retry_outbox` / `claim_outbox`).
        """
        now = time.time() if now is None else now
        body = json.dumps(payload, ensure_ascii=False)
        with self.tx() as db:
            if dedupe_key is not None:
                row = db.execute(
                    "SELECT id FROM outbox WHERE dedupe_key=? AND status='pending'"
                    " AND (lease_expires IS NULL OR lease_expires<=?) ORDER BY id DESC LIMIT 1",
                    (dedupe_key, now)).fetchone()
                if row is not None:
                    db.execute(
                        "UPDATE outbox SET payload=?, due_epoch=MIN(due_epoch, ?),"
                        " priority=MIN(priority, ?), lease_expires=NULL WHERE id=?",
                        (body, due_epoch, priority, row[0]))
                    return row[0]
            # A row queued already overdue has been owed since its due time.
            cur = db.execute(
                "INSERT INTO outbox (incident_id, channel, kind, priority, due_epoch,"
                " thread_ts, payload, dedupe_key, enqueued_epoch) VALUES (?,?,?,?,?,?,?,?,?)",
                (incident_id, channel, kind, priority, due_epoch, thread_ts, body,
                 dedupe_key, min(now, due_epoch)))
            return cur.lastrowid

    @staticmethod
    def _yield_to_newer(db: sqlite3.Connection, item_id: int) -> bool:
        """Retire `item_id` if a newer pending row shares its dedupe key; the newer row
        inherits the earlier due time and the more urgent priority."""
        row = db.execute(
            "SELECT o2.id, o1.due_epoch, o1.priority, o1.enqueued_epoch FROM outbox o1"
            " JOIN outbox o2"
            " ON o2.dedupe_key=o1.dedupe_key AND o2.status='pending' AND o2.id>o1.id"
            " WHERE o1.id=? AND o1.status='pending' AND o1.dedupe_key IS NOT NULL"
            " ORDER BY o2.id DESC LIMIT 1",
            (item_id,)).fetchone()
        if row is None:
            return False
        db.execute(
            "UPDATE outbox SET due_epoch=MIN(due_epoch, ?), priority=MIN(priority, ?),"
            " enqueued_epoch=MIN(enqueued_epoch, COALESCE(?, enqueued_epoch)) WHERE id=?",
            (row[1], row[2], row[3], row[0]))
        db.execute(
            "UPDATE outbox SET status='superseded', lease_expires=NULL WHERE id=?", (item_id,))
        return True

    def claim_outbox(
        self, now: float, limit: int = 20, lease_seconds: int = 60
    ) -> list[OutboxItem]:
        with self.tx() as db:
            # A row whose publisher died mid-lease may have a newer sibling queued meanwhile.
            stale = db.execute(
                "SELECT id FROM outbox o1 WHERE status='pending' AND dedupe_key IS NOT NULL"
                " AND (lease_expires IS NULL OR lease_expires<=?) AND EXISTS (SELECT 1 FROM"
                " outbox o2 WHERE o2.dedupe_key=o1.dedupe_key AND o2.status='pending'"
                " AND o2.id>o1.id)", (now,)).fetchall()
            for (item_id,) in stale:
                self._yield_to_newer(db, item_id)
            rows = db.execute(
                f"SELECT {_OUTBOX_COLS} FROM outbox WHERE status='pending' AND due_epoch<=?"
                " AND (lease_expires IS NULL OR lease_expires<=?)"
                " ORDER BY priority, due_epoch, id LIMIT ?", (now, now, limit)).fetchall()
            for row in rows:
                db.execute(
                    "UPDATE outbox SET lease_expires=? WHERE id=?",
                    (now + lease_seconds, row[0]))
            return [_outbox_item(r) for r in rows]

    def complete_outbox(self, item_id: int, reply_ts: str, now: float) -> None:
        with self.tx() as db:
            db.execute(
                "UPDATE outbox SET status='sent', reply_ts=?, sent_epoch=?,"
                " lease_expires=NULL WHERE id=?", (reply_ts, now, item_id))

    def retry_outbox(
        self, item_id: int, error: str, retry_at: float, *, count_attempt: bool = True
    ) -> None:
        """`count_attempt=False` for throttling/outages that are not this row's fault.

        A row that a newer same-key row was queued behind while it was leased is retired
        instead of retried: the newer row carries the newer payload.
        """
        with self.tx() as db:
            if self._yield_to_newer(db, item_id):
                return
            db.execute(
                "UPDATE outbox SET attempts=attempts+?, last_error=?, due_epoch=?,"
                " lease_expires=NULL,"
                " status=CASE WHEN attempts+?>=? THEN 'failed' ELSE status END"
                " WHERE id=? AND status='pending'",
                (int(count_attempt), error, retry_at, int(count_attempt),
                 MAX_OUTBOX_ATTEMPTS, item_id))

    def drop_outbox(self, item_id: int, reason: str, now: float) -> None:
        """Retire a row that turned out to have nothing to say (e.g. an update with no new
        occurrences); it counts as neither sent nor failed."""
        with self.tx() as db:
            db.execute(
                "UPDATE outbox SET status='dropped', last_error=?, sent_epoch=?,"
                " lease_expires=NULL WHERE id=? AND status='pending'", (reason, now, item_id))

    def outbox_stats(self, now: float) -> dict:
        """Ages of pending rows, measured from when they were queued (retries and deliberate
        scheduling never reset them): `oldest_pending_age`, `oldest_critical_age` (priority 0),
        `oldest_error_age` (rows that already failed once), `first_pending_age` (non-critical
        first posts). None when there is no such row."""
        def oldest(extra: str = "") -> float | None:
            since = self.read(
                "SELECT MIN(enqueued_epoch) FROM outbox WHERE status='pending'"
                f" AND enqueued_epoch<=?{extra}", (now,))[0][0]
            return None if since is None else now - since
        by_kind = dict(self.read(
            "SELECT kind, COUNT(*) FROM outbox WHERE status='pending' GROUP BY kind"))
        failed = self.read("SELECT COUNT(*) FROM outbox WHERE status='failed'")[0][0]
        return {
            "pending": sum(by_kind.values()),
            "failed": failed,
            "oldest_pending_age": oldest(),
            "oldest_critical_age": oldest(" AND priority=0"),
            "oldest_error_age": oldest(" AND last_error IS NOT NULL"),
            "first_pending_age": oldest(" AND kind='first' AND priority>0"),
            "by_kind": by_kind,
        }

    def upsert_report(
        self, incident_id: int, channel: str, root_ts: str, *, now: float
    ) -> None:
        """The first channel to get a report becomes primary; later calls only move root_ts."""
        with self.tx() as db:
            if db.execute(
                "SELECT 1 FROM reports WHERE incident_id=? AND channel=?",
                (incident_id, channel)).fetchone():
                db.execute(
                    "UPDATE reports SET root_ts=? WHERE incident_id=? AND channel=?",
                    (root_ts, incident_id, channel))
                return
            has_primary = db.execute(
                "SELECT 1 FROM reports WHERE incident_id=?", (incident_id,)).fetchone()
            db.execute(
                "INSERT INTO reports (incident_id, channel, root_ts, created_epoch,"
                " last_update_epoch, is_primary) VALUES (?,?,?,?,?,?)",
                (incident_id, channel, root_ts, now, now, 0 if has_primary else 1))

    def get_report(self, incident_id: int, channel: str) -> dict | None:
        rows = self.read(
            f"SELECT {_REPORT_COLS} FROM reports WHERE incident_id=? AND channel=?",
            (incident_id, channel))
        return _report(rows[0]) if rows else None

    def primary_report(self, incident_id: int) -> dict | None:
        rows = self.read(
            f"SELECT {_REPORT_COLS}, channel FROM reports WHERE incident_id=?"
            " AND is_primary=1", (incident_id,))
        if not rows:
            return None
        return {**_report(rows[0][:8]), "channel": rows[0][8]}

    def set_report_state(
        self, incident_id: int, channel: str, *, last_update_epoch: float,
        last_count: int, last_hosts: int | None = None, last_severity: str | None = None,
        last_backfilled: int | None = None,
    ) -> None:
        """`last_count` occurrences are accounted for by posts so far, `last_backfilled` of
        them backfilled. Optional fields left as None keep their stored value."""
        with self.tx() as db:
            db.execute(
                "UPDATE reports SET last_update_epoch=?, last_count=?,"
                " last_hosts=COALESCE(?, last_hosts),"
                " last_severity=COALESCE(?, last_severity),"
                " last_backfilled=COALESCE(?, last_backfilled)"
                " WHERE incident_id=? AND channel=?",
                (last_update_epoch, last_count, last_hosts, last_severity, last_backfilled,
                 incident_id, channel))

    def count_incident_messages(
        self, incident_id: int, channel: str | None, since: float, until: float
    ) -> int:
        sql = ("SELECT COUNT(*) FROM messages WHERE incident_id=? AND epoch>=?"
               " AND epoch<=?")
        args: list = [incident_id, since, until]
        if channel is not None:
            sql += " AND channel=?"
            args.append(channel)
        return self.read(sql, tuple(args))[0][0]

    def incidents_needing_catchup(self, since: float) -> list[tuple[int, str]]:
        """(incident_id, channel) reports with occurrences newer than `since` whose total
        occurrence count in that channel exceeds what the report last posted."""
        return [tuple(r) for r in self.read(
            "SELECT r.incident_id, r.channel FROM reports r WHERE EXISTS (SELECT 1 FROM"
            " messages m WHERE m.incident_id=r.incident_id AND m.channel=r.channel"
            " AND m.epoch>=?) AND (SELECT COUNT(*) FROM messages m WHERE"
            " m.incident_id=r.incident_id AND m.channel=r.channel) > r.last_count"
            " ORDER BY r.incident_id, r.channel", (since,))]

    def get_protection(self) -> dict:
        rows = self.read("SELECT state, since, reason FROM protection WHERE id=1")
        if not rows:
            return {"state": "normal", "since": None, "reason": ""}
        return {"state": rows[0][0], "since": rows[0][1], "reason": rows[0][2]}

    def set_protection(self, state: str, reason: str, now: float) -> None:
        """`since` moves only when the state changes."""
        with self.tx() as db:
            db.execute(
                "INSERT INTO protection (id, state, since, reason) VALUES (1,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET reason=excluded.reason,"
                " since=CASE WHEN state=excluded.state THEN since ELSE excluded.since END,"
                " state=excluded.state", (state, now, reason))

    def bump_counter(self, name: str, n: int, now: float) -> None:
        with self.tx() as db:
            db.execute(
                "INSERT INTO counters (name, minute, n) VALUES (?,?,?)"
                " ON CONFLICT(name, minute) DO UPDATE SET n=n+excluded.n",
                (name, int(now // 60), n))

    def counter_sum(self, name: str, since: float, until: float) -> int:
        """Sums every minute bucket overlapping [since, until], so edges over-count."""
        return self.read(
            "SELECT COALESCE(SUM(n), 0) FROM counters WHERE name=? AND minute>=?"
            " AND minute<=?", (name, int(since // 60), int(until // 60)))[0][0]
