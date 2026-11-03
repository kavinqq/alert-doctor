"""Long-lived error archive, a SQLite file separate from the operational alert_doctor.db.

It is queried by people and by other tools (see README.md), so every write is
best-effort: a broken archive must never block alert handling.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alert_doctor.fingerprint import FINGERPRINT_VERSION, signature, signature_is_reliable
from alert_doctor.models import Incident, ParsedAlert
from alert_doctor.redact import strip_secret_text

log = logging.getLogger(__name__)

MESSAGE_LIMIT = 2000
WEEK = 7 * 86400
DAY = 86400
TAIPEI = timezone(timedelta(hours=8))

SCHEMA = """
CREATE TABLE IF NOT EXISTS occurrences (
    id INTEGER PRIMARY KEY,
    channel TEXT NOT NULL, channel_name TEXT, ts TEXT NOT NULL, epoch REAL NOT NULL,
    task_pk INTEGER, task_label TEXT, check_code TEXT, check_title TEXT,
    source_system TEXT, category TEXT, severity TEXT,
    incident_id INTEGER, fingerprint TEXT, message TEXT,
    degraded INTEGER NOT NULL DEFAULT 0, backfilled INTEGER NOT NULL DEFAULT 0,
    level INTEGER, error_key TEXT,
    UNIQUE (channel, ts)
);
CREATE INDEX IF NOT EXISTS ix_occ_incident ON occurrences(incident_id);
CREATE INDEX IF NOT EXISTS ix_occ_fp_epoch ON occurrences(fingerprint, epoch);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY, fingerprint TEXT, task_pk INTEGER, task_label TEXT,
    source_system TEXT, first_epoch REAL, last_epoch REAL,
    occurrence_count INTEGER NOT NULL DEFAULT 0, channels TEXT,
    category TEXT, severity TEXT, fix_in_system TEXT, summary TEXT, root_cause TEXT,
    suggested_action TEXT, confidence REAL, model TEXT, verdict_json TEXT, analyzed_epoch REAL,
    agree_count INTEGER NOT NULL DEFAULT 0, reject_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS code_refs (
    incident_id INTEGER NOT NULL, repo TEXT NOT NULL, file TEXT NOT NULL, line INTEGER,
    sha TEXT,
    UNIQUE (incident_id, repo, file, line)
);
CREATE INDEX IF NOT EXISTS ix_refs_file ON code_refs(repo, file);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL, epoch REAL NOT NULL,
    kind TEXT NOT NULL, json TEXT
);
CREATE VIEW IF NOT EXISTS v_file_hotspots AS
    SELECT r.repo, r.file, COUNT(DISTINCT r.incident_id) AS incidents,
           MAX(i.last_epoch) AS last_epoch
    FROM code_refs r JOIN incidents i ON i.incident_id = r.incident_id
    GROUP BY r.repo, r.file;
CREATE VIEW IF NOT EXISTS v_recurring AS
    SELECT fingerprint, MAX(task_label) AS task_label,
           COUNT(DISTINCT CAST(epoch / 604800 AS INTEGER)) AS weeks,
           COUNT(*) AS occurrences, COUNT(DISTINCT incident_id) AS incidents
    FROM occurrences WHERE fingerprint IS NOT NULL
    GROUP BY fingerprint;
"""

# Columns added after the first release; CREATE TABLE IF NOT EXISTS leaves old files without them.
_MIGRATIONS = (("occurrences", "level", "INTEGER"), ("occurrences", "error_key", "TEXT"),
               ("occurrences", "truncated", "INTEGER"), ("occurrences", "reliable", "INTEGER"))
_POST_MIGRATION = "CREATE INDEX IF NOT EXISTS ix_occ_key_epoch ON occurrences(error_key, epoch)"

_STATS = """
SELECT COALESCE(SUM(epoch >= ?), 0) AS today, COALESCE(SUM(epoch >= ?), 0) AS d7,
       COALESCE(SUM(epoch >= ?), 0) AS d30
FROM occurrences WHERE error_key = ? AND epoch <= ?
"""

_HOTSPOTS = """
SELECT r.repo, r.file, COUNT(DISTINCT r.incident_id) AS incidents, MAX(i.last_epoch) AS last_epoch
FROM code_refs r JOIN incidents i ON i.incident_id = r.incident_id
WHERE i.last_epoch >= ? {repo}
GROUP BY r.repo, r.file ORDER BY incidents DESC, last_epoch DESC, r.repo, r.file
"""

_RECURRING = """
SELECT fingerprint, MAX(task_label) AS task_label,
       COUNT(DISTINCT CAST(epoch / 604800 AS INTEGER)) AS weeks,
       COUNT(*) AS occurrences, COUNT(DISTINCT incident_id) AS incidents
FROM occurrences WHERE fingerprint IS NOT NULL AND epoch >= ?
GROUP BY fingerprint HAVING weeks >= 2 OR incidents >= 2
ORDER BY weeks DESC, occurrences DESC, fingerprint
"""


def legacy_fields(verdict: dict) -> tuple:
    """(summary, root_cause, suggested_action); newer verdicts carry `cause` and `fix`
    instead, and the archive columns stay as they were for the tools that query them."""
    fix = verdict.get("fix")
    joined = "；".join(str(f) for f in fix) if isinstance(fix, list) and fix else None
    cause = verdict.get("cause")
    return (verdict.get("summary") or cause, verdict.get("root_cause") or cause,
            verdict.get("suggested_action") or joined)


def error_key(task_pk: int | None, check_code: str | None, level: int | None,
              result_message: str, source_system: str = "") -> str | None:
    """Identity of "the same error" across incidents and days; None when the alert names
    neither a watchdog task nor a check script.

    task_pk identifies the check (one script serves many tasks with different targets), and
    the message `signature` tells apart the different errors a catch-all task reports (task 118
    covers many request paths) while ignoring the ids and hosts of the log line it quotes.
    `source_system` keeps one check code reporting on two systems apart. The incident
    fingerprint is not reused: incidents are cut by time, while this key must stay stable for
    months. FINGERPRINT_VERSION is hashed in, so a signature change starts new keys.
    """
    # The "pk:" prefix keeps a task pk from colliding with a check code spelled the same.
    identity = f"pk:{task_pk}" if task_pk is not None else check_code
    if not identity:
        return None
    level_part = "" if level is None else str(level)
    parts = (f"v{FINGERPRINT_VERSION}", source_system or "", identity, level_part,
             signature(result_message or ""))
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def taipei_midnight(now: float) -> float:
    day = datetime.fromtimestamp(now, TAIPEI).replace(hour=0, minute=0, second=0, microsecond=0)
    return day.timestamp()


class Archive:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._ready = False
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                con = self._connect()
                try:
                    con.execute("PRAGMA journal_mode=WAL")
                    con.executescript(SCHEMA)
                    self._migrate(con)
                    con.commit()
                finally:
                    con.close()
            self._ready = True
        except (OSError, sqlite3.Error) as exc:
            log.warning("錯誤資料庫初始化失敗 %s:%s", self.path, exc)

    @staticmethod
    def _migrate(con: sqlite3.Connection) -> None:
        """Rows from before a migration keep NULL there; `archive-backfill` refills error_key
        from Slack, since the stored message lacks the level and is cut at MESSAGE_LIMIT."""
        for table, column, kind in _MIGRATIONS:
            present = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            if column in present:
                continue
            try:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
            except sqlite3.OperationalError as exc:
                # collector and analyzer open the file concurrently; the other one won the race.
                if "duplicate column" not in str(exc):
                    raise
        con.execute(_POST_MIGRATION)

    def _write(self, what: str, fn):
        """fn's result, or None when the write failed (logged, never raised)."""
        try:
            with self._lock:
                if not self._ready:
                    self._init()
                con = self._connect()
                try:
                    with con:
                        return fn(con)
                finally:
                    con.close()
        except Exception as exc:
            log.warning("錯誤資料庫寫入失敗(%s):%s", what, exc)
            return None

    def _read(self, sql: str, args: tuple) -> list[dict]:
        try:
            with self._lock:
                con = self._connect()
                try:
                    return [dict(r) for r in con.execute(sql, args)]
                finally:
                    con.close()
        except Exception as exc:
            log.warning("錯誤資料庫讀取失敗:%s", exc)
            return []

    def record_occurrence(self, alert: ParsedAlert, *, incident: Incident | None, category: str,
                          severity: str | None, source_system: str, task_label: str,
                          task_pk: int | None, degraded: bool = False,
                          backfilled: bool = False, channel_name: str = "") -> bool | None:
        """True when a new row was written, False when (channel, ts) was already there (its
        error_key, truncated and reliable are then refreshed, level filled in if missing),
        None when the write failed."""
        message = strip_secret_text(alert.result_message or alert.raw_text)[:MESSAGE_LIMIT]
        incident_id = incident.id if incident else None
        key = error_key(task_pk, alert.check_code, alert.level, alert.result_message, source_system)
        reliable = signature_is_reliable(alert.result_message or "", alert.truncated)

        def run(con: sqlite3.Connection) -> bool:
            inserted = con.execute(
                "INSERT OR IGNORE INTO occurrences (channel, channel_name, ts, epoch, task_pk, "
                "task_label, check_code, check_title, source_system, category, severity, "
                "incident_id, fingerprint, message, degraded, backfilled, level, error_key, "
                "truncated, reliable) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert.channel, channel_name, alert.ts, alert.epoch, task_pk, task_label,
                 alert.check_code, alert.check_title, source_system, category, severity,
                 incident_id, incident.fingerprint if incident else None, message,
                 int(degraded), int(backfilled), alert.level, key, int(alert.truncated),
                 int(reliable))).rowcount > 0
            if not inserted:
                # Refreshed, not just filled: a late fragment or a new FINGERPRINT_VERSION
                # (archive-backfill) re-keys the occurrence.
                con.execute("UPDATE occurrences SET error_key=?, level=COALESCE(level, ?), "
                            "truncated=?, reliable=? WHERE channel=? AND ts=?",
                            (key, alert.level, int(alert.truncated), int(reliable),
                             alert.channel, alert.ts))
                return False
            if not incident:
                return True
            row = con.execute("SELECT channels FROM incidents WHERE incident_id=?",
                              (incident.id,)).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO incidents (incident_id, fingerprint, task_pk, task_label, "
                    "source_system, first_epoch, last_epoch, occurrence_count, channels, "
                    "category, severity) VALUES (?,?,?,?,?,?,?,1,?,?,?)",
                    (incident.id, incident.fingerprint, task_pk, task_label, source_system,
                     alert.epoch, alert.epoch, alert.channel, category, severity))
                return True
            channels = dict.fromkeys(filter(None, (row["channels"] or "").split(",")))
            channels[alert.channel] = None
            con.execute(
                "UPDATE incidents SET occurrence_count = occurrence_count + 1, "
                "first_epoch = MIN(first_epoch, ?), last_epoch = MAX(last_epoch, ?), channels = ?, "
                "task_pk = COALESCE(task_pk, ?), task_label = COALESCE(task_label, ?), "
                "severity = CASE WHEN analyzed_epoch IS NULL THEN COALESCE(?, severity) "
                "ELSE severity END WHERE incident_id = ?",
                (alert.epoch, alert.epoch, ",".join(channels), task_pk, task_label, severity,
                 incident.id))
            return True

        return self._write("occurrence", run)

    def record_verdict(self, incident: Incident, verdict: dict, model: str, shas: dict,
                       now: float) -> None:
        def run(con: sqlite3.Connection) -> None:
            con.execute(
                "INSERT OR IGNORE INTO incidents (incident_id, fingerprint, first_epoch, "
                "last_epoch, occurrence_count, channels, source_system) VALUES (?,?,?,?,?,?,?)",
                (incident.id, incident.fingerprint, incident.first_epoch, incident.last_epoch,
                 0, incident.channel, incident.source_system))
            con.execute(
                "UPDATE incidents SET category=?, severity=?, fix_in_system=?, summary=?, "
                "root_cause=?, suggested_action=?, confidence=?, model=?, verdict_json=?, "
                "analyzed_epoch=? WHERE incident_id=?",
                (verdict.get("category"), verdict.get("severity"), verdict.get("fix_in_system"),
                 *legacy_fields(verdict), verdict.get("confidence"), model,
                 json.dumps(verdict, ensure_ascii=False), now, incident.id))
            con.execute("DELETE FROM code_refs WHERE incident_id=?", (incident.id,))
            for item in verdict.get("evidence") or ():
                if not (isinstance(item, dict) and item.get("type") == "code"):
                    continue
                con.execute(
                    "INSERT OR IGNORE INTO code_refs (incident_id, repo, file, line, sha) "
                    "VALUES (?,?,?,?,?)",
                    (incident.id, item.get("repo"), item.get("file"), item.get("line"),
                     shas.get(item.get("repo"))))

        self._write("verdict", run)

    def record_feedback(self, incident_id: int, kind: str, now: float) -> None:
        column = {"agree": "agree_count", "reject": "reject_count"}.get(kind)

        def run(con: sqlite3.Connection) -> None:
            if column:
                con.execute(f"UPDATE incidents SET {column} = {column} + 1 WHERE incident_id=?",
                            (incident_id,))
            con.execute("INSERT INTO evidence (incident_id, epoch, kind, json) VALUES (?,?,?,?)",
                        (incident_id, now, f"feedback:{kind}", None))

        self._write("feedback", run)

    def record_evidence(self, incident_id: int, kind: str, data: dict, now: float) -> None:
        self._write("evidence", lambda con: con.execute(
            "INSERT INTO evidence (incident_id, epoch, kind, json) VALUES (?,?,?,?)",
            (incident_id, now, kind, json.dumps(data, ensure_ascii=False, default=str))))

    def key_of(self, channel: str, ts: str) -> tuple[str, float] | None:
        """(error_key, epoch) of the archived occurrence; None when absent or unkeyed."""
        rows = self._read("SELECT error_key, epoch FROM occurrences WHERE channel=? AND ts=?",
                          (channel, ts))
        if not rows or not rows[0]["error_key"]:
            return None
        return rows[0]["error_key"], rows[0]["epoch"]

    def occurrence_stats(self, key: str, now: float, before: float | None = None) -> dict | None:
        """Counts of `key` up to `now`: since Taipei midnight, last 7 and last 30 days, plus
        the first ever occurrence and the last one strictly before `before` (default `now`).
        None when the archive cannot be read."""
        before = now if before is None else before
        try:
            with self._lock:
                con = self._connect()
                try:
                    counts = con.execute(_STATS, (taipei_midnight(now), now - 7 * DAY,
                                                  now - 30 * DAY, key, now)).fetchone()
                    first = con.execute("SELECT MIN(epoch) FROM occurrences WHERE error_key=?",
                                        (key,)).fetchone()[0]
                    last = con.execute("SELECT MAX(epoch) FROM occurrences WHERE error_key=? "
                                       "AND epoch < ?", (key, before)).fetchone()[0]
                finally:
                    con.close()
        except Exception as exc:
            log.warning("錯誤資料庫讀取失敗:%s", exc)
            return None
        return {"today": counts["today"], "d7": counts["d7"], "d30": counts["d30"],
                "first_epoch": first, "last_before_epoch": last}

    def hotspots(self, days: int, now: float, repo: str | None = None) -> list[dict]:
        args: tuple = (now - days * 86400,)
        clause = ""
        if repo:
            clause, args = "AND r.repo = ?", args + (repo,)
        return self._read(_HOTSPOTS.format(repo=clause), args)

    def recurring(self, days: int, now: float) -> list[dict]:
        return self._read(_RECURRING, (now - days * 86400,))
