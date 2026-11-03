from __future__ import annotations

import json
import math
import statistics

HOUR = 3600
TZ_OFFSET = 8 * HOUR
MAX_UNHEALTHY_SPAN_HOURS = 24 * 30
KEEP_VERSIONS = 48
UNHEALTHY_CATEGORIES = ("code_bug", "infra", "config", "external_dependency")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fp_hourly (
    fingerprint TEXT NOT NULL,
    hour_epoch INTEGER NOT NULL,
    alerts INTEGER NOT NULL DEFAULT 0,
    errors INTEGER,
    healthy INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (fingerprint, hour_epoch)
);
CREATE TABLE IF NOT EXISTS baselines (
    version INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL,
    median REAL NOT NULL,
    p95 REAL NOT NULL,
    samples INTEGER NOT NULL,
    created REAL NOT NULL,
    PRIMARY KEY (version, fingerprint, hour_of_day)
);
CREATE TABLE IF NOT EXISTS baseline_pin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
"""


def ensure_schema(store) -> None:
    with store.tx() as db:
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                db.execute(statement)


def _hour(epoch: float) -> int:
    return int(epoch // HOUR) * HOUR


def _hour_of_day(epoch: float) -> int:
    return int((epoch + TZ_OFFSET) // HOUR) % 24


def record_observation(store, fingerprint: str, epoch: float, errors: int | None) -> None:
    with store.tx() as db:
        db.execute(
            "INSERT INTO fp_hourly (fingerprint, hour_epoch, alerts, errors) "
            "VALUES (?,?,1,?) ON CONFLICT(fingerprint, hour_epoch) DO UPDATE SET "
            "alerts = alerts + 1, "
            "errors = CASE WHEN excluded.errors IS NULL THEN errors "
            "WHEN errors IS NULL THEN excluded.errors "
            "ELSE MAX(errors, excluded.errors) END",
            (fingerprint, _hour(epoch), errors))


def mark_unhealthy(store, fingerprint: str, since: float, until: float) -> None:
    first = _hour(since)
    last = _hour(max(since, until))
    last = min(last, first + MAX_UNHEALTHY_SPAN_HOURS * HOUR)
    with store.tx() as db:
        # Rows are created for hours not yet observed so that a later
        # record_observation cannot resurrect them as healthy.
        for hour in range(first, last + HOUR, HOUR):
            db.execute(
                "INSERT INTO fp_hourly (fingerprint, hour_epoch, alerts, errors, healthy) "
                "VALUES (?,?,0,NULL,0) ON CONFLICT(fingerprint, hour_epoch) "
                "DO UPDATE SET healthy = 0", (fingerprint, hour))


def _percentile(sorted_values: list[float], q: float) -> float:
    rank = max(1, math.ceil(q * len(sorted_values)))
    return float(sorted_values[rank - 1])


def _latest_version(store) -> int:
    rows = store.read("SELECT MAX(version) FROM baselines")
    return rows[0][0] or 0


def _pinned_version(store) -> int | None:
    rows = store.read("SELECT version FROM baseline_pin WHERE id=1")
    return rows[0][0] if rows else None


def _table_exists(store, name: str) -> bool:
    return bool(store.read("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)))


def _is_unhealthy_verdict(raw) -> bool:
    try:
        verdict = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return False
    return isinstance(verdict, dict) and (
        verdict.get("category") in UNHEALTHY_CATEGORIES or bool(verdict.get("needs_human")))


def _unhealthy_spans(store, since: float) -> dict[str, list[tuple[float, float]]]:
    """[first_epoch, last_epoch] of incidents judged a real problem or rejected by a human."""
    rejected: set[int] = set()
    if _table_exists(store, "feedback"):
        rejected = {r[0] for r in store.read("SELECT incident_id FROM feedback WHERE kind='reject'")}
    spans: dict[str, list[tuple[float, float]]] = {}
    for incident_id, fp, first, last, verdict in store.read(
            "SELECT id, fingerprint, first_epoch, last_epoch, verdict FROM incidents"
            " WHERE last_epoch >= ?", (since,)):
        if incident_id in rejected or _is_unhealthy_verdict(verdict):
            spans.setdefault(fp, []).append((first, last))
    return spans


def _overlaps(hour_epoch: int, spans: list[tuple[float, float]]) -> bool:
    return any(hour_epoch <= last and first < hour_epoch + HOUR for first, last in spans)


def recompute_baselines(store, now: float, days: int = 14, min_samples: int = 5) -> int:
    """New baseline version from healthy hours; returns the pinned version untouched while pinned."""
    pinned = _pinned_version(store)
    if pinned is not None:
        return pinned
    since = now - days * 86400
    rows = store.read(
        "SELECT fingerprint, hour_epoch, alerts, errors FROM fp_hourly "
        "WHERE healthy = 1 AND alerts > 0 AND hour_epoch >= ? AND hour_epoch <= ?",
        (since, now))
    spans = _unhealthy_spans(store, since - HOUR)
    groups: dict[tuple[str, int], list[float]] = {}
    for fp, hour_epoch, alerts, errors in rows:
        if _overlaps(hour_epoch, spans.get(fp, ())):
            continue
        value = errors if errors is not None else alerts
        groups.setdefault((fp, _hour_of_day(hour_epoch)), []).append(float(value))
    computed = [
        (fp, hod, statistics.median(vals), _percentile(sorted(vals), 0.95), len(vals))
        for (fp, hod), vals in groups.items() if len(vals) >= min_samples]
    if not computed:
        return _latest_version(store)
    with store.tx() as db:
        version = (db.execute("SELECT MAX(version) FROM baselines").fetchone()[0] or 0) + 1
        db.executemany(
            "INSERT INTO baselines VALUES (?,?,?,?,?,?,?)",
            [(version, fp, hod, med, p95, n, now) for fp, hod, med, p95, n in computed])
    _prune(store)
    return version


def _prune(store) -> None:
    pinned = _pinned_version(store)
    with store.tx() as db:
        db.execute(
            "DELETE FROM baselines WHERE version NOT IN (SELECT DISTINCT version FROM baselines"
            " ORDER BY version DESC LIMIT ?) AND version IS NOT ?", (KEEP_VERSIONS, pinned))


def baseline_for(store, fingerprint: str, epoch: float) -> tuple[float, float] | None:
    version = _latest_version(store)
    if not version:
        return None
    rows = store.read(
        "SELECT median, p95 FROM baselines WHERE version=? AND fingerprint=? AND hour_of_day=?",
        (version, fingerprint, _hour_of_day(epoch)))
    return (rows[0][0], rows[0][1]) if rows else None


def rollback_baselines(store, version: int) -> None:
    """Delete versions newer than `version` and pin it until `unpin_baselines`."""
    with store.tx() as db:
        db.execute("DELETE FROM baselines WHERE version > ?", (version,))
        db.execute("INSERT INTO baseline_pin (id, version) VALUES (1, ?)"
                   " ON CONFLICT(id) DO UPDATE SET version = excluded.version", (version,))


def unpin_baselines(store) -> None:
    with store.tx() as db:
        db.execute("DELETE FROM baseline_pin")


def is_accumulated(signal, baseline: tuple[float, float] | None, *,
                   min_errors: int, never_silence: bool, min_rate: float | None = None) -> bool:
    if not signal.ok or signal.errors is None:
        return False
    if min_rate is not None and signal.rate is not None and signal.rate < min_rate:
        return False
    floor = min_errors
    if baseline is None:
        threshold = 3 * min_errors
        exceeds = signal.errors >= threshold / (2 if never_silence else 1)
    else:
        median, p95 = baseline
        threshold = max(p95 * 2, median * 3, min_errors)
        exceeds = signal.errors > threshold / (2 if never_silence else 1)
    if never_silence:
        floor = min_errors / 2
    if signal.errors < floor or not exceeds:
        return False
    return signal.duration_minutes >= 5 or signal.hosts >= 2
