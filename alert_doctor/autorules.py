from __future__ import annotations

import json
import random
from dataclasses import dataclass

DAY = 86400
TZ_OFFSET = 8 * 3600
NOISE_CATEGORIES = ("noise", "transient")
REAL_CATEGORIES = ("code_bug", "infra", "config", "external_dependency")
MIN_CONFIDENCE = 0.75
NOISE_MIN_INCIDENTS = 3
VERDICT_WINDOW_DAYS = 14

_SCHEMA = """
CREATE TABLE IF NOT EXISTS auto_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    state TEXT NOT NULL,
    created REAL NOT NULL,
    activated REAL,
    expires REAL,
    shadow_hits INTEGER NOT NULL DEFAULT 0,
    sampled INTEGER NOT NULL DEFAULT 0,
    sampled_agree INTEGER NOT NULL DEFAULT 0,
    rejections INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS auto_rules_fp ON auto_rules (fingerprint, state);
CREATE TABLE IF NOT EXISTS fp_blocks (
    fingerprint TEXT PRIMARY KEY,
    until REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS counterexamples (
    fingerprint TEXT NOT NULL,
    epoch REAL NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS auto_samples (
    incident_id INTEGER PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    channel TEXT NOT NULL,
    message_ts TEXT NOT NULL,
    epoch REAL NOT NULL,
    settled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auto_shadow_hits (
    rule_id INTEGER NOT NULL,
    incident_id INTEGER NOT NULL,
    epoch REAL NOT NULL,
    PRIMARY KEY (rule_id, incident_id)
)
"""

_COLS = ("id, fingerprint, kind, source, state, created, activated, expires, "
         "shadow_hits, sampled, sampled_agree, rejections, reason")


@dataclass
class AutoRule:
    id: int
    fingerprint: str
    kind: str
    source: str
    state: str
    created: float
    activated: float | None
    expires: float | None
    shadow_hits: int
    sampled: int
    sampled_agree: int
    rejections: int
    reason: str


@dataclass
class AutoHit:
    rule: AutoRule
    active: bool
    sample: bool


def ensure_schema(store) -> None:
    with store.tx() as db:
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                db.execute(statement)


def _rules(store, where: str, args: tuple = ()) -> list[AutoRule]:
    return [AutoRule(*row) for row in
            store.read(f"SELECT {_COLS} FROM auto_rules WHERE {where} ORDER BY id", args)]


def is_blocked(store, fingerprint: str, now: float) -> bool:
    return bool(store.read(
        "SELECT 1 FROM fp_blocks WHERE fingerprint=? AND until > ?", (fingerprint, now)))


def _has_live_rule(store, fingerprint: str) -> bool:
    return bool(store.read(
        "SELECT 1 FROM auto_rules WHERE fingerprint=? AND state IN ('shadow','active')",
        (fingerprint,)))


def _create_shadow(db, fingerprint: str, kind: str, source: str, now: float, reason: str) -> int:
    return db.execute(
        "INSERT INTO auto_rules (fingerprint, kind, source, state, created, reason) "
        "VALUES (?,?,?,'shadow',?,?)", (fingerprint, kind, source, now, reason)).lastrowid


def _get(store, rule_id: int) -> AutoRule:
    return _rules(store, "id=?", (rule_id,))[0]


def _confident(verdict: dict) -> bool:
    try:
        return float(verdict.get("confidence", 0)) >= MIN_CONFIDENCE
    except (TypeError, ValueError):
        return False


def propose_from_verdicts(store, now: float) -> list[AutoRule]:
    rows = store.read(
        "SELECT fingerprint, verdict FROM incidents WHERE analysis_state='done' "
        "AND verdict IS NOT NULL AND completed_epoch >= ? AND verdict_reused = 0",
        (now - VERDICT_WINDOW_DAYS * DAY,))
    by_fp: dict[str, list[dict]] = {}
    for fp, raw in rows:
        try:
            verdict = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(verdict, dict):
            by_fp.setdefault(fp, []).append(verdict)

    created: list[int] = []
    for fp, verdicts in by_fp.items():
        if _has_live_rule(store, fp) or is_blocked(store, fp, now):
            continue
        real = [v for v in verdicts if _confident(v) and v.get("category") in REAL_CATEGORIES]
        noisy = [v for v in verdicts if _confident(v) and v.get("category") in NOISE_CATEGORIES]
        # Any verdict that is not a confident noise one (a real cause, a low-confidence
        # call, needs_human, critical...) vetoes silencing: noise is only learned
        # from a history that is uniformly noise.
        all_noise = all(
            _confident(v) and v.get("category") in NOISE_CATEGORIES
            and not v.get("needs_human") for v in verdicts)
        if real:
            kind, reason = "known", f"verdict 判定已知問題({real[-1].get('category')})"
        elif all_noise and len(noisy) >= NOISE_MIN_INCIDENTS:
            kind, reason = "noise", f"近 {VERDICT_WINDOW_DAYS} 天 {len(noisy)} 次判定為雜訊"
        else:
            continue
        with store.tx() as db:
            created.append(_create_shadow(db, fp, kind, "verdict", now, reason))
    return [_get(store, rule_id) for rule_id in created]


def propose_from_human(store, fingerprint: str, now: float, user: str) -> AutoRule | None:
    """Returns None when the fingerprint is blocked; an existing live rule is returned as is."""
    if is_blocked(store, fingerprint, now):
        return None
    live = _rules(store, "fingerprint=? AND state IN ('shadow','active')", (fingerprint,))
    if live:
        return live[0]
    with store.tx() as db:
        rule_id = _create_shadow(db, fingerprint, "noise", "human", now, f"{user} 按 🔇")
    return _get(store, rule_id)


def match(store, fingerprint: str, now: float, sample_rate: float,
          rng=random.random) -> AutoHit | None:
    if is_blocked(store, fingerprint, now):
        return None
    active = _rules(
        store, "fingerprint=? AND state='active' AND expires IS NOT NULL AND expires > ?",
        (fingerprint, now))
    if active:
        return AutoHit(active[-1], True, rng() < sample_rate)
    shadow = _rules(store, "fingerprint=? AND state='shadow'", (fingerprint,))
    if shadow:
        return AutoHit(shadow[-1], False, False)
    return None


def record_shadow_hit(store, rule_id: int, incident_id: int | None = None,
                      epoch: float | None = None) -> None:
    """Count one shadow match; only calls with `incident_id` and `epoch` count towards promotion."""
    with store.tx() as db:
        db.execute("UPDATE auto_rules SET shadow_hits = shadow_hits + 1 WHERE id=?", (rule_id,))
        if incident_id is not None and epoch is not None:
            db.execute("INSERT OR IGNORE INTO auto_shadow_hits (rule_id, incident_id, epoch)"
                       " VALUES (?,?,?)", (rule_id, incident_id, epoch))


def record_sample_result(store, rule_id: int, agreed: bool) -> None:
    """Each reviewed analysis lands in exactly one of sampled (agreed) or rejections,
    so the reject-rate denominator `sampled + rejections` is the reviewed count."""
    column = "sampled = sampled + 1, sampled_agree = sampled_agree + 1" if agreed \
        else "rejections = rejections + 1"
    with store.tx() as db:
        db.execute(f"UPDATE auto_rules SET {column} WHERE id=?", (rule_id,))


def _taipei_day(epoch: float) -> int:
    return int((epoch + TZ_OFFSET) // DAY)


def _agrees(rule: AutoRule, verdict) -> bool:
    if not isinstance(verdict, dict) or verdict.get("needs_human") or not _confident(verdict):
        return False
    expected = REAL_CATEGORIES if rule.kind == "known" else NOISE_CATEGORIES
    return verdict.get("category") in expected


def _fresh_verdicts(store, rule: AutoRule) -> list:
    """Verdicts of LLM runs finished while the rule was live; reused verdicts are not new evidence."""
    verdicts = []
    for (raw,) in store.read(
            "SELECT verdict FROM incidents WHERE fingerprint=? AND analysis_state='done'"
            " AND verdict IS NOT NULL AND completed_epoch >= ? AND verdict_reused = 0",
            (rule.fingerprint, rule.created)):
        try:
            verdicts.append(json.loads(raw))
        except (TypeError, ValueError):
            verdicts.append(None)
    return verdicts


def _hits_cover_week(store, rule: AutoRule, min_hits: int, min_days: int,
                     min_hit_days: int) -> bool:
    rows = store.read("SELECT epoch FROM auto_shadow_hits WHERE rule_id=? AND epoch >= ?",
                      (rule.id, rule.created))
    if len(rows) < min_hits:
        return False
    days = {_taipei_day(epoch) for (epoch,) in rows}
    return len(days) >= min_hit_days and max(days) - _taipei_day(rule.created) + 1 >= min_days


def promote_and_expire(store, now: float, *, min_days: int = 7, min_hits: int = 10,
                       min_hit_days: int = 5, max_reject_rate: float = 0.05,
                       ttl_days: int = 7) -> dict:
    """Expire active rules past TTL; promote or revoke shadow rules.

    `min_hits` counts distinct incidents, not messages: one incident absorbs a burst of
    repeated alerts, so 10 incidents on >= `min_hit_days` Taipei days reaching day
    `min_days` after creation is stronger evidence than the old 20 messages.
    A fresh (non-reused) verdict that disagrees with the rule revokes it outright.
    """
    promoted: list[int] = []
    revoked: list[int] = []
    expired = [r.id for r in _rules(
        store, "state='active' AND (expires IS NULL OR expires <= ?)", (now,))]
    with store.tx() as db:
        db.execute("UPDATE auto_rules SET state='expired' WHERE state='active' "
                   "AND (expires IS NULL OR expires <= ?)", (now,))
    for rule in _rules(store, "state='shadow'"):
        verdicts = _fresh_verdicts(store, rule)
        if not all(_agrees(rule, v) for v in verdicts):
            revoke(store, rule.fingerprint, "後續分析不同意", now)
            revoked.append(rule.id)
            continue
        # Disagreeing verdicts would also count as rejections, but any one of them has
        # already revoked the rule above, so only human rejections remain here.
        reject_rate = rule.rejections / max(1, len(verdicts) + rule.sampled + rule.rejections)
        if (now - rule.created >= min_days * DAY
                and _hits_cover_week(store, rule, min_hits, min_days, min_hit_days)
                and reject_rate < max_reject_rate
                and not is_blocked(store, rule.fingerprint, now)):
            with store.tx() as db:
                db.execute("UPDATE auto_rules SET state='active', activated=?, expires=? "
                           "WHERE id=? AND state='shadow'",
                           (now, now + ttl_days * DAY, rule.id))
            promoted.append(rule.id)
    return {"promoted": [_get(store, i) for i in promoted],
            "expired": [_get(store, i) for i in expired],
            "revoked": [_get(store, i) for i in revoked]}


def revoke(store, fingerprint: str, reason: str, now: float, block_days: int = 30) -> None:
    with store.tx() as db:
        db.execute("UPDATE auto_rules SET state='revoked', reason=? "
                   "WHERE fingerprint=? AND state != 'revoked'", (reason, fingerprint))
        db.execute(
            "INSERT INTO fp_blocks (fingerprint, until, reason) VALUES (?,?,?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            "until = MAX(until, excluded.until), reason = excluded.reason",
            (fingerprint, now + block_days * DAY, reason))
        db.execute("INSERT INTO counterexamples (fingerprint, epoch, note) VALUES (?,?,?)",
                   (fingerprint, now, reason))


def invalidate(store, fingerprint: str, reason: str, now: float) -> None:
    with store.tx() as db:
        db.execute("UPDATE auto_rules SET state='revoked', reason=? "
                   "WHERE fingerprint=? AND state='active'", (reason, fingerprint))


def record_sample(store, rule_id: int, incident_id: int, channel: str, message_ts: str,
                  now: float) -> None:
    """Remember that `incident_id` is being analysed as a re-check of `rule_id` (first sample wins)."""
    with store.tx() as db:
        db.execute(
            "INSERT OR IGNORE INTO auto_samples (incident_id, rule_id, channel, message_ts, epoch)"
            " VALUES (?,?,?,?,?)", (incident_id, rule_id, channel, message_ts, now))


def sample_rule(store, incident_id: int) -> int | None:
    """Rule id of an unsettled sample for this incident."""
    rows = store.read(
        "SELECT rule_id FROM auto_samples WHERE incident_id=? AND settled=0", (incident_id,))
    return rows[0][0] if rows else None


def settle_sample(store, incident_id: int, agreed: bool) -> int | None:
    """Count one sample result for the incident's rule, at most once; returns the rule id.

    Both the finished analysis and a human ✅/❌ can settle a sample, so the first one wins
    and the reject rate is not double counted.
    """
    with store.tx() as db:
        row = db.execute(
            "SELECT rule_id FROM auto_samples WHERE incident_id=? AND settled=0",
            (incident_id,)).fetchone()
        if row is None:
            return None
        db.execute("UPDATE auto_samples SET settled=1 WHERE incident_id=?", (incident_id,))
    record_sample_result(store, row[0], agreed)
    return row[0]


def invalidate_for_systems(store, systems, reason: str, now: float) -> list[str]:
    """Invalidate active rules whose fingerprint has incidents from one of `systems`."""
    systems = tuple(systems)
    if not systems:
        return []
    rows = store.read(
        "SELECT DISTINCT r.fingerprint FROM auto_rules r JOIN incidents i"
        " ON i.fingerprint = r.fingerprint WHERE r.state='active'"
        f" AND i.source_system IN ({','.join('?' * len(systems))}) ORDER BY r.fingerprint",
        systems)
    fingerprints = [r[0] for r in rows]
    for fp in fingerprints:
        invalidate(store, fp, reason, now)
    return fingerprints
