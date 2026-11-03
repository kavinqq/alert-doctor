"""Known errors linked by error identity: the cache in front of analysis.

An entry is a named known phenomenon; a link maps one `archive.error_key` to an entry.
A linked error is answered from the entry without analysis. Entries and links live in
the production store so Slack and the CLI can add them while the service runs.

Every link expires (DEFAULT_LINK_DAYS, at most MAX_LINK_DAYS) and counts its hits, so a
wrong link cannot bypass analysis forever; `review` lists the links someone should look at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from alert_doctor.archive import error_key
from alert_doctor.fingerprint import signature_is_reliable
from alert_doctor.models import ParsedAlert

TAIPEI = timezone(timedelta(hours=8))
DAY = 86400
SAMPLE_CHARS = 300
SEARCH_LIMIT = 10
DEFAULT_LINK_DAYS = 14
MAX_LINK_DAYS = 90
REVIEW_EXPIRING_DAYS = 3
REVIEW_IDLE_DAYS = 14
REVIEW_BUSY_DAYS = 7
REVIEW_BUSY_HITS = 50

_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT 'known',
    source TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    expires TEXT
);
CREATE TABLE IF NOT EXISTS known_links (
    error_key TEXT PRIMARY KEY,
    known_id TEXT NOT NULL,
    linked_by TEXT NOT NULL DEFAULT '',
    linked_at REAL NOT NULL,
    sample_message TEXT NOT NULL DEFAULT '',
    sample_label TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS known_links_by_entry ON known_links(known_id);
CREATE TABLE IF NOT EXISTS known_link_daily (
    error_key TEXT NOT NULL,
    day TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (error_key, day)
)
"""
# Link columns added after the first release, with the statement that fills old rows.
_LINK_MIGRATIONS = (
    ("created_by", "TEXT NOT NULL DEFAULT ''", "UPDATE known_links SET created_by=linked_by"),
    ("expires_at", "REAL", f"UPDATE known_links SET expires_at=linked_at+{DEFAULT_LINK_DAYS * DAY}"),
    ("hit_count", "INTEGER NOT NULL DEFAULT 0", None),
    ("first_hit_at", "REAL", None),
    ("last_hit_at", "REAL", None),
    ("last_reviewed_by", "TEXT", None),
    ("last_reviewed_at", "REAL", None),
)
_ENTRY_COLS = "id, title, description, action, source, created_by, created_at, expires"
_LINK_COLS = ("error_key", "linked_by", "linked_at", "sample_message", "sample_label", "expires_at",
              "hit_count", "first_hit_at", "last_hit_at", "created_by", "last_reviewed_by",
              "last_reviewed_at")


@dataclass(frozen=True)
class StoredEntry:
    id: str
    title: str
    description: str = ""
    action: str = "known"
    source: str = ""
    created_by: str = ""
    created_at: float = 0.0
    expires: str | None = None

    def expired(self, epoch: float) -> bool:
        return bool(self.expires) and datetime.fromtimestamp(epoch, TAIPEI).date().isoformat() > self.expires


@dataclass(frozen=True)
class LinkHit:
    """A cache hit: the alert's error identity is linked to `entry`."""

    entry: StoredEntry
    error_key: str
    linked_by: str = ""
    linked_at: float = 0.0
    sample_message: str = ""
    sample_label: str = ""
    expires_at: float | None = None
    hit_count: int = 0
    first_hit_at: float | None = None
    last_hit_at: float | None = None

    def reply_text(self) -> str:
        lines = [f"🔖 *固定錯誤*:{self.entry.title},屬已知現象,不另行分析"]
        if self.entry.description:
            lines.append(self.entry.description)
        source = f"<@{self.linked_by}> 標記" if self.linked_by else self.entry.source
        if source:
            expiry = f",連結 {_day(self.expires_at)} 到期" if self.expires_at else ""
            lines.append(f"_來源:{source}(`{self.entry.id}`{expiry})_")
        return "\n".join(lines)

    def magnitude_note(self) -> str:
        return f"🔖 此錯誤已標記為固定錯誤【{self.entry.title}】,但量級異常,仍送分析"


def _day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).date().isoformat()


def ensure_schema(store) -> None:
    with store.tx() as db:
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                db.execute(statement)
        present = {r[1] for r in db.execute("PRAGMA table_info(known_links)")}
        for column, decl, fill in _LINK_MIGRATIONS:
            if column in present:
                continue
            # BEGIN IMMEDIATE holds the write lock, so a concurrent process cannot race this ALTER.
            db.execute(f"ALTER TABLE known_links ADD COLUMN {column} {decl}")
            if fill:
                db.execute(fill)


def task_pk_of(alert: ParsedAlert) -> int | None:
    vkwargs = alert.extra.get("vkwargs") if isinstance(alert.extra, dict) else None
    pk = vkwargs.get("crontab_task_pk") if isinstance(vkwargs, dict) else None
    try:
        return int(pk) if pk is not None else None
    except (TypeError, ValueError):
        return None


def alert_error_key(alert: ParsedAlert, task_pk: int | None = None,
                    source_system: str = "") -> str | None:
    """`task_pk` defaults to the alert's own `crontab_task_pk`; `source_system` must be the
    one the collector resolved, or the key differs from the archived one."""
    pk = task_pk if task_pk is not None else task_pk_of(alert)
    return error_key(pk, alert.check_code, alert.level, alert.result_message, source_system)


def slug(title: str) -> str:
    """Lower-case id from a title; CJK characters are kept, other separators become `-`."""
    return re.sub(r"[^\w]+", "-", title.strip().lower()).strip("-_") or "known"


def _entry(row) -> StoredEntry:
    return StoredEntry(*row)


def get_entry(store, entry_id: str) -> StoredEntry | None:
    rows = store.read(f"SELECT {_ENTRY_COLS} FROM known_entries WHERE id=?", (entry_id,))
    return _entry(rows[0]) if rows else None


def find_entry(store, id_or_title: str) -> StoredEntry | None:
    """By id, then exact title, then the title's slug as id."""
    text = id_or_title.strip()
    found = get_entry(store, text)
    if found is None:
        rows = store.read(f"SELECT {_ENTRY_COLS} FROM known_entries WHERE title=? ORDER BY created_at"
                          " LIMIT 1", (text,))
        found = _entry(rows[0]) if rows else None
    return found or get_entry(store, slug(text))


def add_entry(store, entry_id: str, title: str, *, now: float, description: str = "",
              source: str = "", created_by: str = "", expires: str | None = None) -> StoredEntry:
    """Create the entry, or return the existing one with that id unchanged."""
    if not entry_id or not title:
        raise ValueError("id 與 title 必填")
    if expires is not None:
        datetime.strptime(expires, "%Y-%m-%d")
    with store.tx() as db:
        db.execute(
            "INSERT OR IGNORE INTO known_entries (id, title, description, action, source,"
            " created_by, created_at, expires) VALUES (?,?,?,?,?,?,?,?)",
            (entry_id, title, description, "known", source, created_by, now, expires))
    return get_entry(store, entry_id)


def link(store, key: str, known_id: str, *, now: float, linked_by: str = "",
         sample_message: str = "", sample_label: str = "", days: int = DEFAULT_LINK_DAYS) -> bool:
    """Point `key` at `known_id` until `days` (capped at MAX_LINK_DAYS) from `now`. True for
    a new link; relinking an existing key is a review: it moves the key, renews the expiry
    and keeps its creator and hit counters. Raises ValueError for a missing entry or days < 1."""
    if get_entry(store, known_id) is None:
        raise ValueError(f"沒有固定錯誤 {known_id!r}")
    if days < 1:
        raise ValueError("天數至少 1 天")
    expires_at = now + min(days, MAX_LINK_DAYS) * DAY
    with store.tx() as db:
        existed = db.execute("SELECT 1 FROM known_links WHERE error_key=?", (key,)).fetchone()
        db.execute(
            "INSERT INTO known_links (error_key, known_id, linked_by, linked_at, sample_message,"
            " sample_label, created_by, expires_at) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(error_key) DO UPDATE SET"
            " known_id=excluded.known_id, linked_by=excluded.linked_by,"
            " sample_message=excluded.sample_message, sample_label=excluded.sample_label,"
            " expires_at=excluded.expires_at, last_reviewed_by=excluded.linked_by,"
            " last_reviewed_at=?",
            (key, known_id, linked_by, now, (sample_message or "")[:SAMPLE_CHARS], sample_label or "",
             linked_by, expires_at, now))
    return existed is None


def record_hit(store, key: str, at: float) -> None:
    """Count one alert answered (or annotated) by the link of `key`; no-op without one."""
    with store.tx() as db:
        updated = db.execute(
            "UPDATE known_links SET hit_count=hit_count+1, first_hit_at=COALESCE(first_hit_at, ?),"
            " last_hit_at=MAX(COALESCE(last_hit_at, ?), ?) WHERE error_key=?",
            (at, at, at, key)).rowcount
        if updated:
            db.execute(
                "INSERT INTO known_link_daily (error_key, day, hits) VALUES (?,?,1)"
                " ON CONFLICT(error_key, day) DO UPDATE SET hits=hits+1", (key, _day(at)))


def unlink(store, key: str) -> StoredEntry | None:
    """Remove the link; returns the entry it pointed to, or None when there was none."""
    rows = store.read("SELECT known_id FROM known_links WHERE error_key=?", (key,))
    if not rows:
        return None
    with store.tx() as db:
        db.execute("DELETE FROM known_links WHERE error_key=?", (key,))
        db.execute("DELETE FROM known_link_daily WHERE error_key=?", (key,))
    return get_entry(store, rows[0][0])


def _entry_select() -> str:
    return ", ".join("e." + c.strip() for c in _ENTRY_COLS.split(","))


def lookup(store, key: str | None, now: float | None = None) -> LinkHit | None:
    """The linked entry for `key`; None for no key, no link, or a link or entry expired at
    `now`."""
    if not key:
        return None
    rows = store.read(
        f"SELECT {_entry_select()}, l.error_key, l.linked_by, l.linked_at, l.sample_message,"
        " l.sample_label, l.expires_at, l.hit_count, l.first_hit_at, l.last_hit_at"
        " FROM known_links l JOIN known_entries e ON e.id = l.known_id WHERE l.error_key=?", (key,))
    if not rows:
        return None
    row = rows[0]
    entry = _entry(row[:8])
    hit = LinkHit(entry, *row[8:])
    if now is not None and (entry.expired(now) or (hit.expires_at is not None and now >= hit.expires_at)):
        return None
    return hit


def _summaries(store, where: str, args: tuple, limit: int | None) -> list[dict]:
    sql = (f"SELECT {', '.join('e.' + c.strip() for c in _ENTRY_COLS.split(','))},"
           " COUNT(l.error_key),"
           " (SELECT sample_message FROM known_links s WHERE s.known_id = e.id"
           "  ORDER BY s.linked_at DESC LIMIT 1)"
           " FROM known_entries e LEFT JOIN known_links l ON l.known_id = e.id"
           f" {where} GROUP BY e.id ORDER BY e.created_at DESC, e.id")
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    return [{**_entry(row[:8]).__dict__, "links": row[8], "sample": row[9] or ""}
            for row in store.read(sql, args)]


def list_entries(store) -> list[dict]:
    """Every entry with `links` (linked error count) and its latest `sample` message."""
    return _summaries(store, "", (), None)


def search(store, text: str, limit: int = SEARCH_LIMIT) -> list[dict]:
    """Entries whose id, title, description or any linked sample contains `text`."""
    like = f"%{text.strip()}%"
    return _summaries(
        store,
        "WHERE e.id LIKE ? OR e.title LIKE ? OR e.description LIKE ? OR EXISTS ("
        " SELECT 1 FROM known_links m WHERE m.known_id = e.id"
        " AND (m.sample_message LIKE ? OR m.sample_label LIKE ?))",
        (like, like, like, like, like), limit)


def links_of(store, entry_id: str) -> list[dict]:
    rows = store.read(f"SELECT {', '.join(_LINK_COLS)} FROM known_links WHERE known_id=?"
                      " ORDER BY linked_at DESC", (entry_id,))
    return [dict(zip(_LINK_COLS, r)) for r in rows]


def review(store, now: float) -> dict[str, list[dict]]:
    """Links someone should look at, each a `links_of` row plus `known_id`, `title` and
    `hits_7d`: "expired" (no longer matching), "expiring" (within REVIEW_EXPIRING_DAYS),
    "idle" (neither hit nor reviewed for REVIEW_IDLE_DAYS) and "busy" (REVIEW_BUSY_HITS or more hits in the
    last REVIEW_BUSY_DAYS Taipei days). A link can be in several of the last three."""
    since_day = _day(now - (REVIEW_BUSY_DAYS - 1) * DAY)
    cols = ", ".join("l." + c for c in _LINK_COLS)
    rows = store.read(
        f"SELECT {cols}, l.known_id, e.title, COALESCE((SELECT SUM(d.hits) FROM known_link_daily d"
        "  WHERE d.error_key = l.error_key AND d.day >= ?), 0)"
        " FROM known_links l LEFT JOIN known_entries e ON e.id = l.known_id"
        " ORDER BY l.expires_at, l.error_key", (since_day,))
    found = {"expiring": [], "expired": [], "idle": [], "busy": []}
    for r in rows:
        row = {**dict(zip(_LINK_COLS, r)), "known_id": r[-3], "title": r[-2] or "", "hits_7d": r[-1]}
        expires_at = row["expires_at"]
        if expires_at is not None and expires_at <= now:
            found["expired"].append(row)
            continue
        if expires_at is not None and expires_at <= now + REVIEW_EXPIRING_DAYS * DAY:
            found["expiring"].append(row)
        last_seen = max(t for t in (row["linked_at"], row["last_hit_at"], row["last_reviewed_at"])
                        if t is not None)
        if last_seen < now - REVIEW_IDLE_DAYS * DAY:
            found["idle"].append(row)
        if row["hits_7d"] >= REVIEW_BUSY_HITS:
            found["busy"].append(row)
    return found


def render_search(results: list[dict], query: str) -> str:
    if not results:
        return f"🔍 找不到符合「{query}」的固定錯誤"
    lines = [f"🔍 符合「{query}」的固定錯誤({len(results)} 筆):"]
    for r in results:
        line = f"• `{r['id']}` *{r['title']}*(已連結 {r['links']} 種錯誤)"
        if r["sample"]:
            line += f"\n  例:{r['sample'][:120]}"
        lines.append(line)
    return "\n".join(lines)


_MENTION = re.compile(r"<@[A-Z0-9]+(?:\|[^>]*)?>")
LINK_COMMAND = "固定錯誤"
UNLINK_COMMAND = "取消固定"
SEARCH_COMMAND = "查"
NEED_THREAD = "請在告警的討論串裡使用此指令(找不到這個串對應的告警)"
NOT_EDITOR = ("🙏 抱歉,只有維護名單(設定檔 known_editors)上的成員可以「固定錯誤 / 取消固定」;"
              "「查」所有人都能用。需要加入名單請洽 alert-doctor 維護者。")
_DAYS_SUFFIX = re.compile(r"^(.*?)\s*(\d+)\s*天$")


def parse_command(text: str) -> tuple[str, str] | None:
    """(command, argument) from a mention's text, or None when it is not a known-error command."""
    body = _MENTION.sub(" ", text or "").strip()
    for command in (UNLINK_COMMAND, LINK_COMMAND, SEARCH_COMMAND):
        if body == command or body.startswith(command + " ") or body.startswith(command + "　"):
            return command, body[len(command):].strip()
    return None


def _label_of(alert: ParsedAlert) -> str:
    vkwargs = alert.extra.get("vkwargs") if isinstance(alert.extra, dict) else None
    label = vkwargs.get("crontab_task_label") if isinstance(vkwargs, dict) else None
    return str(label or alert.check_title or "")


def _split_days(argument: str) -> tuple[str, int | None]:
    """(title, days) from `<title> 30天`; days None when no suffix is given."""
    match = _DAYS_SUFFIX.match(argument)
    if not match or not match.group(1):
        return argument, None
    return match.group(1).strip(), int(match.group(2))


def _unreliable_reason(alert: ParsedAlert) -> str | None:
    if alert.truncated:
        return "這則告警原文超過 Slack 長度上限被截斷"
    if not signature_is_reliable(alert.result_message or ""):
        return "這則告警引用的 log 被截斷,而且沒有可辨識的錯誤代碼"
    return None


def handle_command(store, command: str, argument: str, *, alert: ParsedAlert | None, user: str,
                   now: float, source_system: str = "", can_edit: bool) -> str:
    """Run one parsed mention command; `alert` is the thread's anchor alert (None outside
    an alert thread) and `source_system` the system the collector resolved for it. Linking
    and unlinking need `can_edit`. Returns the reply text."""
    if command == SEARCH_COMMAND:
        if not argument:
            return f"用法:`{SEARCH_COMMAND} <關鍵字>`"
        return render_search(search(store, argument), argument)
    if not can_edit:
        return NOT_EDITOR
    key = alert_error_key(alert, source_system=source_system) if alert is not None else None
    if key is None:
        return NEED_THREAD
    if command == UNLINK_COMMAND:
        entry = unlink(store, key)
        if entry is None:
            return "此錯誤樣式沒有連結任何固定錯誤"
        return f"已取消此錯誤樣式與【{entry.title}】的連結,之後相同錯誤恢復正常分析"
    title, days = _split_days(argument)
    if not title or days == 0:
        return f"用法:`{LINK_COMMAND} <名稱或既有 id> [天數,例如 30天]`(預設 {DEFAULT_LINK_DAYS} 天,最多 {MAX_LINK_DAYS} 天)"
    reason = _unreliable_reason(alert)
    if reason:
        return (f"⚠️ 無法固定:{reason},錯誤樣式不可靠,固定後可能把不同的錯誤一起略過。"
                "請等下一則完整的同類告警再標記,或在 known.toml 設定有範圍限制的規則。")
    entry = find_entry(store, title)
    if entry is None:
        entry = add_entry(store, slug(title), title, now=now, created_by=user,
                          source=f"<@{user}> {_day(now)} 於 Slack 標記")
    days = days or DEFAULT_LINK_DAYS
    link(store, key, entry.id, now=now, linked_by=user, sample_message=alert.result_message,
         sample_label=_label_of(alert), days=days)
    capped = f",最多 {MAX_LINK_DAYS} 天" if days > MAX_LINK_DAYS else ""
    expires = _day(now + min(days, MAX_LINK_DAYS) * DAY)
    return (f"已將此錯誤樣式連結到【{entry.title}】,之後相同錯誤直接回覆不再分析"
            f"(連結 {expires} 到期{capped},到期後恢復分析)")
