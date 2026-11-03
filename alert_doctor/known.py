"""Known background: recurring maintenance windows and fixed errors people already explained.

An entry with action "known" answers a matching alert without analysis; "context" entries
only reach the analyzer as background. Windows are Taipei wall-clock times.

A "known" entry must be scoped (systems plus task_pks or check_codes): a window alone, or a
regex alone, would silence unrelated errors that happen to run at the same hour.
"""
from __future__ import annotations

import logging
import os
import re
import tomllib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from alert_doctor.models import ParsedAlert

log = logging.getLogger("alert_doctor.known")

TAIPEI = timezone(timedelta(hours=8))
ACTIONS = ("known", "context")
DEFAULT_GRACE_MINUTES = {"known": 2, "context": 5}
DAY_SETS = {
    "daily": frozenset(range(7)),
    "weekdays": frozenset(range(5)),
    "weekends": frozenset((5, 6)),
}
DAY_MINUTES = 24 * 60
# Past a week every daily window overlaps anyway; the cap keeps a stale incident cheap.
MAX_SCAN_DAYS = 8
ENTRY_KEYS = {"id", "title", "description", "windows", "match", "action", "grace_minutes",
              "expires", "source"}
WINDOW_KEYS = {"start", "end", "days", "label"}
MATCH_KEYS = {"systems", "any_regex", "all_regex", "check_codes", "task_pks"}
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


@dataclass(frozen=True)
class KnownWindow:
    """`start`/`end` are minutes after Taipei midnight; `end < start` crosses midnight.
    `days` holds weekday numbers (Monday = 0) of the day the window starts."""

    start: int
    end: int
    days: frozenset
    label: str = ""

    @property
    def span(self) -> str:
        return f"{_hhmm(self.start)}–{_hhmm(self.end)}"

    @property
    def duration(self) -> int:
        return (self.end - self.start) % DAY_MINUTES

    def occurrences(self, first_day: date, last_day: date):
        """(start, end) datetimes of every occurrence starting between the two days, inclusive."""
        day = first_day
        while day <= last_day:
            if day.weekday() in self.days:
                start = datetime(day.year, day.month, day.day, tzinfo=TAIPEI) + timedelta(minutes=self.start)
                yield start, start + timedelta(minutes=self.duration)
            day += timedelta(days=1)


@dataclass(frozen=True)
class KnownEntry:
    id: str
    title: str
    windows: tuple
    action: str
    description: str = ""
    systems: tuple = ()
    any_regex: tuple = ()
    all_regex: tuple = ()
    check_codes: tuple = ()
    task_pks: tuple = ()
    grace_minutes: int = DEFAULT_GRACE_MINUTES["known"]
    expires: date | None = None
    source: str = ""

    def expired(self, epoch: float) -> bool:
        return self.expires is not None and _local(epoch).date() > self.expires

    @property
    def has_text_filter(self) -> bool:
        return bool(self.any_regex or self.all_regex)

    def text_matches(self, alert: ParsedAlert) -> bool:
        """At least one `any_regex` (when given) and every `all_regex` pattern found."""
        if not self.has_text_filter:
            return False
        text = "\n".join((alert.result_message or "", alert.check_title or "", alert.raw_text or ""))
        if self.any_regex and not any(p.search(text) for p in self.any_regex):
            return False
        return all(p.search(text) for p in self.all_regex)

    def scope_matches(self, alert: ParsedAlert, source_system: str) -> bool:
        if self.systems and source_system not in self.systems:
            return False
        if self.check_codes and alert.check_code not in self.check_codes:
            return False
        if self.task_pks and _task_pk(alert) not in self.task_pks:
            return False
        return True

    def matches(self, alert: ParsedAlert, source_system: str) -> bool:
        if not self.scope_matches(alert, source_system):
            return False
        return self.text_matches(alert) if self.has_text_filter else True


@dataclass(frozen=True)
class KnownHit:
    entry: KnownEntry
    window: KnownWindow
    distance_minutes: float = 0.0

    def reply_text(self) -> str:
        return known_reply(self)

    def magnitude_note(self) -> str:
        return f"🔖 正值固定維護窗【{self.entry.title}】({self.label}),但量級異常,仍送分析"

    @property
    def label(self) -> str:
        if self.window.label:
            return f"{_hhmm(self.window.start)} {self.window.label}"
        return self.window.span


def _hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def _local(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, TAIPEI)


def _task_pk(alert: ParsedAlert):
    vkwargs = alert.extra.get("vkwargs") if isinstance(alert.extra, dict) else None
    return vkwargs.get("crontab_task_pk") if isinstance(vkwargs, dict) else None


def _parse_minutes(entry_id: str, value) -> int:
    match = _HHMM.match(value) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"known {entry_id!r}: 時間必須是 HH:MM(00:00–23:59),拿到 {value!r}")
    return int(match.group(1)) * 60 + int(match.group(2))


def _parse_days(entry_id: str, value) -> frozenset:
    if isinstance(value, str) and value in DAY_SETS:
        return DAY_SETS[value]
    if (isinstance(value, list) and value
            and all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in value)):
        return frozenset(value)
    raise ValueError(f"known {entry_id!r}: days 必須是 daily / weekdays / weekends 或 0–6 的清單,拿到 {value!r}")


def _parse_window(entry_id: str, raw) -> KnownWindow:
    if not isinstance(raw, dict):
        raise ValueError(f"known {entry_id!r}: windows 的每一項必須是 {{start, end}} 表格")
    unknown = sorted(set(raw) - WINDOW_KEYS)
    if unknown:
        raise ValueError(f"known {entry_id!r}: windows 有不認得的欄位 {unknown}")
    if "start" not in raw or "end" not in raw:
        raise ValueError(f"known {entry_id!r}: windows 每一項都要有 start 與 end")
    start = _parse_minutes(entry_id, raw["start"])
    end = _parse_minutes(entry_id, raw["end"])
    if start == end:
        raise ValueError(f"known {entry_id!r}: window 的 start 與 end 不能相同")
    return KnownWindow(start, end, _parse_days(entry_id, raw.get("days", "daily")),
                       str(raw.get("label", "")))


def _parse_expires(entry_id: str, value) -> date | None:
    # TOML parses an unquoted 2026-12-31 as date but a quoted one as str; accept both.
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            pass
    raise ValueError(f"known {entry_id!r}: expires 必須是 YYYY-MM-DD,拿到 {value!r}")


def _str_list(entry_id: str, key: str, value) -> tuple:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"known {entry_id!r}: {key} 必須是字串清單")
    return tuple(value)


def _patterns(entry_id: str, key: str, match: dict) -> tuple:
    try:
        return tuple(re.compile(p, re.IGNORECASE) for p in _str_list(entry_id, key, match.get(key, [])))
    except re.error as exc:
        raise ValueError(f"known {entry_id!r}: {key} 無法編譯:{exc}") from None


def _parse_entry(raw) -> KnownEntry:
    entry_id = raw.get("id", "<no id>") if isinstance(raw, dict) else "<no id>"
    if not isinstance(raw, dict):
        raise ValueError(f"known {entry_id!r}: [[known]] 必須是表格")
    unknown = sorted(set(raw) - ENTRY_KEYS)
    if unknown:
        raise ValueError(f"known {entry_id!r}: 不認得的欄位 {unknown}")
    if not raw.get("id") or not raw.get("title"):
        raise ValueError(f"known {entry_id!r}: id 與 title 必填")
    action = raw.get("action", "known")
    if action not in ACTIONS:
        raise ValueError(f"known {entry_id!r}: action 必須是 {' / '.join(ACTIONS)},拿到 {action!r}")
    windows = raw.get("windows")
    if not isinstance(windows, list) or not windows:
        raise ValueError(f"known {entry_id!r}: windows 至少要有一段")
    grace = raw.get("grace_minutes", DEFAULT_GRACE_MINUTES[action])
    if not isinstance(grace, int) or isinstance(grace, bool) or not 0 <= grace <= 180:
        raise ValueError(f"known {entry_id!r}: grace_minutes 必須是 0–180 的整數,拿到 {grace!r}")
    match = raw.get("match", {})
    if not isinstance(match, dict):
        raise ValueError(f"known {entry_id!r}: match 必須是表格")
    unknown = sorted(set(match) - MATCH_KEYS)
    if unknown:
        raise ValueError(f"known {entry_id!r}: match 有不認得的欄位 {unknown}")
    patterns = _patterns(entry_id, "any_regex", match)
    all_patterns = _patterns(entry_id, "all_regex", match)
    task_pks = match.get("task_pks", [])
    if not isinstance(task_pks, list) or not all(
            isinstance(v, int) and not isinstance(v, bool) for v in task_pks):
        raise ValueError(f"known {entry_id!r}: task_pks 必須是整數清單")
    check_codes = _str_list(entry_id, "check_codes", match.get("check_codes", []))
    systems = _str_list(entry_id, "systems", match.get("systems", []))
    if action == "known" and not (systems and (check_codes or task_pks)):
        raise ValueError(f"known {entry_id!r}: action = \"known\" 必須同時限定 systems 與"
                         " task_pks / check_codes 其中之一;範圍說不清楚就改用 action = \"context\"")
    return KnownEntry(
        id=str(raw["id"]), title=str(raw["title"]), action=action,
        windows=tuple(_parse_window(entry_id, w) for w in windows),
        description=str(raw.get("description", "")).strip(),
        systems=systems, any_regex=patterns, all_regex=all_patterns, check_codes=check_codes,
        task_pks=tuple(task_pks),
        grace_minutes=grace, expires=_parse_expires(entry_id, raw.get("expires")),
        source=str(raw.get("source", "")),
    )


def load_known(path: str) -> list[KnownEntry]:
    """Parse `[[known]]` entries in file order; a missing file is an empty list.

    Raises ValueError naming the entry id on any invalid or duplicate entry.
    """
    if not path or not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        data = tomllib.load(f)
    entries = [_parse_entry(raw) for raw in data.get("known", [])]
    seen = set()
    for entry in entries:
        if entry.id in seen:
            raise ValueError(f"known {entry.id!r}: id 重複")
        seen.add(entry.id)
    return entries


def _distance(window: KnownWindow, epoch: float) -> float:
    """Minutes from `epoch` to the nearest occurrence of `window` (0 inside it)."""
    moment = _local(epoch)
    today = moment.date()
    best = float("inf")
    for start, end in window.occurrences(today - timedelta(days=1), today + timedelta(days=1)):
        if start <= moment <= end:
            return 0.0
        gap = (start - moment) if moment < start else (moment - end)
        best = min(best, gap.total_seconds() / 60)
    return best


def match_known(entries, alert: ParsedAlert, now_epoch: float, source_system: str,
                action: str | None = None) -> KnownHit | None:
    """The best hit for an alert at `now_epoch`, or None.

    An entry hits when it is not expired, its `match` filters accept the alert, and
    `now_epoch` is within `grace_minutes` of one of its windows. Among hits the closest
    window wins, then the shortest (a host's own restart over the whole night), then file
    order. `action` restricts the entries considered.
    """
    best = None
    best_key = None
    for order, entry in enumerate(entries):
        if action is not None and entry.action != action:
            continue
        if entry.expired(now_epoch) or not entry.matches(alert, source_system):
            continue
        for window in entry.windows:
            distance = _distance(window, now_epoch)
            if distance > entry.grace_minutes:
                continue
            key = (distance, window.duration, order)
            if best_key is None or key < best_key:
                best, best_key = KnownHit(entry, window, distance), key
    return best


def known_reply(hit: KnownHit) -> str:
    entry = hit.entry
    lines = [f"🔖 *固定維護窗*:{entry.title}({hit.label}),屬已知現象,不另行分析"]
    if entry.description:
        lines.append(entry.description)
    if entry.source:
        lines.append(f"_來源:{entry.source}_")
    return "\n".join(lines)


def _overlapping(entry: KnownEntry, since: float, until: float) -> list[str]:
    grace = timedelta(minutes=entry.grace_minutes)
    lo, hi = _local(since), _local(max(since, until))
    first_day = lo.date() - timedelta(days=1)
    last_day = min(hi.date(), lo.date() + timedelta(days=MAX_SCAN_DAYS))
    found = []
    for window in entry.windows:
        label = KnownHit(entry, window).label
        if any(start - grace <= hi and lo <= end + grace
               for start, end in window.occurrences(first_day, last_day)):
            found.append(label)
    return found


def background(entries, alert: ParsedAlert | None, first_epoch: float, last_epoch: float,
               source_system: str, lookback_seconds: float = 1800) -> list[dict]:
    """Analyzer background: every unexpired entry with a window overlapping
    [first_epoch - lookback_seconds, last_epoch], or whose filters accept the alert."""
    found = []
    for entry in entries:
        if entry.expired(last_epoch):
            continue
        windows = _overlapping(entry, first_epoch - lookback_seconds, last_epoch)
        text_match = alert is not None and entry.has_text_filter and entry.matches(alert, source_system)
        if not windows and not text_match:
            continue
        found.append({
            "id": entry.id,
            "title": entry.title,
            "description": entry.description,
            "action": entry.action,
            "source": entry.source,
            "windows": [{"label": KnownHit(entry, w).label, "span": w.span,
                         "days": sorted(w.days)} for w in entry.windows],
            "grace_minutes": entry.grace_minutes,
            "in_window": bool(windows),
            "overlapping_windows": windows,
            "text_match": text_match,
        })
    return found


class KnownSource:
    """Entries from a file, re-read when its mtime changes so edits apply without a restart.

    A file that fails to parse is logged and the last good entries stay in force.
    """

    def __init__(self, path: str, loader=load_known):
        self.path = path or ""
        self._loader = loader
        self._mtime = None
        self._entries: list[KnownEntry] = []

    def entries(self) -> list[KnownEntry]:
        try:
            mtime = os.stat(self.path).st_mtime if self.path else None
        except OSError:
            mtime = None
        if mtime is None:
            self._mtime, self._entries = None, []
            return self._entries
        if mtime != self._mtime:
            try:
                self._entries = self._loader(self.path)
            except Exception as exc:
                log.error("固定錯誤清單 %s 載入失敗,沿用上一版:%s", self.path, exc)
            self._mtime = mtime
        return self._entries


class _Static:
    def __init__(self, entries):
        self._entries = list(entries)

    def entries(self) -> list[KnownEntry]:
        return self._entries


def as_source(value):
    """A source from a KnownSource-like object, a list of entries, or a path."""
    if hasattr(value, "entries"):
        return value
    if isinstance(value, (list, tuple)):
        return _Static(value)
    return KnownSource(value or "")
