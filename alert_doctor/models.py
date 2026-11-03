from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    NOISE = "noise"
    KNOWN = "known"
    DUPLICATE = "duplicate"
    NEW = "new"
    SPIKE = "spike"
    CRITICAL = "critical"
    UNPARSED = "unparsed"
    DATASOURCE = "datasource"
    ACCUMULATED = "accumulated"


class Reaction:
    NOISE = "mute"
    KNOWN = "bookmark"
    DUPLICATE = "repeat"
    ANALYZING = "mag"
    CRITICAL = "rotating_light"
    UNPARSED = "grey_question"
    DATASOURCE = "warning"
    DONE = "white_check_mark"
    NEEDS_HUMAN = "raising_hand"
    ACCUMULATED = "chart_with_upwards_trend"
    SEV_LOW = "large_green_circle"
    SEV_MEDIUM = "large_yellow_circle"
    SEV_HIGH = "large_orange_circle"
    SEV_CRITICAL = "red_circle"


SEVERITY_REACTION = {
    "low": Reaction.SEV_LOW,
    "medium": Reaction.SEV_MEDIUM,
    "high": Reaction.SEV_HIGH,
    "critical": Reaction.SEV_CRITICAL,
}


@dataclass(frozen=True)
class ParsedAlert:
    """One watchdog message from the watched Slack channel.

    `parse_ok` is False when the `extra` dict could not be recovered; the alert is
    still stored and replied to, only with coarser classification. `truncated` marks text
    cut inside `result.message` (Slack's length limit, or the head of a split message);
    it is stored with the message.
    """

    channel: str
    ts: str
    raw_text: str
    parse_ok: bool
    check_title: str
    check_code: str | None = None
    task_id: str | None = None
    level: int | None = None
    result_message: str = ""
    extra: dict = field(default_factory=dict)
    mentions: tuple[str, ...] = ()
    truncated: bool = False

    @property
    def epoch(self) -> float:
        return float(self.ts)


@dataclass(frozen=True)
class Incident:
    id: int
    fingerprint: str
    group_fp: str
    check_code: str | None
    check_title: str
    channel: str
    anchor_ts: str
    first_epoch: float
    last_epoch: float
    count: int
    analysis_state: str
    verdict: dict | None = None
    attempts: int = 0
    source_system: str = ""
    fresh_requested: bool = False


ANALYSIS_STATES = ("none", "pending", "leased", "done", "failed")


@dataclass(frozen=True)
class ElkSpec:
    index: str
    query: dict
    host_field: str = "log.extra.server_ip"
    lookback_minutes: int = 15
    total_query: dict | None = None


@dataclass(frozen=True)
class CheckSpec:
    key: str
    system: str = ""
    never_silence: bool = False
    owners: tuple[str, ...] = ()
    repo: str | None = None
    deploy_ref: str = "origin/HEAD"
    elk: ElkSpec | None = None
    signal: str = "count"
    min_errors: int = 5


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    action: str
    note: str = ""
    link: str | None = None
    require_transient: bool = False
    max_count: int = 20


@dataclass(frozen=True)
class Evidence:
    query_ok: bool
    window_from: str
    window_to: str
    total: int | None = None
    per_host: dict = field(default_factory=dict)
    histogram: tuple = ()
    samples: tuple = ()
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "query_ok": self.query_ok,
            "window_from": self.window_from,
            "window_to": self.window_to,
            "total": self.total,
            "per_host": dict(self.per_host),
            "histogram": [list(b) for b in self.histogram],
            "samples": list(self.samples),
            "error": self.error,
        }


@dataclass(frozen=True)
class Decision:
    category: Category
    reply_text: str
    reaction: str
    needs_analysis: bool
    rule: RuleMatch | None = None
    severity: str | None = None
    # What the collector must do about the matched auto rule:
    # "silenced" | "sample" | "shadow" (count a shadow hit) | "invalidate" | None.
    auto_effect: str | None = None
