from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from dataclasses import fields
from datetime import date, datetime, timedelta, timezone

from alert_doctor.models import ParsedAlert, RuleMatch

ACTIONS = ("noise", "known", "never_silence", "datasource")
TAIPEI = timezone(timedelta(hours=8))


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    match_code: str | None = None
    match_title: str | None = None
    match_message: str | None = None
    level: int | None = None
    note: str = ""
    link: str | None = None
    require_transient: bool = False
    max_count: int = 20
    expires: date | None = None


def _parse_expires(rule_id: str, value: object) -> date | None:
    # TOML parses an unquoted 2026-12-31 as datetime.date but a quoted one as str; accept both.
    if value is None:
        return None
    if isinstance(value, datetime):
        raise ValueError(f"rule {rule_id!r}: expires must be a date, got datetime {value!r}")
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError(f"rule {rule_id!r}: expires must be YYYY-MM-DD, got {value!r}") from None
    raise ValueError(f"rule {rule_id!r}: expires must be a date or YYYY-MM-DD string, got {value!r}")


def load_rules(path: str) -> list[Rule]:
    """Parse `[[rules]]` tables in file order.

    Raises ValueError (naming the rule id) on a missing id/action, unknown key, bad action, bad regex or bad `expires`.
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)
    rules = []
    for raw in data.get("rules", []):
        rule_id = raw.get("id", "<no id>")
        unknown = sorted(set(raw) - {f.name for f in fields(Rule)})
        if unknown:
            raise ValueError(f"rule {rule_id!r}: unknown keys {unknown}")
        if "id" not in raw or "action" not in raw:
            raise ValueError(f"rule {rule_id!r}: id and action are required")
        rule = Rule(**{**raw, "expires": _parse_expires(rule_id, raw.get("expires"))})
        if rule.action not in ACTIONS:
            raise ValueError(f"rule {rule.id!r}: unknown action {rule.action!r}")
        for pattern in (rule.match_code, rule.match_title, rule.match_message):
            if pattern is not None:
                re.compile(pattern)
        rules.append(rule)
    return rules


def _expired(rule: Rule, now: float) -> bool:
    if not rule.expires:
        return False
    today = datetime.fromtimestamp(now, TAIPEI).date()
    return today > rule.expires


def _hit(pattern: str | None, value: str | None) -> bool:
    if pattern is None:
        return True
    return value is not None and re.search(pattern, value) is not None


def match_rule(rules: list[Rule], alert: ParsedAlert, now: float) -> RuleMatch | None:
    """First non-expired rule whose every given criterion matches; `expires` is inclusive (Asia/Taipei date)."""
    for rule in rules:
        if _expired(rule, now):
            continue
        if rule.level is not None and rule.level != alert.level:
            continue
        if (
            _hit(rule.match_code, alert.check_code)
            and _hit(rule.match_title, alert.check_title)
            and _hit(rule.match_message, alert.result_message)
        ):
            return RuleMatch(
                rule_id=rule.id,
                action=rule.action,
                note=rule.note,
                link=rule.link,
                require_transient=rule.require_transient,
                max_count=rule.max_count,
            )
    return None
