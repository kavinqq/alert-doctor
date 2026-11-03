"""Turn configured owners (user ID, user-group ID or email) into Slack mention strings."""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("alert_doctor.mentions")

# email -> user ID, or None when Slack said there is no such user.
_email_cache: dict[str, str | None] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    with _cache_lock:
        _email_cache.clear()


def _email_user(slack, bot_token: str, email: str) -> str | None:
    with _cache_lock:
        if email in _email_cache:
            return _email_cache[email]
    lookup = getattr(slack, "lookup_user_by_email", None)
    if lookup is None:
        log.warning("無法解析 owner email %s:Slack 介面沒有 lookup_user_by_email", email)
        return None
    try:
        user = lookup(bot_token, email)
    except Exception as exc:
        # Not cached: a transient failure must not drop the owner for the rest of the process.
        log.warning("查詢 owner email %s 失敗:%s", email, exc)
        return None
    with _cache_lock:
        _email_cache[email] = user
    if user is None:
        log.warning("Slack 找不到 owner email %s,略過不 @", email)
    return user


def mention(slack, bot_token: str, owner: str) -> str | None:
    owner = owner.strip()
    if owner.startswith("<") and owner.endswith(">"):
        return owner
    if "@" in owner:
        user = _email_user(slack, bot_token, owner)
        return f"<@{user}>" if user else None
    if owner[:1] in ("U", "W"):
        return f"<@{owner}>"
    if owner[:1] == "S":
        return f"<!subteam^{owner}>"
    log.warning("看不懂的 owner 格式 %r(應為 U…/W…/S… 或 email),略過", owner)
    return None


def resolve_owners(slack, bot_token: str, owners) -> tuple[str, ...]:
    """Mention strings for `owners`; unresolvable ones are logged and skipped, never raised."""
    found = (mention(slack, bot_token, o) for o in owners or ())
    return tuple(dict.fromkeys(m for m in found if m))


def owners_for(cfg, system: str, check=None) -> tuple[str, ...]:
    """Check-level owners win; the system's owners are the fallback.

    Pass `check` only when the mention is about the alert's own system: a check's owners
    are not the owners of another system the root cause was traced to.
    """
    if check is not None and check.owners:
        return tuple(check.owners)
    spec = cfg.systems.get(system)
    return tuple(spec.owners) if spec else ()


def first_message_owners(cfg, source_system: str, check=None) -> tuple[str, ...]:
    """Raw owners to tag on an incident's first message: global defaults, then check/system owners."""
    defaults = tuple(getattr(cfg, "default_owners", ()))
    return tuple(dict.fromkeys(defaults + owners_for(cfg, source_system, check)))


def warm(slack, bot_token: str, cfg, checks: dict | None = None) -> None:
    """Resolve every configured email once at startup so later replies hit the cache."""
    owners = [o for spec in cfg.systems.values() for o in spec.owners]
    owners += [o for check in (checks or {}).values() for o in check.owners]
    resolve_owners(slack, bot_token, [o for o in owners if "@" in o])
