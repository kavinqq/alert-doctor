"""Read-only view of the exported watchdog schedule snapshot (`tasks.json`)."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from alert_doctor.models import ParsedAlert
from alert_doctor.redact import strip_secrets

log = logging.getLogger(__name__)

ELK_INDEX = "log*"
# Only check_log_message fails when its keywords appear. Other scripts take `keywords` too, e.g.
# riJG42iS-Dl7JNwYe5cP5 (查不到關鍵字就報錯) fails when they are absent, so querying for those
# keywords would measure the healthy case.
KEYWORD_QUERY_CODES = frozenset({"MDlNB90WVnwW-YUfdtieV"})
_CRON_ORDER = ("minute", "hour", "day_of_month", "month_of_year", "day_of_week")


@dataclass(frozen=True)
class TaskInfo:
    id: int
    label: str
    enabled: bool
    cron: str
    check_code: str
    check_title: str
    kwargs: dict
    channels: tuple[str, ...]
    owners: tuple[str, ...]


@dataclass(frozen=True)
class Snapshot:
    exported_at: str
    _tasks: dict

    def task(self, pk: int | None) -> TaskInfo | None:
        return self._tasks.get(pk)

    def tasks(self) -> list[TaskInfo]:
        return list(self._tasks.values())

    def task_for_alert(self, alert: ParsedAlert) -> TaskInfo | None:
        vkwargs = alert.extra.get("vkwargs") if isinstance(alert.extra, dict) else None
        if not isinstance(vkwargs, dict):
            return None
        try:
            pk = int(vkwargs.get("crontab_task_pk"))
        except (TypeError, ValueError):
            return None
        return self.task(pk)


def _redact_kwargs(kwargs: dict) -> dict:
    # `sql_pwad` (sic) exists in the real data and slips past redact.SECRET_KEY.
    cleaned = strip_secrets(kwargs)
    return {k: "<redacted>" if "pw" in k.lower() else v for k, v in cleaned.items()}


def _cron(raw: dict) -> str:
    return " ".join(str(raw.get(part, "*")) for part in _CRON_ORDER)


def _unique(items) -> tuple:
    return tuple(dict.fromkeys(items))


def _build(raw: dict) -> Snapshot:
    scripts = {s["id"]: s for s in raw.get("check_scripts") or ()}
    channels = {c["id"]: c["channel_id"] for c in raw.get("channels") or ()}
    users = {u["id"]: u["user_id"] for u in raw.get("users") or () if not u.get("is_deleted")}
    groups = {g["id"]: g for g in raw.get("groups") or ()}
    tasks = {}
    for t in raw.get("tasks") or ():
        script = scripts.get(t.get("check_script_id"), {})
        task_groups = [groups[g] for g in t.get("groups") or () if g in groups]
        tasks[t["id"]] = TaskInfo(
            id=t["id"], label=t.get("label", ""), enabled=bool(t.get("enabled")),
            cron=_cron(t.get("cron") or {}),
            check_code=script.get("code", ""), check_title=script.get("title", ""),
            kwargs=_redact_kwargs(t.get("kwargs") or {}),
            channels=_unique(channels[c] for g in task_groups for c in g.get("channels") or ()
                             if c in channels),
            owners=_unique(users[u] for g in task_groups for u in g.get("users") or ()
                           if u in users),
        )
    return Snapshot(exported_at=raw.get("exported_at", ""), _tasks=tasks)


def load_snapshot(path: str) -> Snapshot | None:
    """Return None when the file is absent or unreadable; the snapshot is optional."""
    try:
        return _build(json.loads(Path(path).read_text()))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        log.warning("watchdog 快照讀取失敗 %s:%s", path, exc)
        return None


def _phrases(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value] if isinstance(value, (list, tuple)) else []


def elk_query_from_kwargs(kwargs: dict) -> dict | None:
    """Optimised equivalent of what `check_log_message` runs (tags/time as filters, which skip scoring)."""
    keywords = _phrases(kwargs.get("keywords"))
    if not keywords:
        return None
    flt = [{"range": {"@timestamp": {"gte": "{{from}}", "lte": "{{to}}"}}}]
    tags = _phrases(kwargs.get("log_tags"))
    if tags:
        flt.append({"terms": {"log.tags": tags}})
    query = {
        "filter": flt,
        "must": [{"match_phrase": {"log.message": k}} for k in keywords],
    }
    excluded = _phrases(kwargs.get("except_keywords"))
    if excluded:
        query["must_not"] = [{"match_phrase": {"log.message": k}} for k in excluded]
    return {"bool": query}


def elk_index_for(kwargs: dict) -> str:
    return ELK_INDEX


def alert_label(alert: ParsedAlert, snapshot: Snapshot | None) -> str:
    task = snapshot.task_for_alert(alert) if snapshot else None
    return task.label if task else alert.check_title
