from __future__ import annotations

from dataclasses import dataclass

from alert_doctor.config import SystemSpec

INDEX = "logs-generic-*"
DAY_SECONDS = 86400
MIN_ERRORS = 5
MIN_RATIO = 3
ID_FIELDS = ("log.extra.request_id", "log.request_id")
LOOKUP_MARGIN_SECONDS = 300
LOOKUP_SIZE = 200


@dataclass(frozen=True)
class Candidate:
    system: str
    errors_now: int
    errors_before: int
    ratio: float


def _range(start: float, end: float) -> dict:
    return {"range": {"@timestamp": {
        "gte": int(start * 1000), "lte": int(end * 1000), "format": "epoch_millis"}}}


def _count(elk, spec: SystemSpec, start: float, end: float) -> int:
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [spec.error_query, _range(start, end)]}},
    }
    return elk.search(INDEX, body)["hits"]["total"]["value"]


def with_elk_project(systems: dict[str, SystemSpec]) -> dict[str, SystemSpec]:
    """Systems whose ELK project is known; an empty one (待確認) would query nothing useful."""
    return {k: v for k, v in systems.items() if v.elk_project}


def co_erroring(elk, systems: dict[str, SystemSpec], until: float,
                window_minutes: int = 15, exclude: str = "") -> list[Candidate]:
    """Systems whose error count in `[until-window, until]` is at least 5 and 3x the same window a day earlier.

    Clues only, not causes. A system whose query fails is skipped; ordered by ratio, highest first.
    """
    start = until - window_minutes * 60
    found = []
    for key, spec in with_elk_project(systems).items():
        if key == exclude:
            continue
        try:
            now = _count(elk, spec, start, until)
            before = _count(elk, spec, start - DAY_SECONDS, until - DAY_SECONDS)
        except Exception:
            continue
        ratio = (now + 1) / (before + 1)
        if now >= MIN_ERRORS and ratio >= MIN_RATIO:
            found.append(Candidate(key, now, before, ratio))
    return sorted(found, key=lambda c: c.ratio, reverse=True)


def _dig(src: dict, dotted: str):
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _request_id(src: dict) -> str | None:
    for name in ID_FIELDS:
        value = _dig(src, name)
        if value:
            return str(value)
    return None


def _sample_ids(elk, spec: SystemSpec, start: float, until: float, samples: int) -> list[str]:
    body = {
        "size": samples,
        "sort": [{"@timestamp": "desc"}],
        "_source": list(ID_FIELDS),
        "query": {"bool": {
            "filter": [{"term": {"project": spec.elk_project}}, _range(start, until)],
            "should": [{"exists": {"field": name}} for name in ID_FIELDS],
            "minimum_should_match": 1,
        }},
    }
    hits = elk.search(INDEX, body)["hits"]["hits"]
    ids = {_request_id(h.get("_source", {})) for h in hits}
    return sorted(i for i in ids if i)


def _found_ids(elk, spec: SystemSpec, ids: list[str], start: float, until: float) -> set[str]:
    body = {
        "size": LOOKUP_SIZE,
        "_source": list(ID_FIELDS),
        "query": {"bool": {
            "filter": [
                {"term": {"project": spec.elk_project}},
                _range(start - LOOKUP_MARGIN_SECONDS, until + LOOKUP_MARGIN_SECONDS),
            ],
            "should": [{"terms": {name: ids}} for name in ID_FIELDS],
            "minimum_should_match": 1,
        }},
    }
    hits = elk.search(INDEX, body)["hits"]["hits"]
    return {i for i in (_request_id(h.get("_source", {})) for h in hits) if i} & set(ids)


def audit_request_ids(elk, systems: dict[str, SystemSpec], until: float,
                      samples: int = 20, window_minutes: int = 15) -> str:
    """繁中 report on whether request ids sampled from one system show up in the others."""
    start = until - window_minutes * 60
    sampled: dict[str, list[str]] = {}
    lines = [f"- {key}:elk_project 未設定(待確認),略過" for key, spec in systems.items()
             if not spec.elk_project]
    systems = with_elk_project(systems)
    for key, spec in systems.items():
        try:
            ids = _sample_ids(elk, spec, start, until, samples)
        except Exception:
            lines.append(f"- {key}:取樣查詢失敗")
            continue
        if not ids:
            lines.append(f"- {key}:沒有取到帶 request_id 的紀錄(該系統可能不記或查無資料)")
            continue
        sampled[key] = ids

    shared, unshared = [], []
    for src, ids in sampled.items():
        for dst, spec in systems.items():
            if dst == src:
                continue
            try:
                hit = len(_found_ids(elk, spec, ids, start, until))
            except Exception:
                lines.append(f"- {src} → {dst}:查詢失敗")
                continue
            (shared if hit else unshared).append(f"{src} → {dst}:{hit}/{len(ids)}")

    out = [f"request_id 稽核(取樣窗 {window_minutes} 分鐘,每系統最多 {samples} 個 id)"]
    out.append("有共用:" + (";".join(shared) if shared else "無"))
    out.append("沒有共用:" + (";".join(unshared) if unshared else "無"))
    if lines:
        out.append("其他:")
        out.extend(lines)
    return "\n".join(out)
