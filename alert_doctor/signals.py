from __future__ import annotations

from dataclasses import asdict, dataclass

from alert_doctor.elk_client import _iso, _substitute, host_aggs, host_buckets
from alert_doctor.models import CheckSpec


@dataclass(frozen=True)
class Signal:
    ok: bool
    errors: int | None
    total: int | None
    rate: float | None
    duration_minutes: int
    hosts: int
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _longest_nonzero_run(counts) -> int:
    best = run = 0
    for c in counts:
        run = run + 1 if c else 0
        best = max(best, run)
    return best


def _search(elk, index: str, query: dict, host_field: str, values: dict[str, str]) -> dict:
    window_from, window_to = values["from"], values["to"]
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": _substitute(query, values),
        "aggs": {
            "h": {"date_histogram": {
                "field": "@timestamp",
                "fixed_interval": "1m",
                "time_zone": "+08:00",
                "min_doc_count": 0,
                "extended_bounds": {"min": window_from, "max": window_to},
            }},
            **host_aggs(host_field),
        },
    }
    resp = elk.search(index, body)
    if resp.get("timed_out") or (resp.get("_shards") or {}).get("failed"):
        raise RuntimeError("ES 查詢逾時或部分 shard 失敗,結果不完整")
    return resp


def gather_signal(elk, check: CheckSpec, until: float, window_minutes: int = 60,
                  variables: dict | None = None) -> Signal:
    """Error magnitude over `[until - window, until]`; never raises (failure -> `ok=False`).

    `variables` fill `{{vars.X}}` placeholders exactly like `ElkClient.gather`.
    """
    try:
        spec = check.elk
        if spec is None:
            raise ValueError("check 沒有 elk 設定")
        window_from = _iso(until - window_minutes * 60)
        window_to = _iso(until)
        values = {"from": window_from, "to": window_to}
        values.update({f"vars.{k}": str(v) for k, v in (variables or {}).items()})
        resp = _search(elk, spec.index, spec.query, spec.host_field, values)
        aggs = resp.get("aggregations") or {}
        errors = ((resp.get("hits") or {}).get("total") or {}).get("value", 0)
        buckets = (aggs.get("h") or {}).get("buckets", [])
        total = rate = None
        if check.signal == "rate" and spec.total_query is not None:
            denom = _search(elk, spec.index, spec.total_query, spec.host_field, values)
            total = ((denom.get("hits") or {}).get("total") or {}).get("value", 0)
            rate = errors / total if total else None
        return Signal(
            ok=True,
            errors=errors,
            total=total,
            rate=rate,
            duration_minutes=_longest_nonzero_run(b["doc_count"] for b in buckets),
            hosts=len(host_buckets(aggs, spec.host_field)),
        )
    except Exception as e:
        return Signal(
            ok=False, errors=None, total=None, rate=None, duration_minutes=0, hosts=0,
            error=f"{type(e).__name__}: {e}"[:300],
        )
