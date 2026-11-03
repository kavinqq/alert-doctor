from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable

from alert_doctor.models import ElkSpec, Evidence

TW = timezone(timedelta(hours=8))
FORWARD_SECONDS = 120
MESSAGE_LIMIT = 500
_PLACEHOLDER = re.compile(r"\{\{\s*(from|to|vars\.[^}\s]+)\s*\}\}")


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TW).isoformat(timespec="seconds")


def _substitute(node, values: dict[str, str]):
    if isinstance(node, str):
        def repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise KeyError(f"查詢模板用到未提供的變數 {key.removeprefix('vars.')}")
            return values[key]
        return _PLACEHOLDER.sub(repl, node)
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    return node


def _dig(src: dict, dotted: str):
    """Look up `a.b.c` as nested dicts, falling back to a flat `"a.b.c"` key."""
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(src: dict, *paths: str):
    for p in paths:
        v = _dig(src, p)
        if v is not None:
            return v
    return None


# Each system logs its host under a different field (FastPxy/Pxy `log.extra.server_ip`, SSO
# `log.host`); "auto" aggregates all of them and keeps whichever one the hits actually have.
AUTO_HOST_FIELDS = ("log.extra.server_ip", "log.host", "host.name")


def _host_fields(host_field: str) -> tuple[str, ...]:
    return AUTO_HOST_FIELDS if host_field == "auto" else (host_field,)


def host_aggs(host_field: str) -> dict:
    """Terms aggregations for `host_field` ("auto" = one per candidate field)."""
    if host_field != "auto":
        return {"hosts": {"terms": {"field": host_field, "size": 10}}}
    return {f"hosts_{i}": {"terms": {"field": f, "size": 10}} for i, f in enumerate(AUTO_HOST_FIELDS)}


def host_buckets(aggs: dict, host_field: str) -> dict:
    """Host -> doc count from the aggregations `host_aggs` asked for."""
    names = ["hosts"] if host_field != "auto" else [f"hosts_{i}" for i in range(len(AUTO_HOST_FIELDS))]
    best: dict = {}
    for name in names:
        found = {b["key"]: b["doc_count"] for b in (aggs.get(name) or {}).get("buckets", [])}
        if len(found) > len(best):
            best = found
    return best


def _sample(src: dict, host_field: str) -> dict:
    # log.message before top-level message: the latter has CJK unicode-escaped.
    # PE logs have no `.extra.`, hence the log.request_path fallbacks.
    fields = {
        "@timestamp": _first(src, "@timestamp"),
        "message": _first(src, "log.message", "message"),
        "request_id": _first(src, "log.extra.request_id", "log.request_id"),
        "request_path": _first(src, "log.extra.request_path", "log.request_path"),
        "response_status": _first(src, "log.extra.response_status", "log.response_status"),
        "host": _first(src, *_host_fields(host_field)),
    }
    if isinstance(fields["message"], str):
        fields["message"] = fields["message"][:MESSAGE_LIMIT]
    return {k: v for k, v in fields.items() if v is not None}


class ElkClient:
    def __init__(
        self,
        url: str,
        user: str,
        password_provider: Callable[[], str],
        timeout: int,
        opener=urllib.request.urlopen,
        *,
        clock: Callable[[], float] = time.time,
    ):
        self._url = url.rstrip("/")
        self._user = user
        self._password_provider = password_provider
        self._timeout = timeout
        self._opener = opener
        self._clock = clock
        self._auth: str | None = None

    def _auth_header(self) -> str:
        if self._auth is None:
            token = base64.b64encode(f"{self._user}:{self._password_provider()}".encode()).decode()
            self._auth = "Basic " + token
        return self._auth

    def search(self, index: str, body: dict) -> dict:
        """POST `/<index>/_search`. Raises on transport, HTTP or JSON errors."""
        req = urllib.request.Request(
            f"{self._url}/{urllib.parse.quote(index, safe=',*-_.')}/_search",
            data=json.dumps(body).encode(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", self._auth_header())
        with self._opener(req, timeout=self._timeout) as resp:
            return json.loads(resp.read())

    def gather(self, spec: ElkSpec, until: float, variables: dict) -> Evidence:
        """Collect evidence for `[until - lookback, until + 120s]`; never raises.

        Any failure, including a timed-out or partially failed search, yields
        `query_ok=False` so callers cannot mistake missing data for "recovered".
        """
        window_from = _iso(until - spec.lookback_minutes * 60)
        # Clamped to now: future minutes are always empty and would make every alert look recovered.
        window_to = _iso(min(until + FORWARD_SECONDS, self._clock()))
        try:
            values = {"from": window_from, "to": window_to}
            values.update({f"vars.{k}": str(v) for k, v in variables.items()})
            body = {
                "size": 5,
                "track_total_hits": True,
                "sort": [{"@timestamp": "desc"}],
                "query": _substitute(spec.query, values),
                "aggs": {
                    "h": {"date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1m",
                        "time_zone": "+08:00",
                        # Without these ES omits empty edge buckets, so the last bucket is never 0.
                        "min_doc_count": 0,
                        "extended_bounds": {"min": window_from, "max": window_to},
                    }},
                    **host_aggs(spec.host_field),
                },
            }
            resp = self.search(spec.index, body)
            if resp.get("timed_out") or (resp.get("_shards") or {}).get("failed"):
                raise RuntimeError("ES 查詢逾時或部分 shard 失敗,結果不完整")
            aggs = resp.get("aggregations") or {}
            return Evidence(
                query_ok=True,
                window_from=window_from,
                window_to=window_to,
                total=((resp.get("hits") or {}).get("total") or {}).get("value", 0),
                per_host=host_buckets(aggs, spec.host_field),
                histogram=tuple(
                    (b["key_as_string"], b["doc_count"]) for b in (aggs.get("h") or {}).get("buckets", [])
                ),
                samples=tuple(
                    _sample(h.get("_source") or {}, spec.host_field)
                    for h in (resp.get("hits") or {}).get("hits", [])
                ),
            )
        except Exception as e:
            return Evidence(
                query_ok=False,
                window_from=window_from,
                window_to=window_to,
                error=f"{type(e).__name__}: {e}"[:300],
            )
