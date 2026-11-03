from __future__ import annotations

import json
import tomllib

from alert_doctor.models import CheckSpec, ElkSpec, ParsedAlert


def load_checks(path: str) -> dict[str, CheckSpec]:
    """Parse `[checks."<code or title>"]` tables; `elk.query` is a JSON string decoded here."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    checks = {}
    for key, raw in data.get("checks", {}).items():
        elk_raw = raw.get("elk")
        elk = None
        if elk_raw:
            total_query = elk_raw.get("total_query")
            elk = ElkSpec(
                index=elk_raw["index"],
                query=json.loads(elk_raw["query"]),
                total_query=json.loads(total_query) if total_query else None,
                **{k: elk_raw[k] for k in ("host_field", "lookback_minutes") if k in elk_raw},
            )
        checks[key] = CheckSpec(
            key=key,
            system=raw.get("system", ""),
            never_silence=raw.get("never_silence", False),
            owners=tuple(raw.get("owners", ())),
            repo=raw.get("repo"),
            deploy_ref=raw.get("deploy_ref", "origin/HEAD"),
            elk=elk,
            **{k: raw[k] for k in ("signal", "min_errors") if k in raw},
        )
    return checks


def lookup_check(checks: dict[str, CheckSpec], alert: ParsedAlert) -> CheckSpec | None:
    if alert.check_code and alert.check_code in checks:
        return checks[alert.check_code]
    return checks.get(alert.check_title)
