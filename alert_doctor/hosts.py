"""Which server an alert happened on, taken from text we already have (no extra queries).

Keyword-check alerts quote one log record; its `server_hostname` / `server_ip` / `host`
names the server. `remote_address` is deliberately ignored: it is the client.
"""
from __future__ import annotations

import re

MAX_LISTED = 3
# The quoted record sits inside the alert's message string, so its quotes usually arrive
# backslash-escaped (\'server_hostname\': \'prod-app-pxy-tc-101\').
_Q = r"""\\?['"]"""
_HOST_FIELD = re.compile(
    _Q + r"(?:server_hostname|server_ip|host|hostname)" + _Q + r"\s*:\s*" + _Q
    + r"([A-Za-z0-9][\w.\-]{2,}?)" + _Q)


def hosts_in_text(text: str) -> list[str]:
    """Distinct server names/IPs quoted in `text`, in order of appearance."""
    return list(dict.fromkeys(_HOST_FIELD.findall(text or "")))


def count_hosts(texts) -> dict[str, int]:
    """Occurrences per host over alert texts; each text counts once per host it names."""
    counts: dict[str, int] = {}
    for text in texts:
        for host in hosts_in_text(text):
            counts[host] = counts.get(host, 0) + 1
    return counts


def format_hosts(counts: dict[str, int]) -> str:
    """`b ×3、c ×2、a ×1 等 4 台` — busiest first, at most MAX_LISTED named."""
    if not counts:
        return ""
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    text = "、".join(f"{host} ×{n}" for host, n in ranked[:MAX_LISTED])
    if len(ranked) > MAX_LISTED:
        text += f" 等 {len(ranked)} 台"
    return text
