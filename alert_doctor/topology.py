from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROMPT_HOPS = 2
_FIELDS = ("from", "to", "via", "purpose", "source", "verified")


@dataclass(frozen=True)
class Edge:
    from_: str
    to: str
    via: str
    purpose: str
    source: str
    verified: str


@dataclass(frozen=True)
class Topology:
    version: int = 0
    updated: str = ""
    edges: list[Edge] = field(default_factory=list)

    def neighbors(self, system: str) -> list[Edge]:
        """Edges touching `system`, upstream and downstream alike."""
        return [e for e in self.edges if system in (e.from_, e.to)]

    def render_for_prompt(self, start_systems) -> str:
        """Edges within 2 hops of the start systems, as 繁中 lines; "" when there are none."""
        seen_nodes = set(start_systems)
        frontier = set(start_systems)
        picked: list[Edge] = []
        for _ in range(PROMPT_HOPS):
            next_frontier: set[str] = set()
            for node in sorted(frontier):
                for edge in self.neighbors(node):
                    if edge not in picked:
                        picked.append(edge)
                    for other in (edge.from_, edge.to):
                        if other not in seen_nodes:
                            seen_nodes.add(other)
                            next_frontier.add(other)
            frontier = next_frontier
        if not picked:
            return ""
        lines = [f"- {e.from_} → {e.to}({e.via};{e.purpose})〔{_trust(e)}〕" for e in picked]
        return "\n".join(lines)


def _trust(edge: Edge) -> str:
    if edge.verified:
        return f"已核對 {edge.verified},出處 {edge.source}"
    return f"待確認,{edge.source}" if edge.source != "待確認" else "待確認"


def load_topology(path: str) -> Topology:
    """Load a topology TOML; a missing file yields an empty Topology.

    Raises ValueError when an edge lacks one of from/to/via/purpose/source/verified.
    """
    file = Path(path)
    if not file.exists():
        return Topology()
    with open(file, "rb") as f:
        raw = tomllib.load(f)
    meta = raw.get("meta", {})
    edges = []
    for i, item in enumerate(raw.get("edges", ()), 1):
        missing = [k for k in _FIELDS if k not in item]
        if missing:
            raise ValueError(f"[[edges]] 第 {i} 條缺少欄位:{', '.join(missing)}")
        edges.append(Edge(item["from"], item["to"], item["via"], item["purpose"],
                          item["source"], item["verified"]))
    return Topology(int(meta.get("version", 0)), str(meta.get("updated", "")), edges)
