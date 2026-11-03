import os
import tempfile
import unittest

from alert_doctor.topology import Edge, Topology, load_topology

TOML = """
[meta]
version = 3
updated = "2026-10-20"

[[edges]]
from = "pxy"
to = "sso"
via = "HTTP verify_token"
purpose = "驗證 token"
source = "a.md:1"
verified = "2026-10-20"

[[edges]]
from = "sso"
to = "redis"
via = "django_redis"
purpose = "快取"
source = "待確認"
verified = ""

[[edges]]
from = "redis"
to = "far"
via = "x"
purpose = "三跳外"
source = "待確認"
verified = ""

[[edges]]
from = "far"
to = "farther"
via = "x"
purpose = "四跳外"
source = "待確認"
verified = ""
"""


def write(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


class TopologyTest(unittest.TestCase):
    def setUp(self):
        self.path = write(TOML)
        self.addCleanup(os.unlink, self.path)
        self.topo = load_topology(self.path)

    def test_load_meta_and_edges(self):
        self.assertEqual(self.topo.version, 3)
        self.assertEqual(self.topo.updated, "2026-10-20")
        self.assertEqual(len(self.topo.edges), 4)
        self.assertEqual(self.topo.edges[0], Edge(
            "pxy", "sso", "HTTP verify_token", "驗證 token", "a.md:1", "2026-10-20"))

    def test_neighbors_include_upstream_and_downstream(self):
        got = {(e.from_, e.to) for e in self.topo.neighbors("sso")}
        self.assertEqual(got, {("pxy", "sso"), ("sso", "redis")})

    def test_neighbors_unknown_system(self):
        self.assertEqual(self.topo.neighbors("nope"), [])

    def test_render_two_hops_only(self):
        text = self.topo.render_for_prompt(["pxy"])
        self.assertIn("pxy", text)
        self.assertIn("redis", text)
        self.assertNotIn("far", text)

    def test_render_marks_unverified(self):
        text = self.topo.render_for_prompt(["sso"])
        self.assertIn("待確認", text)
        self.assertIn("已核對 2026-10-20", text)

    def test_render_empty_when_no_edges_near_start(self):
        self.assertEqual(self.topo.render_for_prompt(["nope"]), "")

    def test_missing_file_gives_empty_topology(self):
        topo = load_topology("/nonexistent/topology.toml")
        self.assertEqual(topo.edges, [])
        self.assertEqual(topo.render_for_prompt(["pxy"]), "")

    def test_edge_missing_field_raises(self):
        path = write('[[edges]]\nfrom = "a"\n')
        self.addCleanup(os.unlink, path)
        with self.assertRaises(ValueError):
            load_topology(path)

    def test_example_file_loads_and_covers_config_systems(self):
        example = os.path.join(os.path.dirname(__file__), "..", "topology.example.toml")
        topo = load_topology(example)
        nodes = {n for e in topo.edges for n in (e.from_, e.to)}
        from alert_doctor.config import load_config
        config = load_config(os.path.join(os.path.dirname(__file__), "..", "config.example.toml"))
        for key in config.systems:
            self.assertIn(key, nodes)
        for e in topo.edges:
            self.assertTrue(e.source, e)
            if not e.verified:
                self.assertTrue(e.source.startswith("待確認"), e)


if __name__ == "__main__":
    unittest.main()
