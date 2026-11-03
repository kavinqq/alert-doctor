import unittest

from alert_doctor.config import SystemSpec
from alert_doctor.correlate import Candidate, audit_request_ids, co_erroring

UNTIL = 1_800_000_000.0
DAY = 86400


def spec(key):
    return SystemSpec(key, (), (), key, {"term": {"project": key}})


def project_of(body):
    return body["query"]["bool"]["filter"][0]["term"]["project"]


def gte_of(body):
    flt = body["query"]["bool"]["filter"][1]["range"]["@timestamp"]
    return flt["gte"]


class FakeElk:
    def __init__(self, counts, fail=()):
        self.counts = counts
        self.fail = set(fail)
        self.calls = []

    def search(self, index, body):
        self.calls.append(body)
        project = project_of(body)
        if project in self.fail:
            raise OSError("boom")
        is_before = gte_of(body) < (UNTIL - DAY) * 1000 + 1
        now, before = self.counts[project]
        return {"hits": {"total": {"value": before if is_before else now}}}


class CoErroringTest(unittest.TestCase):
    def systems(self, *keys):
        return {k: spec(k) for k in keys}

    def test_filters_and_sorts_by_ratio(self):
        elk = FakeElk({"a": (50, 4), "b": (10, 0), "c": (4, 0), "d": (100, 90), "e": (30, 2)})
        got = co_erroring(elk, self.systems("a", "b", "c", "d", "e"), UNTIL)
        self.assertEqual([c.system for c in got], ["b", "e", "a"])
        self.assertEqual(got[0], Candidate("b", 10, 0, 11.0))
        self.assertAlmostEqual(got[2].ratio, 51 / 5)

    def test_system_without_elk_project_is_skipped(self):
        elk = FakeElk({"a": (50, 0)})
        systems = {"a": spec("a"), "oa": SystemSpec("oa", (), (), "", {"term": {"project": ""}})}
        got = co_erroring(elk, systems, UNTIL)
        self.assertEqual([c.system for c in got], ["a"])
        self.assertNotIn("", [project_of(b) for b in elk.calls])

    def test_exclude_source_system(self):
        elk = FakeElk({"a": (50, 0), "b": (50, 0)})
        got = co_erroring(elk, self.systems("a", "b"), UNTIL, exclude="a")
        self.assertEqual([c.system for c in got], ["b"])

    def test_failed_system_skipped(self):
        elk = FakeElk({"a": (50, 0), "b": (50, 0)}, fail={"a"})
        got = co_erroring(elk, self.systems("a", "b"), UNTIL)
        self.assertEqual([c.system for c in got], ["b"])

    def test_window_and_previous_day(self):
        elk = FakeElk({"a": (50, 0)})
        co_erroring(elk, self.systems("a"), UNTIL, window_minutes=10)
        gtes = sorted(gte_of(b) for b in elk.calls)
        self.assertEqual(gtes, [(UNTIL - DAY - 600) * 1000, (UNTIL - 600) * 1000])
        self.assertTrue(all(b["size"] == 0 and b["track_total_hits"] for b in elk.calls))

    def test_uses_system_error_query(self):
        elk = FakeElk({"a": (0, 0)})
        co_erroring(elk, self.systems("a"), UNTIL)
        self.assertEqual(elk.calls[0]["query"]["bool"]["filter"][0], {"term": {"project": "a"}})


class AuditElk:
    """ids_by_project: project -> ids it has; every project is searchable for any id it holds."""

    def __init__(self, ids_by_project, fail=()):
        self.ids = ids_by_project
        self.fail = set(fail)

    def search(self, index, body):
        flt = body["query"]["bool"]["filter"]
        project = flt[0]["term"]["project"]
        if project in self.fail:
            raise OSError("boom")
        wanted = None
        for clause in body["query"]["bool"].get("should", []):
            if "terms" in clause:
                wanted = set(next(iter(clause["terms"].values())))
        pool = self.ids[project]
        hits = [{"_source": {"log": {"extra": {"request_id": i}}}}
                for i in pool if wanted is None or i in wanted]
        return {"hits": {"hits": hits}}


class AuditTest(unittest.TestCase):
    def test_report_shows_shared_and_unshared(self):
        elk = AuditElk({"pxy": ["r1", "r2"], "sso": ["r1", "x"], "cms": ["y"]})
        systems = {k: spec(k) for k in ("pxy", "sso", "cms")}
        report = audit_request_ids(elk, systems, UNTIL)
        self.assertIn("pxy → sso:1/2", report)
        self.assertIn("pxy → cms:0/2", report)
        self.assertIn("有共用", report)
        self.assertIn("沒有共用", report)

    def test_system_without_request_ids_reported(self):
        elk = AuditElk({"pxy": [], "sso": ["r1"]})
        systems = {k: spec(k) for k in ("pxy", "sso")}
        report = audit_request_ids(elk, systems, UNTIL)
        self.assertIn("pxy", report)
        self.assertIn("沒有取到帶 request_id 的紀錄", report)

    def test_failed_query_reported_not_raised(self):
        elk = AuditElk({"pxy": ["r1"], "sso": ["r1"]}, fail={"sso"})
        systems = {k: spec(k) for k in ("pxy", "sso")}
        report = audit_request_ids(elk, systems, UNTIL)
        self.assertIn("查詢失敗", report)


if __name__ == "__main__":
    unittest.main()
