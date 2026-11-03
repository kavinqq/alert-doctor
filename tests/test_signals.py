import unittest

from alert_doctor.models import CheckSpec, ElkSpec
from alert_doctor.signals import Signal, gather_signal

QUERY = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "{{from}}", "lte": "{{to}}"}}},
                             {"term": {"x": "{{vars.nope}}"}}]}}
PLAIN = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "{{from}}", "lte": "{{to}}"}}}]}}
UNTIL = 1760000000.0


def resp(total, counts, hosts=()):
    return {
        "timed_out": False,
        "_shards": {"failed": 0},
        "hits": {"total": {"value": total}},
        "aggregations": {
            "h": {"buckets": [{"key_as_string": f"t{i}", "doc_count": c} for i, c in enumerate(counts)]},
            "hosts": {"buckets": [{"key": h, "doc_count": 1} for h in hosts]},
        },
    }


class FakeElk:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def search(self, index, body):
        self.calls.append((index, body))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def check(query=PLAIN, **kw):
    total_query = kw.pop("total_query", None)
    return CheckSpec(key="k", elk=ElkSpec(index="logs-generic-default", query=query, total_query=total_query), **kw)


class SignalTest(unittest.TestCase):
    def test_longest_consecutive_nonzero_run(self):
        elk = FakeElk(resp(9, [1, 0, 2, 3, 1, 0, 1], ["a", "b"]))
        s = gather_signal(elk, check(), UNTIL)
        self.assertTrue(s.ok)
        self.assertEqual((s.errors, s.duration_minutes, s.hosts), (9, 3, 2))
        self.assertIsNone(s.total)
        self.assertIsNone(s.rate)

    def test_all_zero_histogram(self):
        s = gather_signal(FakeElk(resp(0, [0, 0])), check(), UNTIL)
        self.assertEqual((s.errors, s.duration_minutes, s.hosts), (0, 0, 0))

    def test_request_body(self):
        elk = FakeElk(resp(1, [1]))
        gather_signal(elk, check(), UNTIL, window_minutes=30)
        index, body = elk.calls[0]
        self.assertEqual(index, "logs-generic-default")
        self.assertEqual(body["size"], 0)
        self.assertTrue(body["track_total_hits"])
        rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(rng, {"gte": "2025-10-09T16:23:20+08:00", "lte": "2025-10-09T16:53:20+08:00"})
        h = body["aggs"]["h"]["date_histogram"]
        self.assertEqual(h["fixed_interval"], "1m")
        self.assertEqual(h["min_doc_count"], 0)
        self.assertEqual(h["extended_bounds"], {"min": rng["gte"], "max": rng["lte"]})
        self.assertEqual(body["aggs"]["hosts"]["terms"]["field"], "log.extra.server_ip")

    def test_rate_uses_total_query(self):
        elk = FakeElk(resp(10, [10]), resp(200, [200]))
        s = gather_signal(elk, check(signal="rate", total_query=PLAIN), UNTIL)
        self.assertEqual((s.errors, s.total, s.rate), (10, 200, 0.05))
        self.assertEqual(len(elk.calls), 2)

    def test_rate_zero_total_gives_none_rate(self):
        elk = FakeElk(resp(0, [0]), resp(0, [0]))
        s = gather_signal(elk, check(signal="rate", total_query=PLAIN), UNTIL)
        self.assertTrue(s.ok)
        self.assertEqual(s.total, 0)
        self.assertIsNone(s.rate)

    def test_count_signal_skips_total_query(self):
        elk = FakeElk(resp(10, [10]))
        s = gather_signal(elk, check(total_query=PLAIN), UNTIL)
        self.assertEqual(len(elk.calls), 1)
        self.assertIsNone(s.total)

    def test_rate_without_total_query(self):
        s = gather_signal(FakeElk(resp(3, [3])), check(signal="rate"), UNTIL)
        self.assertTrue(s.ok)
        self.assertIsNone(s.rate)

    def test_exception_gives_not_ok(self):
        s = gather_signal(FakeElk(OSError("boom")), check(), UNTIL)
        self.assertFalse(s.ok)
        self.assertIn("boom", s.error)
        self.assertIsNone(s.errors)

    def test_missing_template_var_gives_not_ok(self):
        s = gather_signal(FakeElk(), check(query=QUERY), UNTIL)
        self.assertFalse(s.ok)

    def test_vars_substituted_in_query_and_total_query(self):
        elk = FakeElk(resp(2, [2]), resp(40, [40]))
        q = {"bool": {"filter": [{"term": {"x": "{{vars.nope}}"}}]}}
        s = gather_signal(elk, check(query=q, signal="rate", total_query=q), UNTIL, variables={"nope": 7})
        self.assertTrue(s.ok)
        self.assertEqual(elk.calls[0][1]["query"]["bool"]["filter"][0]["term"]["x"], "7")
        self.assertEqual(elk.calls[1][1]["query"]["bool"]["filter"][0]["term"]["x"], "7")

    def test_partial_failure_gives_not_ok(self):
        bad = resp(5, [5])
        bad["_shards"]["failed"] = 1
        self.assertFalse(gather_signal(FakeElk(bad), check(), UNTIL).ok)

    def test_no_elk_spec_gives_not_ok(self):
        s = gather_signal(FakeElk(), CheckSpec(key="k"), UNTIL)
        self.assertFalse(s.ok)

    def test_to_dict(self):
        s = Signal(ok=True, errors=1, total=None, rate=None, duration_minutes=2, hosts=1)
        self.assertEqual(s.to_dict(), {
            "ok": True, "errors": 1, "total": None, "rate": None,
            "duration_minutes": 2, "hosts": 1, "error": None,
        })


if __name__ == "__main__":
    unittest.main()
