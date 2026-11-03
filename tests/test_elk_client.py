import io
import json
import socket
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone

from alert_doctor.elk_client import ElkClient
from alert_doctor.models import ElkSpec

TW = timezone(timedelta(hours=8))
UNTIL = datetime(2026, 10, 19, 9, 30, 0, tzinfo=TW).timestamp()


class FakeResponse:
    def __init__(self, payload):
        self._raw = json.dumps(payload).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, payload=None, error=None):
        self.payload, self.error = payload, error
        self.requests, self.timeouts = [], []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        self.timeouts.append(timeout)
        if self.error:
            raise self.error
        return FakeResponse(self.payload)

    @property
    def body(self):
        return json.loads(self.requests[-1].data)


def es_response(**overrides):
    base = {
        "timed_out": False,
        "_shards": {"total": 1, "failed": 0},
        "hits": {
            "total": {"value": 7, "relation": "eq"},
            "hits": [
                {"_source": {
                    "@timestamp": "2026-10-19T01:29:00.000Z",
                    "message": "\\u9023\\u7dda\\u903e\\u6642",
                    "log": {
                        "message": "連線逾時 " + "x" * 600,
                        "extra": {"request_id": "r-1", "request_path": "/a", "response_status": 502,
                                  "server_ip": "10.0.0.1"},
                    },
                }},
                {"_source": {"@timestamp": "2026-10-19T01:28:00.000Z"}},
            ],
        },
        "aggregations": {
            "h": {"buckets": [
                {"key_as_string": "2026-10-19T09:28:00.000+08:00", "doc_count": 3},
                {"key_as_string": "2026-10-19T09:29:00.000+08:00", "doc_count": 0},
            ]},
            "hosts": {"buckets": [{"key": "10.0.0.1", "doc_count": 5}, {"key": "10.0.0.2", "doc_count": 2}]},
        },
    }
    base.update(overrides)
    return base


def spec(**kw):
    query = kw.pop("query", {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": "{{from}}", "lte": "{{to}}"}}},
        {"term": {"log.extra.request_path": "{{vars.path}}"}},
    ]}})
    return ElkSpec(index="logs-generic-default", query=query, **kw)


def client(opener, password=lambda: "pw", now=UNTIL + 3600):
    return ElkClient("http://elk:9200/", "elastic", password, 10, opener=opener, clock=lambda: now)


class SearchTest(unittest.TestCase):
    def test_posts_to_index_with_basic_auth_and_timeout(self):
        op = FakeOpener({"ok": 1})
        out = client(op).search("logs-generic-default", {"size": 0})
        self.assertEqual(out, {"ok": 1})
        req = op.requests[0]
        self.assertEqual(req.full_url, "http://elk:9200/logs-generic-default/_search")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.get_header("Authorization"), "Basic ZWxhc3RpYzpwdw==")
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(op.timeouts[0], 10)
        self.assertEqual(op.body, {"size": 0})

    def test_password_fetched_lazily_once(self):
        calls = []
        op = FakeOpener({})
        c = client(op, lambda: calls.append(1) or "pw")
        self.assertEqual(calls, [])
        c.search("i", {})
        c.search("i", {})
        self.assertEqual(len(calls), 1)


class GatherTest(unittest.TestCase):
    def gather(self, s=None, **kw):
        op = FakeOpener(kw.pop("payload", es_response()), kw.pop("error", None))
        ev = client(op).gather(s or spec(), UNTIL, kw.pop("variables", {"path": "/a"}))
        return ev, op

    def test_window_and_substitution(self):
        ev, op = self.gather()
        rng = op.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "2026-10-19T09:15:00+08:00")
        self.assertEqual(rng["lte"], "2026-10-19T09:32:00+08:00")
        self.assertEqual(op.body["query"]["bool"]["filter"][1]["term"]["log.extra.request_path"], "/a")
        self.assertEqual((ev.window_from, ev.window_to), ("2026-10-19T09:15:00+08:00", "2026-10-19T09:32:00+08:00"))

    def test_window_to_clamped_to_clock(self):
        op = FakeOpener(es_response())
        ev = client(op, now=UNTIL + 30).gather(spec(), UNTIL, {"path": "/a"})
        self.assertEqual(ev.window_to, "2026-10-19T09:30:30+08:00")
        rng = op.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(rng["lte"], "2026-10-19T09:30:30+08:00")
        bounds = op.body["aggs"]["h"]["date_histogram"]["extended_bounds"]
        self.assertEqual(bounds["max"], "2026-10-19T09:30:30+08:00")

    def test_lookback_minutes_respected(self):
        _, op = self.gather(spec(lookback_minutes=60))
        rng = op.body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "2026-10-19T08:30:00+08:00")

    def test_body_shape(self):
        _, op = self.gather(spec(host_field="log.host"))
        b = op.body
        self.assertEqual(b["size"], 5)
        self.assertTrue(b["track_total_hits"])
        self.assertEqual(b["sort"], [{"@timestamp": "desc"}])
        self.assertEqual(b["aggs"]["h"], {"date_histogram": {
            "field": "@timestamp", "fixed_interval": "1m", "time_zone": "+08:00", "min_doc_count": 0,
            "extended_bounds": {"min": "2026-10-19T09:15:00+08:00", "max": "2026-10-19T09:32:00+08:00"}}})
        self.assertEqual(b["aggs"]["hosts"], {"terms": {"field": "log.host", "size": 10}})
        self.assertEqual(op.requests[0].full_url, "http://elk:9200/logs-generic-default/_search")

    def test_substitution_is_recursive_over_lists_and_embedded(self):
        s = spec(query={"bool": {"must": [{"match": {"m": "id={{vars.id}} at {{from}}"}}], "n": 3}})
        _, op = self.gather(s, variables={"id": 12})
        self.assertEqual(op.body["query"]["bool"]["must"][0]["match"]["m"], "id=12 at 2026-10-19T09:15:00+08:00")
        self.assertEqual(op.body["query"]["bool"]["n"], 3)

    def test_spec_query_not_mutated(self):
        s = spec()
        self.gather(s)
        self.assertEqual(s.query["bool"]["filter"][1]["term"]["log.extra.request_path"], "{{vars.path}}")

    def test_evidence_fields(self):
        ev, _ = self.gather()
        self.assertTrue(ev.query_ok)
        self.assertEqual(ev.total, 7)
        self.assertEqual(ev.per_host, {"10.0.0.1": 5, "10.0.0.2": 2})
        self.assertEqual(ev.histogram, (("2026-10-19T09:28:00.000+08:00", 3), ("2026-10-19T09:29:00.000+08:00", 0)))
        self.assertIsNone(ev.error)

    def test_samples_trimmed_and_tolerate_missing_fields(self):
        ev, _ = self.gather()
        first, second = ev.samples
        self.assertEqual(first["@timestamp"], "2026-10-19T01:29:00.000Z")
        self.assertEqual(len(first["message"]), 500)
        self.assertTrue(first["message"].startswith("連線逾時"))
        self.assertEqual(first["request_id"], "r-1")
        self.assertEqual(first["request_path"], "/a")
        self.assertEqual(first["response_status"], 502)
        self.assertEqual(first["host"], "10.0.0.1")
        self.assertEqual(second, {"@timestamp": "2026-10-19T01:28:00.000Z"})

    def test_sample_falls_back_to_top_level_message_and_log_request_path(self):
        payload = es_response()
        payload["hits"]["hits"] = [{"_source": {
            "@timestamp": "t", "message": "top", "log": {"request_path": "/pe", "response_status": 500}}}]
        ev, _ = self.gather(payload=payload)
        self.assertEqual(ev.samples[0], {"@timestamp": "t", "message": "top",
                                         "request_path": "/pe", "response_status": 500})

    def test_sample_reads_host_field_when_source_is_flat(self):
        payload = es_response()
        payload["hits"]["hits"] = [{"_source": {"@timestamp": "t", "log.host": "h1"}}]
        ev, _ = self.gather(spec(host_field="log.host"), payload=payload)
        self.assertEqual(ev.samples[0]["host"], "h1")

    def test_missing_aggregations_and_total(self):
        ev, _ = self.gather(payload={"hits": {"hits": []}})
        self.assertTrue(ev.query_ok)
        self.assertEqual((ev.total, ev.per_host, ev.histogram, ev.samples), (0, {}, (), ()))

    def test_http_error_becomes_query_ok_false(self):
        err = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b"bad creds"))
        ev, _ = self.gather(error=err)
        self.assertFalse(ev.query_ok)
        self.assertIn("401", ev.error)
        self.assertIsNone(ev.total)
        self.assertEqual(ev.window_from, "2026-10-19T09:15:00+08:00")

    def test_timeout_becomes_query_ok_false(self):
        ev, _ = self.gather(error=socket.timeout("timed out"))
        self.assertFalse(ev.query_ok)
        self.assertIn("timed out", ev.error)

    def test_url_error_becomes_query_ok_false(self):
        ev, _ = self.gather(error=urllib.error.URLError("refused"))
        self.assertFalse(ev.query_ok)

    def test_partial_results_are_not_trusted(self):
        ev, _ = self.gather(payload=es_response(timed_out=True))
        self.assertFalse(ev.query_ok)
        ev, _ = self.gather(payload=es_response(_shards={"total": 2, "failed": 1}))
        self.assertFalse(ev.query_ok)

    def test_missing_variable_becomes_query_ok_false(self):
        ev, op = self.gather(variables={})
        self.assertFalse(ev.query_ok)
        self.assertIn("path", ev.error)
        self.assertEqual(op.requests, [])

    def test_password_provider_failure_does_not_raise(self):
        def boom():
            raise RuntimeError("no keychain")
        c = client(FakeOpener(es_response()), boom)
        ev = c.gather(spec(), UNTIL, {"path": "/a"})
        self.assertFalse(ev.query_ok)
        self.assertIn("no keychain", ev.error)

    def test_non_json_response_does_not_raise(self):
        class Bad(FakeOpener):
            def __call__(self, req, timeout=None):
                return type("R", (FakeResponse,), {"read": lambda s: b"<html>"})({})
        ev = client(Bad()).gather(spec(), UNTIL, {"path": "/a"})
        self.assertFalse(ev.query_ok)


if __name__ == "__main__":
    unittest.main()
