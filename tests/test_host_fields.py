import unittest

from alert_doctor import elk_client
from alert_doctor.elk_client import AUTO_HOST_FIELDS, host_aggs, host_buckets
from alert_doctor.models import CheckSpec, ElkSpec
from alert_doctor.publisher import report_changes
from alert_doctor.signals import gather_signal


def resp_with(field_buckets: dict, total=3, source=None):
    aggs = {"h": {"buckets": [{"key_as_string": "t", "doc_count": total}]}}
    for i, field in enumerate(AUTO_HOST_FIELDS):
        keys = field_buckets.get(field, [])
        aggs[f"hosts_{i}"] = {"buckets": [{"key": k, "doc_count": 1} for k in keys]}
    hits = [{"_source": source}] if source else []
    return {"hits": {"total": {"value": total}, "hits": hits}, "aggregations": aggs}


class FakeElk:
    def __init__(self, resp):
        self.resp, self.bodies = resp, []

    def search(self, index, body):
        self.bodies.append(body)
        return self.resp


class AutoHostFieldTest(unittest.TestCase):
    def test_auto_aggregates_every_candidate_field(self):
        self.assertEqual(sorted(host_aggs("auto")), [f"hosts_{i}" for i in range(len(AUTO_HOST_FIELDS))])
        self.assertEqual(host_aggs("log.host"), {"hosts": {"terms": {"field": "log.host", "size": 10}}})

    def test_auto_picks_the_field_that_has_hosts(self):
        aggs = resp_with({"log.host": ["prod-app-pxy-tc-101", "prod-app-sb-193"]})["aggregations"]
        self.assertEqual(host_buckets(aggs, "auto"), {"prod-app-pxy-tc-101": 1, "prod-app-sb-193": 1})

    def test_signal_counts_hosts_from_sso_style_logs(self):
        elk = FakeElk(resp_with({"log.host": ["a", "b"]}))
        check = CheckSpec(key="k", elk=ElkSpec(index="log*", query={"match_all": {}}, host_field="auto"))
        self.assertEqual(gather_signal(elk, check, 1792437480.0).hosts, 2)

    def test_gather_evidence_hosts_and_sample_host_with_auto(self):
        resp = resp_with({"log.host": ["prod-app-pxy-tc-101"]},
                         source={"@timestamp": "t", "log": {"host": "prod-app-pxy-tc-101", "message": "M999"}})
        client = elk_client.ElkClient("http://x", "u", lambda: "p", 5, clock=lambda: 1792437600.0)
        client.search = FakeElk(resp).search
        ev = client.gather(ElkSpec(index="log*", query={"match_all": {}}, host_field="auto"), 1792437480.0, {})
        self.assertTrue(ev.query_ok)
        self.assertEqual(ev.per_host, {"prod-app-pxy-tc-101": 1})
        self.assertEqual(ev.samples[0]["host"], "prod-app-pxy-tc-101")


class DoublingThresholdTest(unittest.TestCase):
    def test_small_counts_do_not_count_as_doubling(self):
        self.assertEqual(report_changes({"last_count": 1}, total=2, hosts=None, severity=None), [])
        self.assertEqual(report_changes({"last_count": 4}, total=9, hosts=None, severity=None), [])

    def test_doubling_counts_once_volume_is_meaningful(self):
        self.assertEqual(report_changes({"last_count": 5}, total=10, hosts=None, severity=None), ["量級翻倍"])


if __name__ == "__main__":
    unittest.main()
