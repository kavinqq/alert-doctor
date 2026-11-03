import json
import unittest
from types import SimpleNamespace

from alert_doctor import tuner
from alert_doctor.store import Store

HOUR = 3600
DAY = 86400
# 2026-01-05 00:00 UTC is Monday 08:00 at +08:00
BASE = 1767571200


def sig(errors=100, ok=True, duration=10, hosts=1, total=None, rate=None):
    return SimpleNamespace(ok=ok, errors=errors, total=total, rate=rate,
                           duration_minutes=duration, hosts=hosts, error=None)


class TunerBase(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        tuner.ensure_schema(self.s)

    def incident(self, fp, first, last, verdict=None):
        with self.s.tx() as db:
            return db.execute(
                "INSERT INTO incidents (fingerprint, group_fp, check_title, channel, anchor_ts,"
                " first_epoch, last_epoch, count, analysis_state, verdict) VALUES"
                " (?,?,?,?,?,?,?,?,?,?)",
                (fp, "g", "t", "C1", str(first), first, last, 1,
                 "done" if verdict else "none", json.dumps(verdict) if verdict else None)
            ).lastrowid

    def seed(self, fp, errors_by_day, hour_offset=0):
        for day, errors in enumerate(errors_by_day):
            tuner.record_observation(self.s, fp, BASE + day * DAY + hour_offset, errors)


class ObservationTests(TunerBase):
    def test_schema_idempotent(self):
        tuner.ensure_schema(self.s)

    def test_alerts_increment_errors_take_max(self):
        for e in (3, 9, 4):
            tuner.record_observation(self.s, "fp", BASE + 10, e)
        row = self.s.read("SELECT alerts, errors, healthy FROM fp_hourly")[0]
        self.assertEqual(row, (3, 9, 1))

    def test_none_errors_do_not_clobber(self):
        tuner.record_observation(self.s, "fp", BASE, 7)
        tuner.record_observation(self.s, "fp", BASE, None)
        self.assertEqual(self.s.read("SELECT alerts, errors FROM fp_hourly")[0], (2, 7))


class BaselineTests(TunerBase):
    NOW = BASE + 10 * DAY

    def test_median_p95_and_hour_of_day_in_plus8(self):
        self.seed("fp", [10, 20, 30, 40, 100])
        v = tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(v, 1)
        row = self.s.read("SELECT hour_of_day, median, p95, samples FROM baselines")[0]
        self.assertEqual(row, (8, 30.0, 100.0, 5))
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE + 3 * DAY + 5), (30.0, 100.0))
        self.assertIsNone(tuner.baseline_for(self.s, "fp", BASE + 3 * HOUR))

    def test_min_samples(self):
        self.seed("fp", [10, 20, 30, 40])
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertIsNone(tuner.baseline_for(self.s, "fp", BASE))

    def test_unhealthy_hours_excluded(self):
        self.seed("fp", [10, 10, 10, 10, 10, 5000, 5000])
        tuner.mark_unhealthy(self.s, "fp", BASE + 5 * DAY, BASE + 6 * DAY + 100)
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))

    def test_hours_of_real_incident_span_excluded(self):
        self.seed("fp", [10, 10, 10, 10, 10, 5000, 5000])
        self.incident("fp", BASE + 5 * DAY + 10, BASE + 6 * DAY + 100,
                      {"category": "infra", "confidence": 0.9})
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))

    def test_needs_human_incident_span_excluded(self):
        self.seed("fp", [10, 10, 10, 10, 10, 5000])
        self.incident("fp", BASE + 5 * DAY, BASE + 5 * DAY,
                      {"category": "noise", "confidence": 0.9, "needs_human": True})
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))

    def test_rejected_incident_span_excluded(self):
        from alert_doctor import feedback
        feedback.ensure_schema(self.s)
        self.seed("fp", [10, 10, 10, 10, 10, 5000])
        inc = self.incident("fp", BASE + 5 * DAY, BASE + 5 * DAY,
                            {"category": "noise", "confidence": 0.9})
        with self.s.tx() as db:
            db.execute("INSERT INTO feedback (incident_id, user, kind, epoch) VALUES (?,?,?,?)",
                       (inc, "U1", "reject", BASE))
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))

    def test_noise_incident_and_other_fingerprint_keep_hours(self):
        self.seed("fp", [10, 10, 10, 10, 30])
        self.incident("fp", BASE + 4 * DAY, BASE + 4 * DAY, {"category": "noise", "confidence": 0.9})
        self.incident("other", BASE + 4 * DAY, BASE + 4 * DAY, {"category": "code_bug"})
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 30.0))

    def test_unhealthy_before_observation_is_not_resurrected(self):
        tuner.mark_unhealthy(self.s, "fp", BASE, BASE + 10)
        tuner.record_observation(self.s, "fp", BASE + 20, 9999)
        self.assertEqual(self.s.read("SELECT healthy FROM fp_hourly")[0][0], 0)

    def test_unhealthy_only_affects_that_fingerprint_and_window(self):
        self.seed("a", [1] * 5)
        self.seed("b", [1] * 5)
        tuner.mark_unhealthy(self.s, "a", BASE, BASE + 10)
        rows = dict(((r[0], r[1]), r[2]) for r in self.s.read(
            "SELECT fingerprint, hour_epoch, healthy FROM fp_hourly"))
        self.assertEqual(rows[("a", BASE)], 0)
        self.assertEqual(rows[("a", BASE + DAY)], 1)
        self.assertEqual(rows[("b", BASE)], 1)

    def test_window_days_respected(self):
        self.seed("fp", [10] * 5)
        tuner.recompute_baselines(self.s, BASE + 60 * DAY)
        self.assertIsNone(tuner.baseline_for(self.s, "fp", BASE))

    def test_falls_back_to_alerts_without_errors(self):
        for day in range(5):
            for _ in range(day + 1):
                tuner.record_observation(self.s, "fp", BASE + day * DAY, None)
        tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE)[0], 3.0)

    def test_versions_and_rollback(self):
        self.seed("fp", [10] * 5)
        v1 = tuner.recompute_baselines(self.s, self.NOW)
        self.seed("fp", [10] * 5)
        for day in range(5):
            tuner.record_observation(self.s, "fp", BASE + day * DAY, 500)
        v2 = tuner.recompute_baselines(self.s, self.NOW)
        self.assertEqual((v1, v2), (1, 2))
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (500.0, 500.0))
        tuner.rollback_baselines(self.s, v1)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))
        self.assertEqual(tuner.recompute_baselines(self.s, self.NOW), v1)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (10.0, 10.0))
        tuner.unpin_baselines(self.s)
        self.assertEqual(tuner.recompute_baselines(self.s, self.NOW), 2)
        self.assertEqual(tuner.baseline_for(self.s, "fp", BASE), (500.0, 500.0))

    def test_keeps_only_latest_48_versions(self):
        self.seed("fp", [10] * 5)
        for _ in range(50):
            latest = tuner.recompute_baselines(self.s, self.NOW)
        versions = [r[0] for r in self.s.read("SELECT DISTINCT version FROM baselines ORDER BY version")]
        self.assertEqual(versions, list(range(latest - 47, latest + 1)))

    def test_pinned_version_survives_pruning(self):
        self.seed("fp", [10] * 5)
        tuner.recompute_baselines(self.s, self.NOW)
        tuner.rollback_baselines(self.s, 1)
        with self.s.tx() as db:
            for v in range(2, 60):
                db.execute("INSERT INTO baselines VALUES (?, 'x', 0, 1, 1, 1, 0)", (v,))
        tuner._prune(self.s)
        versions = [r[0] for r in self.s.read("SELECT DISTINCT version FROM baselines ORDER BY version")]
        self.assertEqual(versions, [1] + list(range(12, 60)))

    def test_empty_recompute_keeps_latest_version(self):
        self.assertEqual(tuner.recompute_baselines(self.s, self.NOW), 0)


class AccumulatedTests(unittest.TestCase):
    def acc(self, signal, baseline=None, min_errors=5, never_silence=False, **kw):
        return tuner.is_accumulated(signal, baseline, min_errors=min_errors,
                                    never_silence=never_silence, **kw)

    def test_min_rate_required_when_rate_known(self):
        self.assertTrue(self.acc(sig(errors=100, rate=0.001)))
        self.assertFalse(self.acc(sig(errors=100, rate=0.001), min_rate=0.01))
        self.assertTrue(self.acc(sig(errors=100, rate=0.01), min_rate=0.01))
        self.assertTrue(self.acc(sig(errors=100, rate=None), min_rate=0.01))

    def test_not_ok_never_accumulated(self):
        self.assertFalse(self.acc(sig(ok=False)))
        self.assertFalse(self.acc(sig(errors=None)))

    def test_cold_start_needs_triple_min(self):
        self.assertFalse(self.acc(sig(errors=14)))
        self.assertTrue(self.acc(sig(errors=15)))

    def test_absolute_floor(self):
        self.assertFalse(self.acc(sig(errors=4), baseline=(0.0, 0.0)))
        self.assertTrue(self.acc(sig(errors=6), baseline=(0.0, 0.0)))

    def test_baseline_threshold(self):
        base = (10.0, 20.0)
        self.assertFalse(self.acc(sig(errors=40), base))
        self.assertTrue(self.acc(sig(errors=41), base))
        self.assertFalse(self.acc(sig(errors=30), (10.0, 5.0)))
        self.assertTrue(self.acc(sig(errors=31), (10.0, 5.0)))

    def test_needs_duration_or_hosts(self):
        self.assertFalse(self.acc(sig(errors=100, duration=4, hosts=1)))
        self.assertTrue(self.acc(sig(errors=100, duration=4, hosts=2)))
        self.assertTrue(self.acc(sig(errors=100, duration=5, hosts=1)))

    def test_never_silence_halves_thresholds(self):
        self.assertFalse(self.acc(sig(errors=8)))
        self.assertTrue(self.acc(sig(errors=8), never_silence=True))
        self.assertFalse(self.acc(sig(errors=7), never_silence=True))
        base = (10.0, 20.0)
        self.assertFalse(self.acc(sig(errors=20), base))
        self.assertTrue(self.acc(sig(errors=21), base, never_silence=True))


if __name__ == "__main__":
    unittest.main()
