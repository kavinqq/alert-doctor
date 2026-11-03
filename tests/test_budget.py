import unittest

from alert_doctor.budget import Budgets, ProtectionMonitor, TokenBucket
from alert_doctor.config import Config


def cfg(**kw):
    return Config(workspace_url="https://x", **kw)


class TokenBucketTest(unittest.TestCase):
    def _bucket(self):
        return TokenBucket(20, 20, {"critical": 4, "first": 4})

    def test_normal_capped_by_reserves(self):
        b = self._bucket()
        taken = sum(b.take("normal", 0) for _ in range(30))
        self.assertEqual(taken, 12)
        self.assertEqual(b.available("critical", 0), 4)
        self.assertEqual(b.available("first", 0), 4)

    def test_critical_uses_own_reserve_plus_shared(self):
        b = self._bucket()
        self.assertEqual(sum(b.take("critical", 0) for _ in range(30)), 16)

    def test_reserves_survive_normal_drain(self):
        b = self._bucket()
        for _ in range(12):
            b.take("normal", 0)
        self.assertEqual(sum(b.take("first", 0) for _ in range(10)), 4)
        self.assertFalse(b.take("normal", 0))
        self.assertEqual(sum(b.take("critical", 0) for _ in range(10)), 4)

    def test_refill_restores_reserves_before_shared_pool(self):
        b = self._bucket()
        for _ in range(16):
            b.take("critical", 0)
        self.assertFalse(b.take("normal", 0))
        self.assertTrue(b.take("critical", 3, 1))
        self.assertFalse(b.take("normal", 3))

    def test_refill_is_continuous_and_capped(self):
        b = TokenBucket(10, 60)
        self.assertTrue(b.take("normal", 0, 10))
        self.assertFalse(b.take("normal", 0))
        self.assertEqual(b.available("normal", 0.5), 0)
        self.assertEqual(b.available("normal", 5), 5)
        self.assertEqual(b.available("normal", 1000), 10)

    def test_fractional_refill_accumulates(self):
        b = TokenBucket(10, 30)
        b.take("normal", 0, 10)
        self.assertFalse(b.take("normal", 1))
        self.assertTrue(b.take("normal", 2))

    def test_take_never_negative_and_n_is_atomic(self):
        b = TokenBucket(5, 0)
        self.assertFalse(b.take("normal", 0, 6))
        self.assertEqual(b.available("normal", 0), 5)
        self.assertTrue(b.take("normal", 0, 5))
        self.assertFalse(b.take("critical", 0))
        self.assertEqual(b.available("normal", 0), 0)

    def test_clock_going_backwards_does_not_refill_or_break(self):
        b = TokenBucket(10, 60)
        b.take("normal", 100, 10)
        self.assertEqual(b.available("normal", 50), 0)
        self.assertEqual(b.available("normal", 102), 2)

    def test_no_reserve_means_plain_bucket(self):
        b = TokenBucket(3, 0)
        self.assertEqual(sum(b.take("critical", 0) for _ in range(5)), 3)


class BudgetsTest(unittest.TestCase):
    def test_built_from_config(self):
        b = Budgets(cfg())
        self.assertEqual(sum(b.elk.take("normal", 0) for _ in range(100)), 20)
        self.assertEqual(sum(b.elk.take("critical", 0) for _ in range(100)), 10)
        self.assertEqual(sum(b.slack.take("normal", 0) for _ in range(100)), 12)
        self.assertEqual(sum(b.llm.take("normal", 0) for _ in range(100)), 5)

    def test_respects_overrides(self):
        b = Budgets(cfg(budget_llm_per_min=2, budget_slack_per_min=10,
                        budget_slack_reserved_critical=1, budget_slack_reserved_first=1))
        self.assertEqual(sum(b.llm.take("normal", 0) for _ in range(10)), 2)
        self.assertEqual(sum(b.slack.take("normal", 0) for _ in range(20)), 8)


class ProtectionMonitorTest(unittest.TestCase):
    def setUp(self):
        self.m = ProtectionMonitor(cfg(overload_exit_minutes=3, overload_intake_per_min=1000,
                                        overload_active_incidents=30))

    def test_quiet_normal_returns_none(self):
        self.assertIsNone(self.m.observe(0, 10, 1, "normal"))

    def test_enter_immediately_on_intake(self):
        state, reason = self.m.observe(0, 1000, 0, "normal")
        self.assertEqual(state, "overload")
        self.assertIn("1000", reason)

    def test_enter_immediately_on_active_incidents(self):
        state, reason = self.m.observe(0, 0, 30, "normal")
        self.assertEqual(state, "overload")
        self.assertIn("30", reason)

    def test_just_under_threshold_does_not_enter(self):
        self.assertIsNone(self.m.observe(0, 999, 29, "normal"))

    def test_already_overloaded_and_still_high_returns_none(self):
        self.assertIsNone(self.m.observe(0, 5000, 50, "overload"))

    def test_exit_after_n_calm_steps_60s_apart(self):
        self.assertIsNone(self.m.observe(0, 100, 5, "overload"))
        self.assertIsNone(self.m.observe(60, 100, 5, "overload"))
        result = self.m.observe(120, 100, 5, "overload")
        self.assertEqual(result[0], "normal")

    def test_calm_calls_inside_60s_do_not_count(self):
        for t in range(0, 59, 5):
            self.assertIsNone(self.m.observe(t, 0, 0, "overload"))
        self.assertIsNone(self.m.observe(60, 0, 0, "overload"))
        self.assertEqual(self.m.observe(120, 0, 0, "overload")[0], "normal")

    def test_between_half_and_full_threshold_is_not_calm(self):
        self.m.observe(0, 0, 0, "overload")
        self.m.observe(60, 0, 0, "overload")
        self.assertIsNone(self.m.observe(120, 500, 0, "overload"))
        self.assertIsNone(self.m.observe(180, 0, 0, "overload"))
        self.assertIsNone(self.m.observe(240, 0, 0, "overload"))
        self.assertEqual(self.m.observe(300, 0, 0, "overload")[0], "normal")

    def test_active_incidents_at_half_threshold_is_not_calm(self):
        self.assertIsNone(self.m.observe(0, 0, 15, "overload"))
        self.assertIsNone(self.m.observe(60, 0, 15, "overload"))
        self.assertIsNone(self.m.observe(120, 0, 15, "overload"))

    def test_spike_inside_60s_still_resets_streak(self):
        self.m.observe(0, 0, 0, "overload")
        self.m.observe(60, 0, 0, "overload")
        self.assertIsNone(self.m.observe(70, 2000, 0, "overload"))
        self.assertIsNone(self.m.observe(120, 0, 0, "overload"))
        self.assertIsNone(self.m.observe(180, 0, 0, "overload"))
        self.assertEqual(self.m.observe(240, 0, 0, "overload")[0], "normal")

    def test_streak_resets_after_exit(self):
        for t in (0, 60, 120):
            self.m.observe(t, 0, 0, "overload")
        self.assertIsNone(self.m.observe(180, 0, 0, "overload"))
        self.assertIsNone(self.m.observe(240, 0, 0, "overload"))

    def test_normal_state_clears_stale_streak(self):
        self.m.observe(0, 0, 0, "overload")
        self.m.observe(60, 0, 0, "overload")
        self.m.observe(70, 0, 0, "normal")
        self.assertIsNone(self.m.observe(120, 0, 0, "overload"))
        self.assertIsNone(self.m.observe(180, 0, 0, "overload"))


if __name__ == "__main__":
    unittest.main()
