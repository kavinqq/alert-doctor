import unittest

from alert_doctor.models import SEVERITY_REACTION, Category, CheckSpec, ElkSpec, Incident, Reaction


class ModelsV2Test(unittest.TestCase):
    def test_new_names(self):
        self.assertEqual(Category.ACCUMULATED.value, "accumulated")
        self.assertEqual(Reaction.ACCUMULATED, "chart_with_upwards_trend")
        self.assertIsNone(ElkSpec("i", {}).total_query)
        check = CheckSpec("k")
        self.assertEqual((check.signal, check.min_errors), ("count", 5))
        incident = Incident(1, "f", "g", None, "t", "C", "1.0", 1, 1, 1, "none")
        self.assertEqual(incident.source_system, "")

    def test_severity_reactions(self):
        self.assertEqual(Reaction.NEEDS_HUMAN, "raising_hand")
        self.assertEqual(SEVERITY_REACTION, {
            "low": "large_green_circle", "medium": "large_yellow_circle",
            "high": "large_orange_circle", "critical": "red_circle"})


if __name__ == "__main__":
    unittest.main()
