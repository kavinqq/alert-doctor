import os
import tempfile
import unittest
from datetime import datetime

from alert_doctor.checks import load_checks, lookup_check
from alert_doctor.models import ParsedAlert
from alert_doctor.rules import TAIPEI, load_rules, match_rule

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def alert(**kw):
    base = dict(
        channel="C1",
        ts="1760000000.000100",
        raw_text="",
        parse_ok=True,
        check_title="檢查 FastPxy 5xx",
        check_code="fastpxy_5xx",
        level=40,
        result_message="502 Bad Gateway",
    )
    base.update(kw)
    return ParsedAlert(**base)


def epoch(day: str, hm: str = "12:00") -> float:
    return datetime.strptime(f"{day} {hm}", "%Y-%m-%d %H:%M").replace(tzinfo=TAIPEI).timestamp()


def write_rules(text: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


class RulesTest(unittest.TestCase):
    def test_example_rules_load(self):
        rules = load_rules(os.path.join(ROOT, "rules.example.toml"))
        self.assertEqual({r.action for r in rules}, {"datasource", "noise", "known", "never_silence"})
        noise = next(r for r in rules if r.action == "noise")
        self.assertTrue(noise.require_transient)

    def test_first_match_wins_and_fields_carried(self):
        path = write_rules(
            '[[rules]]\nid="a"\naction="known"\nmatch_code="^fastpxy"\nnote="n"\nlink="L"\n'
            '[[rules]]\nid="b"\naction="noise"\n'
        )
        m = match_rule(load_rules(path), alert(), epoch("2026-10-19"))
        self.assertEqual((m.rule_id, m.action, m.note, m.link), ("a", "known", "n", "L"))

    def test_all_given_criteria_must_match(self):
        path = write_rules(
            '[[rules]]\nid="a"\naction="noise"\nmatch_code="fastpxy"\nmatch_message="timeout"\nlevel=40\n'
        )
        rules = load_rules(path)
        now = epoch("2026-10-19")
        self.assertIsNone(match_rule(rules, alert(), now))
        self.assertIsNotNone(match_rule(rules, alert(result_message="read timeout"), now))
        self.assertIsNone(match_rule(rules, alert(result_message="read timeout", level=30), now))

    def test_missing_code_does_not_match_code_pattern(self):
        path = write_rules('[[rules]]\nid="a"\naction="noise"\nmatch_code=".*"\n')
        self.assertIsNone(match_rule(load_rules(path), alert(check_code=None), epoch("2026-10-19")))

    def test_title_match(self):
        path = write_rules('[[rules]]\nid="a"\naction="never_silence"\nmatch_title="下單|登入"\n')
        rules = load_rules(path)
        self.assertIsNotNone(match_rule(rules, alert(check_title="下單失敗率"), 0))
        self.assertIsNone(match_rule(rules, alert(check_title="報價"), 0))

    def test_expires_inclusive_in_taipei_time(self):
        path = write_rules('[[rules]]\nid="a"\naction="noise"\nexpires="2026-10-19"\n')
        rules = load_rules(path)
        self.assertIsNotNone(match_rule(rules, alert(), epoch("2026-10-19", "23:59")))
        self.assertIsNone(match_rule(rules, alert(), epoch("2026-10-20", "00:00")))

    def test_expired_rule_skipped_to_next(self):
        path = write_rules(
            '[[rules]]\nid="old"\naction="noise"\nexpires="2026-01-01"\n[[rules]]\nid="new"\naction="known"\n'
        )
        m = match_rule(load_rules(path), alert(), epoch("2026-10-19"))
        self.assertEqual(m.rule_id, "new")

    def test_unquoted_toml_date_expires(self):
        path = write_rules('[[rules]]\nid="a"\naction="noise"\nexpires=2026-10-19\n')
        rules = load_rules(path)
        self.assertIsNotNone(match_rule(rules, alert(), epoch("2026-10-19", "23:59")))
        self.assertIsNone(match_rule(rules, alert(), epoch("2026-10-20", "00:00")))

    def test_bad_expires_rejected_with_rule_id(self):
        for value in ("20261231", "12345", "true", "2026-10-19T10:00:00", "[1]"):
            with self.subTest(value=value):
                path = write_rules(f'[[rules]]\nid="rid-x"\naction="noise"\nexpires={value}\n')
                with self.assertRaises(ValueError) as cm:
                    load_rules(path)
                self.assertIn("rid-x", str(cm.exception))

    def test_bad_expires_string_rejected_with_rule_id(self):
        path = write_rules('[[rules]]\nid="rid-y"\naction="noise"\nexpires="2026-13-40"\n')
        with self.assertRaises(ValueError) as cm:
            load_rules(path)
        self.assertIn("rid-y", str(cm.exception))

    def test_unknown_key_rejected_with_rule_id(self):
        path = write_rules('[[rules]]\nid="rid-z"\naction="noise"\nmatch_msg="x"\n')
        with self.assertRaises(ValueError) as cm:
            load_rules(path)
        self.assertIn("rid-z", str(cm.exception))
        self.assertIn("match_msg", str(cm.exception))

    def test_missing_id_or_action_is_value_error(self):
        with self.assertRaises(ValueError):
            load_rules(write_rules('[[rules]]\naction="noise"\n'))
        with self.assertRaises(ValueError):
            load_rules(write_rules('[[rules]]\nid="a"\n'))

    def test_bad_action_and_bad_regex_rejected(self):
        with self.assertRaises(ValueError):
            load_rules(write_rules('[[rules]]\nid="a"\naction="mute"\n'))
        with self.assertRaises(Exception):
            load_rules(write_rules('[[rules]]\nid="a"\naction="noise"\nmatch_code="("\n'))


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.checks = load_checks(os.path.join(ROOT, "checks.example.toml"))

    def test_example_parsed(self):
        c = self.checks["fastpxy_5xx"]
        self.assertEqual(c.system, "fastpxy")
        self.assertEqual((c.signal, c.min_errors), ("rate", 5))
        self.assertIsNotNone(c.elk.total_query)
        self.assertEqual(c.repo, "/Users/you/acme-proxy")
        self.assertEqual(c.deploy_ref, "origin/main")
        self.assertEqual(c.owners, ("U01AAAAAAAA",))
        self.assertFalse(c.never_silence)
        self.assertEqual(c.elk.lookback_minutes, 15)
        filters = c.elk.query["bool"]["filter"]
        self.assertEqual(filters[0], {"term": {"log.extra.logger_name": "fast_pxy.log_middleware"}})
        self.assertEqual(filters[2]["range"]["@timestamp"], {"gte": "{{from}}", "lte": "{{to}}"})

    def test_lookup_prefers_code_then_title(self):
        c = self.checks["fastpxy_5xx"]
        self.assertIs(lookup_check(self.checks, alert()), c)
        self.assertIsNone(lookup_check(self.checks, alert(check_code="other", check_title="x")))

    def test_lookup_by_title(self):
        path = write_rules('[checks."檢查 X"]\nsystem="X"\nnever_silence=true\n')
        checks = load_checks(path)
        got = lookup_check(checks, alert(check_code=None, check_title="檢查 X"))
        self.assertTrue(got.never_silence)
        self.assertIsNone(got.elk)
        self.assertEqual(got.deploy_ref, "origin/HEAD")

    def test_signal_fields_parsed(self):
        path = write_rules(
            '[checks.a]\nsignal="rate"\nmin_errors=20\n'
            '[checks.a.elk]\nindex="i"\nquery=\'{"match_all": {}}\'\n'
            'total_query=\'{"term": {"t": 1}}\'\n'
        )
        c = load_checks(path)["a"]
        self.assertEqual((c.signal, c.min_errors), ("rate", 20))
        self.assertEqual(c.elk.total_query, {"term": {"t": 1}})

    def test_signal_defaults(self):
        path = write_rules('[checks.a]\n[checks.a.elk]\nindex="i"\nquery=\'{"match_all": {}}\'\n')
        c = load_checks(path)["a"]
        self.assertEqual((c.signal, c.min_errors), ("count", 5))
        self.assertIsNone(c.elk.total_query)


if __name__ == "__main__":
    unittest.main()
