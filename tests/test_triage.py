import dataclasses
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

if "alert_doctor.replies" not in sys.modules:
    try:
        import alert_doctor.replies  # noqa: F401
    except ImportError:
        sys.modules["alert_doctor.replies"] = types.ModuleType("alert_doctor.replies")

from alert_doctor import known, known_store, triage  # noqa: E402
from alert_doctor.models import (  # noqa: E402
    Category,
    CheckSpec,
    Evidence,
    Incident,
    ParsedAlert,
    Reaction,
    RuleMatch,
)


def alert(**kw):
    base = dict(
        channel="C1",
        ts="1760000000.000100",
        raw_text="",
        parse_ok=True,
        check_title="t",
        check_code="c",
        level=40,
        result_message="m",
    )
    base.update(kw)
    return ParsedAlert(**base)


INCIDENT = Incident(
    id=7,
    fingerprint="f",
    group_fp="g",
    check_code="c",
    check_title="t",
    channel="C1",
    anchor_ts="1760000000.000100",
    first_epoch=0,
    last_epoch=0,
    count=1,
    analysis_state="none",
)


PENDING_INCIDENT = dataclasses.replace(INCIDENT, analysis_state="pending")


def ev(ok=True, total=3, hosts=1, last=0, histogram=None, error=None):
    if not ok:
        return Evidence(query_ok=False, window_from="a", window_to="b", error=error or "timeout")
    if histogram is None:
        histogram = (("t0", total), ("t1", 0), ("t2", last), ("t3", 0))
    return Evidence(
        query_ok=True,
        window_from="a",
        window_to="b",
        total=total,
        per_host={f"h{i}": 1 for i in range(hosts)},
        histogram=histogram,
    )


def noise_rule(**kw):
    return RuleMatch(rule_id="r", action="noise", note="n", **kw)


class ClassifyTest(unittest.TestCase):
    def setUp(self):
        patcher = patch("alert_doctor.triage.replies", MagicMock())
        self.replies = patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("noise", "known", "duplicate", "analyzing", "critical", "unparsed"):
            getattr(self.replies, name).return_value = f"<{name}>"

    def run_classify(self, a=None, **kw):
        args = dict(
            is_new_incident=True,
            spike=False,
            rule=None,
            check=None,
            evidence=None,
            incident=INCIDENT,
            permalink="http://p",
        )
        args.update(kw)
        return triage.classify(a or alert(), **args)

    def test_datasource_failure_is_reported_not_analyzed(self):
        rule = RuleMatch(rule_id="elk", action="datasource", note="ELK")
        d = self.run_classify(rule=rule, is_new_incident=True, spike=True)
        self.assertEqual((d.category, d.reaction, d.needs_analysis, d.severity),
                         (Category.DATASOURCE, Reaction.DATASOURCE, False, None))
        self.replies.datasource.assert_called_once()

    def test_never_silence_beats_datasource_and_says_the_query_failed(self):
        self.replies.datasource.return_value = "<datasource>"
        rule = RuleMatch(rule_id="elk", action="datasource")
        check = CheckSpec(key="c", never_silence=True, owners=("U1",))
        d = self.run_classify(rule=rule, check=check, owners=("<@U1>",))
        self.assertEqual((d.category, d.reaction, d.needs_analysis, d.severity),
                         (Category.CRITICAL, Reaction.CRITICAL, True, Reaction.SEV_CRITICAL))
        self.assertEqual(d.reply_text, "<critical>\n<datasource>")
        self.assertEqual(self.replies.critical.call_args.args[1], ("<@U1>",))
        self.assertEqual(self.replies.datasource.call_args.args[1], ())

    def test_never_silence_rule_with_datasource_check_failure_is_critical(self):
        self.replies.datasource.return_value = "<datasource>"
        d = self.run_classify(rule=RuleMatch(rule_id="elk", action="datasource"),
                              check=CheckSpec(key="c", never_silence=True))
        self.assertEqual(d.category, Category.CRITICAL)
        self.assertIn("<datasource>", d.reply_text)

    def test_unparsed(self):
        d = self.run_classify(alert(parse_ok=False), is_new_incident=True, spike=True)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.UNPARSED, Reaction.UNPARSED, False))
        self.assertEqual(d.reply_text, "<unparsed>")

    def test_never_silence_check_beats_unparsed(self):
        d = self.run_classify(alert(parse_ok=False), check=CheckSpec(key="t", never_silence=True))
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.CRITICAL, Reaction.CRITICAL, True))

    def test_never_silence_rule_beats_unparsed(self):
        d = self.run_classify(alert(parse_ok=False), rule=RuleMatch(rule_id="r", action="never_silence"))
        self.assertEqual((d.category, d.needs_analysis), (Category.CRITICAL, True))

    def test_unparsed_never_silence_duplicate_needs_no_analysis(self):
        d = self.run_classify(
            alert(parse_ok=False), check=CheckSpec(key="t", never_silence=True), is_new_incident=False
        )
        self.assertEqual((d.category, d.needs_analysis), (Category.CRITICAL, False))

    def test_critical_by_check_new(self):
        check = CheckSpec(key="c", never_silence=True, owners=("U1",))
        d = self.run_classify(check=check)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.CRITICAL, Reaction.CRITICAL, True))
        self.replies.critical.assert_called_once_with(INCIDENT, ("U1",), False)

    def test_critical_by_rule_duplicate_needs_no_analysis(self):
        rule = RuleMatch(rule_id="r", action="never_silence")
        d = self.run_classify(rule=rule, is_new_incident=False)
        self.assertEqual(d.category, Category.CRITICAL)
        self.assertFalse(d.needs_analysis)
        self.replies.critical.assert_called_once_with(INCIDENT, (), False)

    def test_critical_spike_needs_analysis(self):
        d = self.run_classify(rule=RuleMatch(rule_id="r", action="never_silence"), is_new_incident=False, spike=True)
        self.assertTrue(d.needs_analysis)

    def test_never_silence_beats_noise_rule(self):
        check = CheckSpec(key="c", never_silence=True)
        d = self.run_classify(check=check, rule=noise_rule(), evidence=ev())
        self.assertEqual(d.category, Category.CRITICAL)

    def test_known(self):
        rule = RuleMatch(rule_id="r", action="known", note="n", link="L")
        d = self.run_classify(rule=rule, is_new_incident=False)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.KNOWN, Reaction.KNOWN, False))
        self.replies.known.assert_called_once_with(rule)

    def test_noise_without_transient_requirement(self):
        d = self.run_classify(rule=noise_rule(), evidence=None)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.NOISE, Reaction.NOISE, False))
        self.assertEqual(d.rule.rule_id, "r")

    def test_noise_with_transient_confirmed(self):
        e = ev()
        rule = noise_rule(require_transient=True)
        d = self.run_classify(rule=rule, evidence=e)
        self.assertEqual(d.category, Category.NOISE)
        self.replies.noise.assert_called_once_with(rule, e)

    def test_duplicate_of_queued_incident(self):
        for state in ("pending", "leased", "done", "failed"):
            incident = dataclasses.replace(INCIDENT, analysis_state=state)
            d = self.run_classify(is_new_incident=False, incident=incident)
            self.assertEqual(
                (d.category, d.reaction, d.needs_analysis), (Category.DUPLICATE, Reaction.DUPLICATE, False), state
            )
        self.replies.duplicate.assert_called_with(incident, "http://p")

    def test_noise_anchor_then_transient_failure_is_new_and_analyzed(self):
        rule = noise_rule(require_transient=True)
        d = self.run_classify(rule=rule, evidence=ev(ok=False), is_new_incident=False, incident=INCIDENT)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.NEW, Reaction.ANALYZING, True))

    def test_never_queued_incident_follow_up_is_new(self):
        d = self.run_classify(is_new_incident=False, incident=INCIDENT)
        self.assertEqual((d.category, d.needs_analysis), (Category.NEW, True))

    def test_new(self):
        d = self.run_classify()
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.NEW, Reaction.ANALYZING, True))
        self.replies.analyzing.assert_called_once_with(INCIDENT, False)

    def test_spike_wins_over_duplicate(self):
        d = self.run_classify(is_new_incident=False, spike=True)
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.SPIKE, Reaction.ANALYZING, True))
        self.replies.analyzing.assert_called_once_with(INCIDENT, True)

    def test_spike_on_new_incident_is_spike(self):
        self.assertEqual(self.run_classify(spike=True).category, Category.SPIKE)


class RequireTransientFailsClosedTest(unittest.TestCase):
    """Review Focus 2: no evidence of recovery means never NOISE."""

    def setUp(self):
        patcher = patch("alert_doctor.triage.replies", MagicMock())
        patcher.start()
        self.addCleanup(patcher.stop)

    def classify_with(self, evidence, **kw):
        args = dict(
            is_new_incident=True,
            spike=False,
            rule=noise_rule(require_transient=True, max_count=20),
            check=None,
            evidence=evidence,
            incident=PENDING_INCIDENT,
            permalink="p",
        )
        args.update(kw)
        return triage.classify(alert(), **args)

    def assert_not_noise(self, evidence, new=True):
        d = self.classify_with(evidence, is_new_incident=new)
        self.assertNotEqual(d.category, Category.NOISE)
        self.assertNotEqual(d.reaction, Reaction.NOISE)
        expected = Category.NEW if new else Category.DUPLICATE
        self.assertEqual(d.category, expected)
        self.assertEqual(d.needs_analysis, new)

    def test_evidence_none(self):
        self.assert_not_noise(None)
        self.assert_not_noise(None, new=False)

    def test_query_failed(self):
        self.assert_not_noise(ev(ok=False))
        self.assert_not_noise(ev(ok=False, error="HTTP 503"), new=False)

    def test_query_failed_even_with_plausible_fields(self):
        e = Evidence(
            query_ok=False, window_from="a", window_to="b", total=0, histogram=(("t", 0),), error="timeout"
        )
        self.assert_not_noise(e)

    def test_total_none(self):
        e = Evidence(query_ok=True, window_from="a", window_to="b", total=None, histogram=(("t", 0),))
        self.assert_not_noise(e)

    def test_two_hosts(self):
        self.assert_not_noise(ev(hosts=2))

    def test_last_bucket_non_zero(self):
        self.assert_not_noise(ev(last=1))

    def test_only_current_partial_minute_empty(self):
        self.assert_not_noise(ev(histogram=(("t0", 1), ("t1", 2), ("t2", 0))))

    def test_no_host_breakdown_with_hits(self):
        self.assert_not_noise(ev(hosts=0))

    def test_too_few_buckets_with_hits(self):
        self.assert_not_noise(ev(histogram=(("t0", 0), ("t1", 0))))

    def test_over_max_count(self):
        self.assert_not_noise(ev(total=21))

    def test_empty_histogram_with_hits(self):
        self.assert_not_noise(ev(total=3, histogram=()))

    def test_spike_with_failed_elk_goes_to_analysis(self):
        d = self.classify_with(ev(ok=False), spike=True, is_new_incident=False)
        self.assertEqual(d.category, Category.SPIKE)
        self.assertTrue(d.needs_analysis)

    def test_boundaries_that_are_transient(self):
        for e in (ev(total=20), ev(total=0, hosts=0, histogram=())):
            self.assertEqual(self.classify_with(e).category, Category.NOISE)

    def test_custom_max_count(self):
        rule = noise_rule(require_transient=True, max_count=2)
        self.assertEqual(self.classify_with(ev(total=3), rule=rule).category, Category.NEW)
        self.assertEqual(self.classify_with(ev(total=2), rule=rule).category, Category.NOISE)


class IsTransientTest(unittest.TestCase):
    def test_cases(self):
        self.assertTrue(triage.is_transient(ev(), 20))
        self.assertFalse(triage.is_transient(None, 20))
        self.assertFalse(triage.is_transient(ev(ok=False), 20))
        self.assertFalse(triage.is_transient(ev(hosts=2), 20))
        self.assertFalse(triage.is_transient(ev(last=2), 20))

    def test_final_partial_bucket_is_ignored(self):
        lagging = ev(histogram=(("t0", 3), ("t1", 0), ("t2", 0), ("t3", 9)))
        self.assertTrue(triage.is_transient(lagging, 20))

    def test_needs_two_settled_empty_buckets_before_final(self):
        self.assertFalse(triage.is_transient(ev(histogram=(("t0", 3), ("t1", 1), ("t2", 0), ("t3", 0))), 20))
        self.assertFalse(triage.is_transient(ev(histogram=(("t0", 3), ("t1", 0), ("t2", 1), ("t3", 0))), 20))

    def test_zero_total_needs_no_buckets_or_hosts(self):
        self.assertTrue(triage.is_transient(ev(total=0, hosts=0, histogram=()), 20))

    def test_hits_without_hosts_not_transient(self):
        self.assertFalse(triage.is_transient(ev(hosts=0), 20))


class DetectSpikeTest(unittest.TestCase):
    def test_spec_cases(self):
        self.assertTrue(triage.detect_spike(5, [0, 0, 0, 0]))
        self.assertFalse(triage.detect_spike(4, [0, 0, 0, 0]))
        self.assertFalse(triage.detect_spike(10, [1, 2, 3]))
        self.assertTrue(triage.detect_spike(10, [3, 3, 3, 3]))
        self.assertFalse(triage.detect_spike(9, [3, 3, 3, 3]))

    def test_empty_baseline_and_median_of_even_count(self):
        self.assertFalse(triage.detect_spike(100, []))
        self.assertTrue(triage.detect_spike(8, [1, 2, 2, 3]))  # median 2 -> 7
        self.assertFalse(triage.detect_spike(6, [1, 2, 2, 3]))


def auto_hit(kind="noise", active=True, sample=False, rule_id=5):
    from alert_doctor.autorules import AutoHit, AutoRule
    rule = AutoRule(rule_id, "f", kind, "verdict", "active" if active else "shadow", 0.0, None, None,
                    0, 0, 0, 0, "")
    return AutoHit(rule, active, sample)


def loud_signal():
    from alert_doctor.signals import Signal
    return Signal(ok=True, errors=500, total=None, rate=None, duration_minutes=30, hosts=3)


def quiet_signal():
    from alert_doctor.signals import Signal
    return Signal(ok=True, errors=1, total=None, rate=None, duration_minutes=1, hosts=1)


def failed_signal():
    from alert_doctor.signals import Signal
    return Signal(ok=False, errors=None, total=None, rate=None, duration_minutes=0, hosts=0, error="x")


class V2OrderingTest(unittest.TestCase):
    """Task C ordering: never_silence > UNPARSED > ACCUMULATED > file KNOWN > auto > file noise > ..."""

    def setUp(self):
        patcher = patch("alert_doctor.triage.replies", MagicMock())
        self.replies = patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("noise", "known", "duplicate", "analyzing", "critical", "unparsed"):
            getattr(self.replies, name).return_value = f"<{name}>"

    def run_classify(self, a=None, **kw):
        args = dict(is_new_incident=True, spike=False, rule=None, check=None, evidence=None,
                    incident=INCIDENT, permalink="http://p", signal=quiet_signal())
        args.update(kw)
        return triage.classify(a or alert(), **args)

    def assert_not_silenced(self, d):
        self.assertNotIn(d.category, (Category.NOISE, Category.KNOWN))
        self.assertTrue(d.needs_analysis)
        self.assertIsNone(d.auto_effect)

    def test_auto_rules_never_silence_without_signal(self):
        for kind in ("noise", "known"):
            self.assert_not_silenced(self.run_classify(auto_hit=auto_hit(kind=kind), signal=None))

    def test_auto_rules_never_silence_on_failed_signal(self):
        for kind in ("noise", "known"):
            d = self.run_classify(auto_hit=auto_hit(kind=kind), signal=failed_signal())
            self.assert_not_silenced(d)
            self.assertEqual(d.category, Category.NEW)

    def test_auto_rules_never_silence_during_spike(self):
        for kind in ("noise", "known"):
            d = self.run_classify(auto_hit=auto_hit(kind=kind), spike=True)
            self.assert_not_silenced(d)
            self.assertEqual(d.category, Category.SPIKE)

    def test_unsilenced_auto_rule_falls_through_to_file_noise_rule(self):
        d = self.run_classify(auto_hit=auto_hit(), signal=None, rule=noise_rule())
        self.assertEqual(d.category, Category.NOISE)
        self.assertIsNone(d.auto_effect)

    def test_unsilenced_auto_rule_falls_through_to_duplicate(self):
        d = self.run_classify(auto_hit=auto_hit(kind="known"), signal=None, is_new_incident=False,
                              incident=PENDING_INCIDENT)
        self.assertEqual(d.category, Category.DUPLICATE)

    def test_active_noise_silences_with_auto_text(self):
        d = self.run_classify(auto_hit=auto_hit())
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.NOISE, Reaction.NOISE, False))
        self.assertIn("自動規則 #5", d.reply_text)
        self.assertEqual(d.auto_effect, "silenced")
        self.assertIsNone(d.severity)

    def test_active_known_links_previous_analysis(self):
        d = self.run_classify(auto_hit=auto_hit(kind="known"), auto_link="http://prev")
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.KNOWN, Reaction.KNOWN, False))
        self.assertIn("http://prev", d.reply_text)

    def test_accumulated_never_silenced_by_active_rule(self):
        d = self.run_classify(auto_hit=auto_hit(), accumulated=True, signal=loud_signal())
        self.assertEqual((d.category, d.reaction, d.needs_analysis),
                         (Category.ACCUMULATED, Reaction.ACCUMULATED, True))
        self.assertEqual(d.auto_effect, "invalidate")
        self.assertEqual(d.severity, Reaction.SEV_HIGH)
        self.assertIn("500", d.reply_text)

    def test_accumulated_beats_file_known_and_noise(self):
        for rule in (RuleMatch(rule_id="k", action="known"), noise_rule()):
            d = self.run_classify(rule=rule, accumulated=True, signal=loud_signal())
            self.assertEqual(d.category, Category.ACCUMULATED)

    def test_unparsed_beats_accumulated(self):
        d = self.run_classify(alert(parse_ok=False), accumulated=True, signal=loud_signal())
        self.assertEqual(d.category, Category.UNPARSED)

    def test_never_silence_check_never_silenced_and_invalidates(self):
        check = CheckSpec(key="c", never_silence=True)
        d = self.run_classify(check=check, auto_hit=auto_hit())
        self.assertEqual(d.category, Category.CRITICAL)
        self.assertEqual(d.auto_effect, "invalidate")
        self.assertEqual(d.severity, Reaction.SEV_CRITICAL)

    def test_never_silence_title_rule_never_silenced(self):
        d = self.run_classify(rule=RuleMatch(rule_id="r", action="never_silence"), auto_hit=auto_hit())
        self.assertEqual(d.category, Category.CRITICAL)

    def test_sampled_goes_to_analysis(self):
        d = self.run_classify(auto_hit=auto_hit(sample=True))
        self.assertEqual((d.category, d.reaction, d.needs_analysis), (Category.NEW, Reaction.ANALYZING, True))
        self.assertEqual(d.auto_effect, "sample")
        self.assertIn("抽樣", d.reply_text)

    def test_sampled_skips_file_noise_rule(self):
        d = self.run_classify(auto_hit=auto_hit(sample=True), rule=noise_rule())
        self.assertEqual(d.category, Category.NEW)

    def test_sampled_duplicate_of_analyzed_incident_is_duplicate(self):
        d = self.run_classify(auto_hit=auto_hit(sample=True), is_new_incident=False, incident=PENDING_INCIDENT)
        self.assertEqual(d.category, Category.DUPLICATE)
        self.assertIsNone(d.auto_effect)

    def test_shadow_does_not_change_category(self):
        d = self.run_classify(auto_hit=auto_hit(active=False))
        self.assertEqual(d.category, Category.NEW)
        self.assertEqual(d.auto_effect, "shadow")

    def test_shadow_not_counted_when_never_silence_or_accumulated(self):
        check = CheckSpec(key="c", never_silence=True)
        self.assertIsNone(self.run_classify(check=check, auto_hit=auto_hit(active=False)).auto_effect)
        d = self.run_classify(auto_hit=auto_hit(active=False), accumulated=True, signal=loud_signal())
        self.assertIsNone(d.auto_effect)

    def test_elk_failure_never_yields_auto_noise(self):
        d = self.run_classify(auto_hit=auto_hit(), elk_failed=True)
        self.assertNotEqual(d.category, Category.NOISE)
        self.assertEqual((d.category, d.needs_analysis), (Category.NEW, True))
        self.assertIsNone(d.auto_effect)

    def test_file_known_beats_auto(self):
        d = self.run_classify(rule=RuleMatch(rule_id="k", action="known"), auto_hit=auto_hit())
        self.assertEqual(d.category, Category.KNOWN)
        self.assertIsNone(d.auto_effect)

    def test_initial_severity(self):
        self.assertEqual(self.run_classify(spike=True).severity, Reaction.SEV_HIGH)
        self.assertIsNone(self.run_classify().severity)
        self.assertIsNone(self.run_classify(rule=noise_rule()).severity)
        self.assertIsNone(self.run_classify(is_new_incident=False, incident=PENDING_INCIDENT).severity)

    def test_owners_override_check_owners_for_critical(self):
        check = CheckSpec(key="c", never_silence=True, owners=("U1",))
        self.run_classify(check=check, owners=("<@U2>",))
        self.replies.critical.assert_called_once_with(INCIDENT, ("<@U2>",), False)



def known_hit(action="known"):
    window = known.KnownWindow(start=180, end=190, days=frozenset(range(7)), label="62 號主機重啟")
    entry = known.KnownEntry(id="ddsc", title="廠商甲主機輪流重啟", windows=(window,), action=action,
                             description="凌晨廠商甲主機輪流重啟")
    return known.KnownHit(entry, window)


class KnownWindowTest(unittest.TestCase):
    """Knowledge-base windows: after datasource and never_silence, before everything else."""

    setUp = V2OrderingTest.setUp
    run_classify = V2OrderingTest.run_classify

    def test_known_hit_replies_without_analysis(self):
        d = self.run_classify(known_hit=known_hit())
        self.assertEqual((d.category, d.reaction, d.needs_analysis, d.auto_effect, d.severity),
                         (Category.KNOWN, Reaction.KNOWN, False, None, None))
        self.assertEqual(d.reply_text, known.known_reply(known_hit()))
        self.assertIn("固定維護窗", d.reply_text)

    def test_never_silence_beats_known_window(self):
        for kw in (dict(check=CheckSpec(key="c", never_silence=True)),
                   dict(rule=RuleMatch(rule_id="r", action="never_silence"))):
            with self.subTest(kw=kw):
                d = self.run_classify(known_hit=known_hit(), **kw)
                self.assertEqual((d.category, d.needs_analysis), (Category.CRITICAL, True))

    def test_datasource_beats_known_window(self):
        d = self.run_classify(known_hit=known_hit(), rule=RuleMatch(rule_id="elk", action="datasource"))
        self.assertEqual(d.category, Category.DATASOURCE)

    def test_known_window_beats_the_rest(self):
        cases = [dict(auto_hit=auto_hit(kind="noise")),
                 dict(rule=noise_rule()), dict(a=alert(parse_ok=False)),
                 dict(is_new_incident=False, incident=PENDING_INCIDENT)]
        for kw in cases:
            with self.subTest(kw=kw):
                d = self.run_classify(known_hit=known_hit(), **kw)
                self.assertEqual((d.category, d.needs_analysis, d.auto_effect),
                                 (Category.KNOWN, False, None))

    def test_known_window_does_not_suppress_magnitude(self):
        hit = known_hit()
        spike = self.run_classify(known_hit=hit, spike=True)
        self.assertEqual((spike.category, spike.needs_analysis), (Category.SPIKE, True))
        self.assertIn(hit.magnitude_note(), spike.reply_text)
        self.assertIn("廠商甲主機輪流重啟", hit.magnitude_note())
        accumulated = self.run_classify(known_hit=hit, accumulated=True)
        self.assertEqual((accumulated.category, accumulated.needs_analysis),
                         (Category.ACCUMULATED, True))
        self.assertIn(hit.magnitude_note(), accumulated.reply_text)

    def test_linked_error_replies_from_its_entry(self):
        hit = known_store.LinkHit(known_store.StoredEntry(id="ddsc", title="廠商甲重啟"), "k", linked_by="U1")
        d = self.run_classify(known_hit=hit)
        self.assertEqual((d.category, d.needs_analysis), (Category.KNOWN, False))
        self.assertEqual(d.reply_text, hit.reply_text())
        check = CheckSpec(key="c", never_silence=True)
        self.assertEqual(self.run_classify(known_hit=hit, check=check).category, Category.CRITICAL)

    def test_linked_error_spike_still_goes_to_analysis(self):
        hit = known_store.LinkHit(known_store.StoredEntry(id="ddsc", title="廠商甲重啟"), "k", linked_by="U1")
        d = self.run_classify(known_hit=hit, spike=True)
        self.assertEqual((d.category, d.needs_analysis), (Category.SPIKE, True))
        self.assertIn("廠商甲重啟", d.reply_text)
        self.assertIn("量級異常", d.reply_text)

    def test_context_hit_does_not_change_classification(self):
        d = self.run_classify(known_hit=known_hit(action="context"))
        self.assertEqual((d.category, d.needs_analysis), (Category.NEW, True))


if __name__ == "__main__":
    unittest.main()
