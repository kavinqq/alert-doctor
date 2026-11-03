import json
import unittest

from alert_doctor import autorules as ar
from alert_doctor import auto_texts
from alert_doctor.store import Store

DAY = 86400
NOW = 2_000_000_000.0


def ensure_verdict_reused(store):
    with store.tx() as db:
        columns = {r[1] for r in db.execute("PRAGMA table_info(incidents)")}
        if "verdict_reused" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN verdict_reused INTEGER DEFAULT 0")


class Base(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")
        ensure_verdict_reused(self.s)
        ar.ensure_schema(self.s)
        self._next_incident = 1000

    def incident(self, fp, category, confidence=0.9, at=NOW - DAY, state="done", reused=0,
                 **extra):
        verdict = {"category": category, "confidence": confidence, **extra}
        with self.s.tx() as db:
            db.execute(
                "INSERT INTO incidents (fingerprint, group_fp, check_code, check_title, channel,"
                " anchor_ts, first_epoch, last_epoch, count, analysis_state, verdict,"
                " completed_epoch, verdict_reused) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fp, "g", "c", "t", "C1", str(at), at, at, 1, state, json.dumps(verdict), at,
                 reused))

    def shadow(self, fp="fp", hits=12, created=NOW - 10 * DAY, kind="noise", day_offsets=None):
        """`hits` distinct incidents, spread over `day_offsets` (days after creation)."""
        rule = ar.propose_from_human(self.s, fp, created, "U1")
        with self.s.tx() as db:
            db.execute("UPDATE auto_rules SET kind=? WHERE id=?", (kind, rule.id))
        offsets = day_offsets if day_offsets is not None else range(8)
        offsets = list(offsets)
        for i in range(hits):
            self._next_incident += 1
            ar.record_shadow_hit(self.s, rule.id, incident_id=self._next_incident,
                                 epoch=created + offsets[i % len(offsets)] * DAY + 3600)
        return rule.id

    def state(self, rule_id):
        return self.s.read("SELECT state FROM auto_rules WHERE id=?", (rule_id,))[0][0]

    def activate(self, fp="fp"):
        rid = self.shadow(fp)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")
        return rid


class ProposeVerdictTests(Base):
    def test_three_noise_make_shadow_noise_rule(self):
        for _ in range(3):
            self.incident("fp", "transient")
        rules = ar.propose_from_verdicts(self.s, NOW)
        self.assertEqual([(r.fingerprint, r.kind, r.state, r.source) for r in rules],
                         [("fp", "noise", "shadow", "verdict")])

    def test_two_noise_not_enough(self):
        for _ in range(2):
            self.incident("fp", "noise")
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_low_confidence_ignored(self):
        for _ in range(3):
            self.incident("fp", "noise", confidence=0.5)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_old_verdicts_ignored(self):
        for _ in range(3):
            self.incident("fp", "noise", at=NOW - 20 * DAY)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_not_done_ignored(self):
        for _ in range(3):
            self.incident("fp", "noise", state="pending")
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_known_needs_single_incident(self):
        self.incident("fp", "infra")
        rules = ar.propose_from_verdicts(self.s, NOW)
        self.assertEqual(rules[0].kind, "known")

    def test_real_verdict_vetoes_noise(self):
        for _ in range(5):
            self.incident("fp", "noise")
        self.incident("fp", "code_bug")
        rules = ar.propose_from_verdicts(self.s, NOW)
        self.assertEqual([r.kind for r in rules], ["known"])

    def test_unconfident_or_human_verdict_vetoes_noise(self):
        for _ in range(3):
            self.incident("a", "noise")
        self.incident("a", "new", confidence=0.4)
        for _ in range(3):
            self.incident("b", "noise")
        self.incident("b", "noise", needs_human=True)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_existing_live_rule_skips_but_expired_or_revoked_do_not(self):
        for _ in range(3):
            self.incident("fp", "noise")
        self.assertEqual(len(ar.propose_from_verdicts(self.s, NOW)), 1)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])
        with self.s.tx() as db:
            db.execute("UPDATE auto_rules SET state='expired'")
        self.assertEqual(len(ar.propose_from_verdicts(self.s, NOW)), 1)

    def test_blocked_fingerprint_never_gets_rule(self):
        for _ in range(3):
            self.incident("fp", "noise")
        self.incident("fp2", "infra")
        ar.revoke(self.s, "fp", "x", NOW - 100)
        ar.revoke(self.s, "fp2", "x", NOW - 100)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_block_expires_after_days(self):
        self.incident("fp", "infra")
        ar.revoke(self.s, "fp", "x", NOW - 31 * DAY)
        self.assertEqual(len(ar.propose_from_verdicts(self.s, NOW)), 1)

    def test_reused_verdicts_do_not_count(self):
        self.incident("fp", "noise")
        self.incident("fp", "noise", reused=1)
        self.incident("fp", "noise", reused=1)
        self.incident("k", "infra", reused=1)
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])

    def test_garbage_verdict_is_skipped(self):
        with self.s.tx() as db:
            db.execute(
                "INSERT INTO incidents (fingerprint, group_fp, check_title, channel, anchor_ts,"
                " first_epoch, last_epoch, count, analysis_state, verdict, completed_epoch)"
                " VALUES ('fp','g','t','C','1',1,1,1,'done','not json',?)", (NOW - 10,))
        self.assertEqual(ar.propose_from_verdicts(self.s, NOW), [])


class HumanProposeTests(Base):
    def test_human_rule_is_shadow(self):
        rule = ar.propose_from_human(self.s, "fp", NOW, "U9")
        self.assertEqual((rule.state, rule.source), ("shadow", "human"))
        self.assertIn("U9", rule.reason)

    def test_blocked_returns_none_and_creates_nothing(self):
        ar.revoke(self.s, "fp", "x", NOW)
        self.assertIsNone(ar.propose_from_human(self.s, "fp", NOW + 1, "U9"))
        self.assertEqual(self.s.read("SELECT COUNT(*) FROM auto_rules WHERE state='shadow'")[0][0], 0)

    def test_idempotent_while_live(self):
        a = ar.propose_from_human(self.s, "fp", NOW, "U1")
        b = ar.propose_from_human(self.s, "fp", NOW + 1, "U2")
        self.assertEqual(a.id, b.id)


class MatchTests(Base):
    def test_no_rule(self):
        self.assertIsNone(ar.match(self.s, "fp", NOW, 0.1))

    def test_shadow_hit_never_samples(self):
        self.shadow()
        hit = ar.match(self.s, "fp", NOW, 1.0, rng=lambda: 0.0)
        self.assertEqual((hit.active, hit.sample), (False, False))

    def test_active_sampling_uses_rng(self):
        self.activate()
        self.assertTrue(ar.match(self.s, "fp", NOW, 0.1, rng=lambda: 0.05).sample)
        self.assertFalse(ar.match(self.s, "fp", NOW, 0.1, rng=lambda: 0.1).sample)
        self.assertTrue(ar.match(self.s, "fp", NOW, 0.1).active)

    def test_expired_active_rule_does_not_match_even_before_sweep(self):
        self.activate()
        later = NOW + 8 * DAY
        self.assertIsNone(ar.match(self.s, "fp", later, 0.1))

    def test_blocked_fingerprint_does_not_match_even_if_rule_row_is_active(self):
        rid = self.activate()
        with self.s.tx() as db:
            db.execute("INSERT INTO fp_blocks VALUES ('fp', ?, 'x')", (NOW + DAY,))
        self.assertEqual(self.state(rid), "active")
        self.assertIsNone(ar.match(self.s, "fp", NOW, 0.1))

    def test_other_fingerprint_unaffected(self):
        self.activate("a")
        self.assertIsNone(ar.match(self.s, "b", NOW, 0.1))


class PromoteTests(Base):
    def test_promotes_when_all_conditions_met(self):
        rid = self.shadow()
        result = ar.promote_and_expire(self.s, NOW)
        self.assertEqual([r.id for r in result["promoted"]], [rid])
        row = self.s.read("SELECT state, activated, expires FROM auto_rules")[0]
        self.assertEqual(row, ("active", NOW, NOW + 7 * DAY))

    def test_needs_min_days(self):
        rid = self.shadow(created=NOW - 6 * DAY)
        self.assertEqual(ar.promote_and_expire(self.s, NOW)["promoted"], [])
        self.assertEqual(self.state(rid), "shadow")

    def test_needs_min_distinct_incidents(self):
        rid = self.shadow(hits=9)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")
        ar.record_shadow_hit(self.s, rid, incident_id=1, epoch=NOW - 5 * DAY)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")

    def test_many_hits_without_days_still_waits(self):
        rid = self.shadow(hits=10_000, created=NOW - DAY, day_offsets=[0])
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_hits_count_per_incident_not_per_message(self):
        rid = self.shadow(hits=0)
        for i in range(40):
            ar.record_shadow_hit(self.s, rid, incident_id=7 + i % 4,
                                 epoch=NOW - 10 * DAY + (i % 8) * DAY + 3600)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_needs_five_distinct_taipei_days(self):
        rid = self.shadow(hits=30, day_offsets=[0, 2, 5, 7])
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_hit_days_must_span_seven_calendar_days(self):
        rid = self.shadow(hits=30, day_offsets=[0, 1, 2, 3, 4, 5])
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_hits_before_creation_ignored(self):
        rid = self.shadow(hits=30, day_offsets=[-3, -2, -1, 0, 1, 7])
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_disagreeing_fresh_verdict_revokes(self):
        for kwargs in ({"category": "code_bug"}, {"category": "noise", "confidence": 0.5},
                       {"category": "transient", "needs_human": True}):
            with self.subTest(**kwargs):
                fp = f"fp-{kwargs}"
                rid = self.shadow(fp)
                self.incident(fp, **kwargs, at=NOW - 2 * DAY)
                result = ar.promote_and_expire(self.s, NOW)
                self.assertEqual(result["promoted"], [])
                self.assertEqual(self.state(rid), "revoked")
                self.assertEqual(
                    self.s.read("SELECT reason FROM auto_rules WHERE id=?", (rid,))[0][0],
                    "後續分析不同意")

    def test_reused_or_older_disagreeing_verdict_ignored(self):
        rid = self.shadow()
        self.incident("fp", "code_bug", at=NOW - 2 * DAY, reused=1)
        self.incident("fp", "code_bug", at=NOW - 11 * DAY)
        self.incident("fp", "infra", at=NOW - 2 * DAY, state="pending")
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")

    def test_agreeing_fresh_verdicts_join_reject_denominator(self):
        rid = self.shadow()
        ar.record_sample_result(self.s, rid, False)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")
        for _ in range(20):
            self.incident("fp", "noise", at=NOW - 2 * DAY)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")

    def test_known_rule_agrees_with_real_category(self):
        rid = self.shadow(kind="known")
        self.incident("fp", "infra", at=NOW - 2 * DAY)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")

    def test_reject_rate_includes_sampled_denominator(self):
        rid = self.shadow()
        for _ in range(20):
            ar.record_sample_result(self.s, rid, True)
        ar.record_sample_result(self.s, rid, False)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "active")

    def test_reject_rate_at_or_above_threshold_blocks_promotion(self):
        rid = self.shadow()
        for _ in range(18):
            ar.record_sample_result(self.s, rid, True)
        ar.record_sample_result(self.s, rid, False)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_single_rejection_without_samples_blocks(self):
        rid = self.shadow()
        ar.record_sample_result(self.s, rid, False)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_blocked_fingerprint_not_promoted(self):
        rid = self.shadow()
        with self.s.tx() as db:
            db.execute("INSERT INTO fp_blocks VALUES ('fp', ?, 'x')", (NOW + DAY,))
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_active_expires(self):
        rid = self.activate()
        self.assertEqual(ar.promote_and_expire(self.s, NOW + 6 * DAY)["expired"], [])
        result = ar.promote_and_expire(self.s, NOW + 7 * DAY)
        self.assertEqual([r.id for r in result["expired"]], [rid])
        self.assertEqual(self.state(rid), "expired")
        self.assertEqual(ar.promote_and_expire(self.s, NOW + 8 * DAY)["expired"], [])

    def test_counters(self):
        rid = self.shadow(hits=0)
        ar.record_shadow_hit(self.s, rid)
        ar.record_sample_result(self.s, rid, True)
        ar.record_sample_result(self.s, rid, False)
        rule = ar.match(self.s, "fp", NOW, 0.1).rule
        self.assertEqual((rule.shadow_hits, rule.sampled, rule.sampled_agree, rule.rejections),
                         (1, 1, 1, 1))


class RevokeInvalidateTests(Base):
    def test_revoke_takes_effect_immediately_and_blocks(self):
        rid = self.activate()
        ar.revoke(self.s, "fp", "human ❌", NOW)
        self.assertEqual(self.state(rid), "revoked")
        self.assertIsNone(ar.match(self.s, "fp", NOW, 0.1))
        self.assertTrue(ar.is_blocked(self.s, "fp", NOW + 29 * DAY))
        self.assertFalse(ar.is_blocked(self.s, "fp", NOW + 30 * DAY + 1))
        self.assertEqual(self.s.read("SELECT fingerprint, note FROM counterexamples"),
                         [("fp", "human ❌")])
        self.assertEqual(self.s.read("SELECT reason FROM auto_rules")[0][0], "human ❌")

    def test_revoke_also_kills_shadow_and_leaves_other_fp(self):
        shadow = self.shadow("fp")
        other = self.activate("other")
        ar.revoke(self.s, "fp", "x", NOW)
        self.assertEqual(self.state(shadow), "revoked")
        self.assertEqual(self.state(other), "active")

    def test_revoke_without_rules_still_blocks(self):
        ar.revoke(self.s, "fp", "x", NOW)
        self.assertTrue(ar.is_blocked(self.s, "fp", NOW))

    def test_revoke_never_shortens_existing_block(self):
        ar.revoke(self.s, "fp", "x", NOW, block_days=30)
        ar.revoke(self.s, "fp", "y", NOW, block_days=1)
        self.assertTrue(ar.is_blocked(self.s, "fp", NOW + 20 * DAY))

    def test_invalidate_revokes_active_immediately_without_block(self):
        rid = self.activate()
        ar.invalidate(self.s, "fp", "量級升級", NOW)
        self.assertEqual(self.state(rid), "revoked")
        self.assertIsNone(ar.match(self.s, "fp", NOW, 0.1))
        self.assertFalse(ar.is_blocked(self.s, "fp", NOW))

    def test_invalidate_leaves_shadow(self):
        rid = self.shadow()
        ar.invalidate(self.s, "fp", "x", NOW)
        self.assertEqual(self.state(rid), "shadow")

    def test_revoked_rule_cannot_be_promoted_back(self):
        rid = self.shadow()
        ar.revoke(self.s, "fp", "x", NOW)
        ar.promote_and_expire(self.s, NOW)
        self.assertEqual(self.state(rid), "revoked")


class TextTests(unittest.TestCase):
    def test_texts_are_traditional_chinese_and_mention_key_facts(self):
        rule = ar.AutoRule(7, "fp", "noise", "human", "active", 0, 0, 0, 0, 0, 0, 0, "")
        self.assertIn("#7", auto_texts.auto_noise(rule, False))
        self.assertIn("抽樣", auto_texts.auto_noise(rule, True))
        self.assertNotIn("抽樣", auto_texts.auto_noise(rule, False))
        self.assertIn("http://x/p", auto_texts.auto_known(rule, "http://x/p"))
        self.assertIn("abc123", auto_texts.revoked_ack("abc123"))

        class Inc:
            check_title = "逾時"
        text = auto_texts.accumulated(
            Inc, {"errors": 80, "rate": 0.12, "duration_minutes": 9, "hosts": 3})
        for needle in ("逾時", "80", "12.0%", "9", "3"):
            self.assertIn(needle, text)
        auto_texts.accumulated(Inc, {"errors": None, "rate": None})


class SampleTrackingTests(Base):
    def test_settle_once_records_sample_result(self):
        rid = self.activate()
        ar.record_sample(self.s, rid, 7, "C1", "1.0", NOW)
        self.assertEqual(ar.sample_rule(self.s, 7), rid)
        self.assertEqual(ar.settle_sample(self.s, 7, agreed=True), rid)
        self.assertIsNone(ar.settle_sample(self.s, 7, agreed=False))
        row = self.s.read("SELECT sampled, sampled_agree, rejections FROM auto_rules WHERE id=?", (rid,))
        self.assertEqual(row, [(1, 1, 0)])

    def test_settle_disagree_counts_rejection(self):
        rid = self.activate()
        ar.record_sample(self.s, rid, 7, "C1", "1.0", NOW)
        ar.settle_sample(self.s, 7, agreed=False)
        self.assertEqual(self.s.read("SELECT rejections FROM auto_rules WHERE id=?", (rid,)), [(1,)])

    def test_unsampled_incident(self):
        self.assertIsNone(ar.sample_rule(self.s, 99))
        self.assertIsNone(ar.settle_sample(self.s, 99, agreed=True))

    def test_record_sample_idempotent(self):
        rid = self.activate()
        ar.record_sample(self.s, rid, 7, "C1", "1.0", NOW)
        ar.record_sample(self.s, rid, 7, "C1", "2.0", NOW)
        self.assertEqual(self.s.read("SELECT COUNT(*) FROM auto_samples"), [(1,)])


class InvalidateForSystemsTests(Base):
    def test_only_active_rules_of_matching_systems(self):
        with self.s.tx() as db:
            for fp, system in (("fa", "pxy"), ("fb", "sso"), ("fc", "pxy")):
                db.execute(
                    "INSERT INTO incidents (fingerprint, group_fp, check_title, channel, anchor_ts,"
                    " first_epoch, last_epoch, count, source_system) VALUES (?,?,?,?,?,?,?,?,?)",
                    (fp, "g", "t", "C1", "1.0", NOW, NOW, 1, system))
        a, b = self.activate("fa"), self.activate("fb")
        c = self.shadow("fc")
        changed = ar.invalidate_for_systems(self.s, ("pxy",), "repo SHA 變更", NOW)
        self.assertEqual(changed, ["fa"])
        self.assertEqual((self.state(a), self.state(b), self.state(c)), ("revoked", "active", "shadow"))
        self.assertFalse(ar.is_blocked(self.s, "fa", NOW))

    def test_no_systems_is_noop(self):
        self.assertEqual(ar.invalidate_for_systems(self.s, (), "x", NOW), [])


if __name__ == "__main__":
    unittest.main()
