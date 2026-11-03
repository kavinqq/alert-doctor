import json
import unittest
from unittest import mock

from alert_doctor import feedback
from alert_doctor.config import ChannelSpec, Config, SystemSpec
from alert_doctor.models import ParsedAlert
from alert_doctor.store import Store

CH = "C1"


class FakeSlack:
    def __init__(self):
        self.posts = []

    def post_message(self, token, channel, text, thread_ts=None):
        self.posts.append((channel, text, thread_ts))
        return "9.9"


class Fakes:
    def __init__(self):
        self.revoked, self.proposed, self.samples, self.analysis = [], [], [], []
        self.unhealthy, self.archived = [], []

    def request_analysis(self, incident_id, **kwargs):
        self.analysis.append((incident_id, kwargs))

    def kwargs(self, **extra):
        values = dict(
            revoke=lambda store, fp, reason, now: self.revoked.append((fp, reason, now)),
            propose_from_human=lambda store, fp, now, user: self.proposed.append((fp, user)),
            settle_sample=lambda store, incident_id, agreed: self.samples.append((incident_id, agreed)),
            revoked_ack=lambda short: f"已撤銷自動規則 {short}",
            request_analysis=self.request_analysis,
            mark_unhealthy=lambda store, fp, since, until: self.unhealthy.append((fp, since, until)),
            record_feedback=lambda incident_id, kind, now: self.archived.append((incident_id, kind, now)))
        values.update(extra)
        return values


class FeedbackTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.cfg = Config(
            workspace_url="https://x.slack.com",
            channels=(ChannelSpec(CH, "c", ("pxy",)),),
            systems={"pxy": SystemSpec("pxy", (), ("U1", "S2", "a@b.c"), "pxy", {})})
        alert = ParsedAlert(channel=CH, ts="100.0", raw_text="r", parse_ok=True, check_title="t")
        self.store.insert_message(alert, 100.0)
        inc = self.store.create_incident(alert, "fp1", "g", source_system="pxy")
        self.inc = inc
        self.store.index_reply(CH, "101.0", "100.0", inc.id, "triage")
        self.store.index_reply(CH, "102.0", "100.0", inc.id, "sample")
        self.slack = FakeSlack()
        self.fakes = Fakes()

    def react(self, ts, name, user="U9"):
        self.store.add_reaction_inbox(CH, ts, user, name, 200.0)

    def run_inbox(self, **extra):
        return feedback.process_inbox(
            self.store, self.cfg, self.slack, "tok", 300.0, **self.fakes.kwargs(**extra))

    def feedback_rows(self):
        return self.store.read("SELECT incident_id, user, kind FROM feedback")

    def acks(self):
        return [(c, json.loads(p)["text"], t, k) for c, p, t, k in self.store.read(
            "SELECT channel, payload, thread_ts, kind FROM outbox ORDER BY id")]

    def test_x_on_bot_reply_revokes_and_acks(self):
        self.react("101.0", "x")
        self.assertEqual(self.run_inbox(), 1)
        self.assertEqual(self.fakes.revoked, [("fp1", "human ❌", 300.0)])
        self.assertEqual(self.fakes.analysis, [(self.inc.id, {"fresh": True})])
        self.assertEqual(self.fakes.unhealthy, [("fp1", self.inc.first_epoch, 300.0)])
        self.assertEqual(self.feedback_rows(), [(self.inc.id, "U9", "reject")])
        self.assertEqual(self.slack.posts, [])
        channel, text, thread, kind = self.acks()[0]
        self.assertEqual((channel, thread, kind), (CH, "100.0", "feedback"))
        self.assertIn("已撤銷自動規則 fp1", text)
        self.assertIn("<@U1>", text)
        self.assertIn("<!subteam^S2>", text)
        self.assertNotIn("a@b.c", text)
        self.assertEqual(self.fakes.samples, [(self.inc.id, False)])

    def test_x_on_alert_or_foreign_message_does_not_revoke(self):
        self.react("100.0", "x")
        self.react("555.0", "x")
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(self.fakes.revoked, [])
        self.assertEqual(self.fakes.analysis, [])
        self.assertEqual(self.fakes.unhealthy, [])
        self.assertEqual(self.feedback_rows(), [])

    def test_other_reactions_ignored_but_marked(self):
        for name in ("eyes", "+1", "tada"):
            self.react("101.0", name)
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(self.fakes.revoked, [])
        self.assertEqual(self.feedback_rows(), [])
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM reactions_inbox WHERE processed=0"), [(0,)])

    def test_check_mark_records_agree(self):
        self.react("101.0", "white_check_mark")
        self.assertEqual(self.run_inbox(), 1)
        self.assertEqual(self.feedback_rows(), [(self.inc.id, "U9", "agree")])
        self.assertEqual(self.fakes.samples, [(self.inc.id, True)])

    def test_mute_on_alert_proposes_rule(self):
        self.react("100.0", "mute")
        self.assertEqual(self.run_inbox(), 1)
        self.assertEqual(self.fakes.proposed, [("fp1", "U9")])

    def test_mute_on_bot_reply_ignored(self):
        self.react("101.0", "mute")
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(self.fakes.proposed, [])

    def test_idempotent(self):
        self.react("101.0", "x")
        self.react("100.0", "mute")
        self.run_inbox()
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(len(self.fakes.revoked), 1)
        self.assertEqual(len(self.fakes.proposed), 1)
        self.assertEqual(len(self.feedback_rows()), 1)
        self.assertEqual(len(self.acks()), 1)

    def test_request_analysis_without_fresh_falls_back(self):
        calls = []
        self.react("101.0", "x")
        self.run_inbox(request_analysis=calls.append)
        self.assertEqual(calls, [self.inc.id])

    def test_same_user_x_twice_acts_once(self):
        self.react("101.0", "x")
        self.react("102.0", "x")
        self.run_inbox()
        self.react("101.0", "x")
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(len(self.fakes.revoked), 1)
        self.assertEqual(len(self.fakes.analysis), 1)
        self.assertEqual(len(self.acks()), 1)
        self.assertEqual(self.feedback_rows(), [(self.inc.id, "U9", "reject")])

    def test_second_user_x_records_without_reacting_again(self):
        self.react("101.0", "x", user="U9")
        self.react("101.0", "x", user="U8")
        self.assertEqual(self.run_inbox(), 2)
        self.assertEqual(len(self.fakes.revoked), 1)
        self.assertEqual(len(self.acks()), 1)
        self.assertEqual(sorted(self.feedback_rows()),
                         [(self.inc.id, "U8", "reject"), (self.inc.id, "U9", "reject")])

    def test_same_user_check_mark_twice_records_once(self):
        self.react("101.0", "white_check_mark")
        self.react("101.0", "white_check_mark")
        self.assertEqual(self.run_inbox(), 1)
        self.assertEqual(self.feedback_rows(), [(self.inc.id, "U9", "agree")])

    def test_custom_mention_resolver(self):
        self.react("101.0", "x")
        self.run_inbox(mention=lambda owners: "@team")
        self.assertTrue(self.acks()[0][1].endswith("@team"))

    def test_ack_failure_does_not_reprocess(self):
        self.react("101.0", "x")
        with mock.patch.object(self.store, "enqueue_reply", side_effect=RuntimeError("down")):
            self.run_inbox()
        self.assertEqual(self.run_inbox(), 0)
        self.assertEqual(len(self.fakes.revoked), 1)

    def test_check_owners_override_system_owners(self):
        from alert_doctor.models import CheckSpec
        self.react("101.0", "x")
        checks = {"t": CheckSpec(key="t", owners=("UCHECK",))}
        self.run_inbox(checks=checks)
        text = self.acks()[0][1]
        self.assertIn("<@UCHECK>", text)
        self.assertNotIn("<@U1>", text)

    def test_agree_and_reject_go_to_archive(self):
        self.react("101.0", "white_check_mark", user="U8")
        self.react("101.0", "x")
        self.react("100.0", "mute")
        self.run_inbox()
        self.assertEqual(self.fakes.archived, [(self.inc.id, "agree", 300.0),
                                               (self.inc.id, "reject", 300.0)])

    def test_archive_failure_does_not_block_feedback(self):
        self.react("101.0", "x")
        self.run_inbox(record_feedback=lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))
        self.assertEqual(self.feedback_rows(), [(self.inc.id, "U9", "reject")])
        self.assertEqual(len(self.acks()), 1)

    def test_default_archive_from_config_and_unopenable_archive_ignored(self):
        from types import SimpleNamespace
        fake = mock.Mock()
        cfg = SimpleNamespace(**{**vars(self.cfg), "archive_db_path": "/x/arch.db"})
        feedback._archives.clear()
        self.addCleanup(feedback._archives.clear)
        with mock.patch.dict("sys.modules", {"alert_doctor.archive": fake}):
            self.assertIs(feedback._archive_recorder(cfg), fake.Archive.return_value.record_feedback)
            fake.Archive.assert_called_once_with("/x/arch.db")
            feedback._archives.clear()
            fake.Archive.side_effect = RuntimeError("locked")
            self.assertIsNone(feedback._archive_recorder(cfg))
        self.assertIsNone(feedback._archive_recorder(SimpleNamespace()))

    def test_ensure_schema_repeatable(self):
        feedback.ensure_schema(self.store)
        feedback.ensure_schema(self.store)



class RealAutorulesTest(unittest.TestCase):
    """No fakes: the signatures feedback uses must be the real autorules/auto_texts ones."""

    def setUp(self):
        from alert_doctor import autorules
        self.ar = autorules
        self.store = Store(":memory:")
        autorules.ensure_schema(self.store)
        self.cfg = Config(workspace_url="https://x.slack.com", channels=(ChannelSpec(CH, "c", ("pxy",)),),
                          systems={"pxy": SystemSpec("pxy", (), (), "pxy", {})})
        alert = ParsedAlert(channel=CH, ts="100.0", raw_text="r", parse_ok=True, check_title="t")
        self.store.insert_message(alert, 100.0)
        self.inc = self.store.create_incident(alert, "fp1", "g", source_system="pxy")
        self.store.index_reply(CH, "101.0", "100.0", self.inc.id, "sample")
        self.store.index_reply(CH, "103.0", "100.0", self.inc.id, "analysis")
        self.slack = FakeSlack()

    def run_inbox(self):
        # The archive is a separate file on disk; these tests are about autorules only.
        return feedback.process_inbox(self.store, self.cfg, self.slack, "tok", 300.0,
                                      record_feedback=lambda *a: None)

    def make_active_sample(self):
        rule = self.ar.propose_from_human(self.store, "fp1", 0.0, "U1")
        with self.store.tx() as db:
            db.execute("UPDATE auto_rules SET state='active', expires=? WHERE id=?", (10_000.0, rule.id))
        self.ar.record_sample(self.store, rule.id, self.inc.id, CH, "100.0", 100.0)
        return rule.id

    def test_check_mark_on_analysis_of_sample_counts_once(self):
        rid = self.make_active_sample()
        self.store.add_reaction_inbox(CH, "103.0", "U9", "white_check_mark", 200.0)
        self.store.add_reaction_inbox(CH, "101.0", "U8", "white_check_mark", 201.0)
        self.assertEqual(self.run_inbox(), 2)
        self.assertEqual(self.store.read("SELECT sampled, sampled_agree FROM auto_rules WHERE id=?", (rid,)),
                         [(1, 1)])

    def test_x_revokes_blocks_and_requests_analysis(self):
        rid = self.make_active_sample()
        self.store.add_reaction_inbox(CH, "101.0", "U9", "x", 200.0)
        self.run_inbox()
        self.assertEqual(self.store.read("SELECT state, rejections FROM auto_rules WHERE id=?", (rid,)),
                         [("revoked", 1)])
        self.assertTrue(self.ar.is_blocked(self.store, "fp1", 300.0))
        self.assertEqual(self.store.get_incident(self.inc.id).analysis_state, "pending")
        self.assertIn("fp1", self.store.read("SELECT payload FROM outbox")[0][0])
        hours = self.store.read("SELECT healthy FROM fp_hourly WHERE fingerprint='fp1'")
        self.assertTrue(hours)
        self.assertTrue(all(h == 0 for (h,) in hours))

    def test_mute_creates_shadow_rule_with_user(self):
        self.store.add_reaction_inbox(CH, "100.0", "U9", "mute", 200.0)
        self.run_inbox()
        self.assertEqual(self.store.read("SELECT state, source, reason FROM auto_rules"),
                         [("shadow", "human", "U9 按 🔇")])

    def test_mute_on_blocked_fingerprint_does_nothing(self):
        self.ar.revoke(self.store, "fp1", "human ❌", 100.0)
        self.store.add_reaction_inbox(CH, "100.0", "U9", "mute", 200.0)
        self.run_inbox()
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM auto_rules WHERE state != 'revoked'"), [(0,)])


if __name__ == "__main__":
    unittest.main()
