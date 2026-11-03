import unittest

from alert_doctor import mentions
from alert_doctor.config import Config, ChannelSpec, SystemSpec
from alert_doctor.models import CheckSpec


class FakeSlack:
    def __init__(self, users=None, fail=False):
        self.users = users or {}
        self.fail = fail
        self.lookups = []

    def lookup_user_by_email(self, token, email):
        self.lookups.append(email)
        if self.fail:
            raise OSError("network down")
        return self.users.get(email)


class ResolveOwnersTest(unittest.TestCase):
    def setUp(self):
        mentions.clear_cache()
        self.addCleanup(mentions.clear_cache)

    def test_ids_groups_and_emails(self):
        slack = FakeSlack({"a@b.c": "U7"})
        got = mentions.resolve_owners(slack, "tok", ("U1", "W2", "S3", "a@b.c", "<@U9>"))
        self.assertEqual(got, ("<@U1>", "<@W2>", "<!subteam^S3>", "<@U7>", "<@U9>"))

    def test_email_resolved_once(self):
        slack = FakeSlack({"a@b.c": "U7"})
        mentions.resolve_owners(slack, "tok", ("a@b.c",))
        mentions.resolve_owners(slack, "tok", ("a@b.c",))
        self.assertEqual(slack.lookups, ["a@b.c"])

    def test_unknown_email_skipped_without_failing(self):
        slack = FakeSlack({})
        with self.assertLogs("alert_doctor.mentions", "WARNING"):
            self.assertEqual(mentions.resolve_owners(slack, "tok", ("x@b.c", "U1")), ("<@U1>",))

    def test_lookup_error_skipped_and_retried_later(self):
        slack = FakeSlack({"a@b.c": "U7"}, fail=True)
        with self.assertLogs("alert_doctor.mentions", "WARNING"):
            self.assertEqual(mentions.resolve_owners(slack, "tok", ("a@b.c",)), ())
        slack.fail = False
        self.assertEqual(mentions.resolve_owners(slack, "tok", ("a@b.c",)), ("<@U7>",))

    def test_garbage_owner_skipped(self):
        with self.assertLogs("alert_doctor.mentions", "WARNING"):
            self.assertEqual(mentions.resolve_owners(FakeSlack(), "tok", ("bob",)), ())

    def test_slack_without_lookup_skips_emails(self):
        with self.assertLogs("alert_doctor.mentions", "WARNING"):
            self.assertEqual(mentions.resolve_owners(object(), "tok", ("a@b.c", "U1")), ("<@U1>",))


class OwnersForTest(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(
            workspace_url="https://x", channels=(ChannelSpec("C1", "c", ("pxy",)),),
            systems={"pxy": SystemSpec("pxy", (), ("USYS",), "pxy", {})})

    def test_check_owners_win(self):
        check = CheckSpec(key="k", owners=("UCHK",))
        self.assertEqual(mentions.owners_for(self.cfg, "pxy", check), ("UCHK",))

    def test_system_owners_fallback(self):
        self.assertEqual(mentions.owners_for(self.cfg, "pxy", CheckSpec(key="k")), ("USYS",))
        self.assertEqual(mentions.owners_for(self.cfg, "pxy", None), ("USYS",))

    def test_unknown_system_is_empty(self):
        self.assertEqual(mentions.owners_for(self.cfg, "nope", None), ())

    def test_warm_resolves_all_emails(self):
        mentions.clear_cache()
        cfg = Config(workspace_url="https://x", channels=self.cfg.channels,
                     systems={"pxy": SystemSpec("pxy", (), ("a@b.c",), "pxy", {})})
        slack = FakeSlack({"a@b.c": "U1", "c@d.e": "U2"})
        mentions.warm(slack, "tok", cfg, {"k": CheckSpec(key="k", owners=("c@d.e",))})
        self.assertEqual(sorted(slack.lookups), ["a@b.c", "c@d.e"])
        mentions.clear_cache()


class FirstMessageOwnersTest(unittest.TestCase):
    class Cfg:
        def __init__(self, default_owners):
            self.default_owners = default_owners
            self.systems = {"pxy": SystemSpec("pxy", (), ("USYS", "UD1"), "pxy", {})}

    def test_defaults_then_check_owners_deduped_in_order(self):
        cfg = self.Cfg(("UD1", "UD2"))
        check = CheckSpec(key="k", owners=("UCHK", "UD2"))
        self.assertEqual(mentions.first_message_owners(cfg, "pxy", check),
                         ("UD1", "UD2", "UCHK"))

    def test_falls_back_to_system_owners(self):
        cfg = self.Cfg(("UD1",))
        self.assertEqual(mentions.first_message_owners(cfg, "pxy", None), ("UD1", "USYS"))

    def test_cfg_without_default_owners(self):
        cfg = Config(workspace_url="https://x", channels=(ChannelSpec("C1", "c", ("pxy",)),),
                     systems={"pxy": SystemSpec("pxy", (), ("USYS",), "pxy", {})})
        stripped = type("C", (), {"systems": cfg.systems})()
        self.assertEqual(mentions.first_message_owners(stripped, "pxy", None), ("USYS",))

    def test_unknown_system_only_defaults(self):
        self.assertEqual(mentions.first_message_owners(self.Cfg(("UD1",)), "nope", None), ("UD1",))


if __name__ == "__main__":
    unittest.main()
