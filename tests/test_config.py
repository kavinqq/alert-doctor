import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from alert_doctor.config import (
    ChannelSpec, Config, RepoSpec, SystemSpec, get_secret, load_config, unknown_check_systems,
)
from alert_doctor.models import CheckSpec

MINIMAL = (
    'workspace_url = "https://example.slack.com"\n'
    '[[channels]]\nid = "C0XXXXXXX"\nname = "alerts-pxy"\nsystems = ["pxy", "fastpxy"]\n'
    '[systems.pxy]\nrepos = ["acme-tx-gateway"]\nowners = ["U1"]\nelk_project = "pxy"\n'
    '[systems.fastpxy]\nrepos = ["acme-proxy"]\nelk_project = "middleware"\n'
    '[repos.acme-tx-gateway]\npath = "/r/acme-tx-gateway"\ndeploy_ref = "origin/main"\n'
    '[repos.acme-proxy]\npath = "/r/acme-proxy"\n'
)


class GetSecretTest(unittest.TestCase):
    def test_env_var_wins_over_keychain(self):
        with mock.patch.dict(os.environ, {"ALERT_DOCTOR_BOT_TOKEN": "xoxb-env"}), \
                mock.patch("subprocess.run") as run:
            self.assertEqual(get_secret("alert-doctor", "bot_token"), "xoxb-env")
        run.assert_not_called()

    def test_env_name_from_service_when_no_account(self):
        with mock.patch.dict(os.environ, {"ALERT_DOCTOR_OPS_ELK": "pw"}):
            self.assertEqual(get_secret("ops-elk"), "pw")

    def test_keychain_command_with_account(self):
        done = subprocess.CompletedProcess([], 0, stdout="tok\n", stderr="")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("subprocess.run", return_value=done) as run:
            self.assertEqual(get_secret("alert-doctor", "app_token"), "tok")
        self.assertEqual(
            run.call_args.args[0],
            ["security", "find-generic-password", "-s", "alert-doctor", "-a", "app_token", "-w"],
        )

    def test_keychain_command_without_account(self):
        done = subprocess.CompletedProcess([], 0, stdout="pw\n", stderr="")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("subprocess.run", return_value=done) as run:
            get_secret("ops-elk")
        self.assertEqual(run.call_args.args[0], ["security", "find-generic-password", "-s", "ops-elk", "-w"])

    def test_keychain_miss_raises_with_hint(self):
        done = subprocess.CompletedProcess([], 44, stdout="", stderr="not found")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("subprocess.run", return_value=done):
            with self.assertRaises(RuntimeError) as cm:
                get_secret("alert-doctor", "bot_token")
        self.assertIn("ALERT_DOCTOR_BOT_TOKEN", str(cm.exception))

    def test_empty_keychain_value_raises(self):
        done = subprocess.CompletedProcess([], 0, stdout="\n", stderr="")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("subprocess.run", return_value=done):
            with self.assertRaises(RuntimeError):
                get_secret("alert-doctor", "bot_token")


class LoadConfigTest(unittest.TestCase):
    def _load(self, text, name="config.toml"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return load_config(str(path)), Path(tmp.name).resolve()

    def test_defaults(self):
        cfg, _ = self._load(MINIMAL)
        self.assertEqual(cfg.report_channel, "")
        self.assertEqual(cfg.keychain_service, "alert-doctor")
        self.assertEqual(cfg.elk_url, "http://10.0.0.100:9200")
        self.assertEqual(cfg.elk_user, "elastic")
        self.assertEqual(cfg.elk_keychain_service, "ops-elk")
        self.assertEqual(cfg.elk_timeout, 10)
        self.assertEqual((cfg.model, cfg.escalation_model), ("sonnet", "opus"))
        self.assertEqual((cfg.daily_limit, cfg.daily_limit_escalation), (80, 15))
        self.assertEqual((cfg.llm_timeout, cfg.verdict_reuse_hours), (600, 24))
        self.assertEqual((cfg.idle_minutes, cfg.spike_window_minutes), (60, 15))

    def test_relative_paths_resolve_against_config_dir(self):
        cfg, base = self._load('db_path = "data/ad.db"\nrules_path = "rules.toml"\n' + MINIMAL)
        self.assertEqual(cfg.db_path, str(base / "data/ad.db"))
        self.assertEqual(cfg.rules_path, str(base / "rules.toml"))
        self.assertEqual(cfg.checks_path, str(base / "checks.toml"))
        self.assertEqual(cfg.runs_dir, str(base / "runs"))
        self.assertEqual(cfg.log_dir, str(base / "logs"))

    def test_absolute_path_kept(self):
        cfg, _ = self._load('db_path = "/var/lib/ad.db"\n' + MINIMAL)
        self.assertEqual(cfg.db_path, "/var/lib/ad.db")

    def test_overrides(self):
        cfg, _ = self._load('model = "haiku"\ndaily_limit = 5\nelk_timeout = 3\n' + MINIMAL)
        self.assertEqual((cfg.model, cfg.daily_limit, cfg.elk_timeout), ("haiku", 5, 3))

    def test_missing_required_key(self):
        with self.assertRaises(ValueError) as cm:
            self._load('[[channels]]\nid = "C1"\nname = "a"\nsystems = []\n')
        self.assertIn("workspace_url", str(cm.exception))

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load('daily_limt = 5\n' + MINIMAL)
        self.assertIn("daily_limt", str(cm.exception))

    def test_example_file_loads(self):
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        cfg = load_config(str(example))
        self.assertEqual(len(cfg.channels), 4)
        self.assertEqual(cfg.channels[1].name, "alerts-pxy")
        self.assertEqual(cfg.channels[1].systems, ("pxy", "fastpxy"))
        self.assertEqual(set(cfg.systems), {"cms", "pxy", "fastpxy", "sso", "oa", "pe"})
        self.assertEqual(cfg.systems["oa"].elk_project, "OA")
        self.assertEqual(cfg.systems["pe"].elk_project, "pe")
        self.assertEqual(cfg.systems["pe"].repos, ("acme-web",))
        self.assertEqual(cfg.repos["acme-web"].path, "/Users/you/acme-web")
        self.assertEqual(cfg.systems["pxy"].owners, ())
        self.assertEqual(cfg.systems["cms"].repos, ("acme-backend", "acme-frontend"))
        self.assertEqual(cfg.repos["acme-proxy"].path, "/Users/you/acme-proxy")

    def test_permalink(self):
        cfg, _ = self._load(MINIMAL)
        self.assertEqual(
            cfg.permalink("C0XXXXXXX", "1760841234.567890"),
            "https://example.slack.com/archives/C0XXXXXXX/p1760841234567890",
        )

    def test_permalink_tolerates_trailing_slash(self):
        cfg, _ = self._load(MINIMAL.replace("example.slack.com", "a.slack.com/"))
        self.assertEqual(cfg.permalink("C1", "1.2"), "https://a.slack.com/archives/C1/p12")

    def test_channels_systems_repos(self):
        cfg, _ = self._load(MINIMAL)
        self.assertEqual(cfg.channels, (ChannelSpec("C0XXXXXXX", "alerts-pxy", ("pxy", "fastpxy")),))
        self.assertEqual(cfg.channel_ids, frozenset({"C0XXXXXXX"}))
        self.assertEqual(cfg.channel("C0XXXXXXX").name, "alerts-pxy")
        self.assertIsNone(cfg.channel("CNOPE"))
        pxy = cfg.systems["pxy"]
        self.assertEqual((pxy.key, pxy.repos, pxy.owners, pxy.elk_project),
                         ("pxy", ("acme-tx-gateway",), ("U1",), "pxy"))
        self.assertEqual(pxy.error_query, {"bool": {"filter": [
            {"term": {"project": "pxy"}}, {"term": {"log.levelname": "ERROR"}}]}})
        self.assertEqual(cfg.systems["fastpxy"].owners, ())
        self.assertEqual(cfg.repos["acme-tx-gateway"], RepoSpec("acme-tx-gateway", "/r/acme-tx-gateway", "origin/main"))
        self.assertEqual(cfg.repos["acme-proxy"].deploy_ref, "origin/HEAD")

    def test_custom_error_query(self):
        text = MINIMAL.replace('elk_project = "pxy"\n', 'elk_project = "pxy"\nerror_query = \'{"match_all":{}}\'\n')
        cfg, _ = self._load(text)
        self.assertEqual(cfg.systems["pxy"].error_query, {"match_all": {}})

    def test_v2_flat_defaults_and_path(self):
        cfg, base = self._load(MINIMAL)
        self.assertEqual(cfg.mirrors_dir, str(base / "mirrors"))
        self.assertEqual(cfg.topology_path, str(base / "topology.toml"))
        self.assertEqual((cfg.shadow_sample_rate, cfg.auto_rule_ttl_days), (0.1, 7))

    def test_v3_defaults(self):
        cfg, _ = self._load(MINIMAL)
        self.assertEqual(cfg.default_owners, ())
        self.assertTrue(cfg.first_reply_immediate)
        self.assertEqual((cfg.update_every_minutes_early, cfg.update_early_window_minutes,
                          cfg.update_every_minutes_late), (1, 10, 5))
        self.assertEqual((cfg.budget_elk_per_min, cfg.budget_elk_reserved_critical), (30, 10))
        self.assertEqual((cfg.budget_slack_per_min, cfg.budget_slack_reserved_critical,
                          cfg.budget_slack_reserved_first), (20, 4, 4))
        self.assertEqual(cfg.budget_llm_per_min, 5)
        self.assertEqual((cfg.overload_intake_per_min, cfg.overload_active_incidents,
                          cfg.overload_exit_minutes), (15, 10, 5))
        self.assertEqual(cfg.backfill_lag_seconds, 120)

    def test_w2c_defaults_and_paths_resolve_against_config_dir(self):
        cfg, base = self._load(MINIMAL)
        self.assertEqual(cfg.watchdog_snapshot_path, str(base / "watchdog_snapshot/tasks.json"))
        self.assertEqual(cfg.archive_db_path, str(base / "data/error_archive.db"))
        self.assertEqual((cfg.batch_settle_seconds, cfg.update_min_interval_minutes), (20, 2))

    def test_known_path_resolves_against_config_dir(self):
        cfg, base = self._load(MINIMAL)
        self.assertEqual(cfg.known_path, str(base / "known.toml"))
        cfg, base = self._load('known_path = "kb/known.toml"\n' + MINIMAL)
        self.assertEqual(cfg.known_path, str(base / "kb/known.toml"))

    def test_example_known_path(self):
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        self.assertEqual(load_config(str(example)).known_path, str(example.parent / "known.toml"))

    def test_w2c_overrides(self):
        cfg, _ = self._load('batch_settle_seconds = 5\nupdate_min_interval_minutes = 3\n'
                            'archive_db_path = "/abs/a.db"\n' + MINIMAL)
        self.assertEqual((cfg.batch_settle_seconds, cfg.update_min_interval_minutes), (5, 3))
        self.assertEqual(cfg.archive_db_path, "/abs/a.db")

    def test_v3_overrides_and_default_owners_become_tuple(self):
        cfg, _ = self._load('default_owners = ["U1", "U2"]\nbudget_llm_per_min = 2\n'
                            'first_reply_immediate = false\n' + MINIMAL)
        self.assertEqual(cfg.default_owners, ("U1", "U2"))
        self.assertEqual(cfg.budget_llm_per_min, 2)
        self.assertFalse(cfg.first_reply_immediate)

    def test_known_editors_default_to_default_owners(self):
        cfg, _ = self._load('default_owners = ["U1", "U2"]\n' + MINIMAL)
        self.assertEqual(cfg.known_editors, ("U1", "U2"))
        cfg, _ = self._load('default_owners = ["U1"]\nknown_editors = ["U3"]\n' + MINIMAL)
        self.assertEqual(cfg.known_editors, ("U3",))
        self.assertEqual(self._load(MINIMAL)[0].known_editors, ())

    def test_overload_untag_minutes(self):
        self.assertEqual(self._load(MINIMAL)[0].overload_untag_minutes, 30)
        self.assertEqual(self._load('overload_untag_minutes = 10\n' + MINIMAL)[0].overload_untag_minutes, 10)
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        self.assertEqual(load_config(str(example)).overload_untag_minutes, 30)

    def test_example_default_owners(self):
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        self.assertEqual(load_config(str(example)).default_owners, ("U01CCCCCCCC", "U01DDDDDDDD"))

    def test_no_channel_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load('workspace_url = "https://x.slack.com"\n')
        self.assertIn("channel", str(cm.exception))

    def test_legacy_channel_id_rejected(self):
        with self.assertRaises(ValueError):
            self._load('channel_id = "C1"\n' + MINIMAL)

    def test_undefined_system_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load(MINIMAL.replace('"fastpxy"]', '"ghost"]', 1))
        self.assertIn("ghost", str(cm.exception))

    def test_undefined_repo_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._load(MINIMAL.replace('repos = ["acme-proxy"]', 'repos = ["ghost-repo"]'))
        self.assertIn("ghost-repo", str(cm.exception))

    def test_channel_missing_field_rejected(self):
        with self.assertRaises(ValueError):
            self._load(MINIMAL.replace('name = "alerts-pxy"\n', ""))

    def test_config_is_frozen(self):
        cfg, _ = self._load(MINIMAL)
        self.assertIsInstance(cfg, Config)
        with self.assertRaises(Exception):
            cfg.model = "x"



class UnknownCheckSystemsTest(unittest.TestCase):
    def test_flags_only_checks_with_undefined_system(self):
        cfg = Config(workspace_url="https://x", systems={"pxy": SystemSpec("pxy", (), (), "pxy", {})})
        checks = {"a": CheckSpec(key="a", system="pxy"), "b": CheckSpec(key="b"),
                  "c": CheckSpec(key="c", system="sso")}
        problems = unknown_check_systems(cfg, checks)
        self.assertEqual(len(problems), 1)
        self.assertIn("c", problems[0])
        self.assertIn("sso", problems[0])


if __name__ == "__main__":
    unittest.main()
