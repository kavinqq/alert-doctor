import plistlib
import unittest
from pathlib import Path

LAUNCHD = Path(__file__).resolve().parent.parent / "deploy" / "launchd"
PYTHON = "/Users/you/.pyenv/versions/3.11.4/bin/python3"
CONFIG = "/Users/you/alert-doctor/config.toml"


def load(name):
    with open(LAUNCHD / f"local.alert-doctor.{name}.plist", "rb") as f:
        return plistlib.load(f)


class LaunchdTest(unittest.TestCase):
    def test_every_plist_runs_cli_with_absolute_paths(self):
        for path in LAUNCHD.glob("*.plist"):
            with open(path, "rb") as f:
                plist = plistlib.load(f)
            self.assertEqual(plist["Label"], path.stem)
            args = plist["ProgramArguments"]
            self.assertEqual(args[:3], [PYTHON, "-m", "alert_doctor"], path.name)
            self.assertEqual(args[-2:], ["--config", CONFIG], path.name)

    def test_tuner_hourly(self):
        plist = load("tuner")
        self.assertEqual(plist["ProgramArguments"][3], "tuner")
        self.assertEqual(plist["StartInterval"], 3600)

    def test_tuner_runs_at_load_so_fresh_install_reports_heartbeat(self):
        self.assertIs(load("tuner")["RunAtLoad"], True)

    def test_weekly_report_monday_0930(self):
        plist = load("weekly")
        self.assertEqual(plist["ProgramArguments"][3:6], ["report", "--weekly", "--post"])
        self.assertEqual(plist["StartCalendarInterval"], {"Weekday": 1, "Hour": 9, "Minute": 30})


if __name__ == "__main__":
    unittest.main()
