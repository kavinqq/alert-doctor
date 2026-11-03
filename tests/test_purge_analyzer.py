import unittest

from alert_doctor import analyzer

from alert_doctor.models import CheckSpec, ParsedAlert
from tests.test_analyzer import CH, NOW, AnalyzerBase, good


class PurgeAnalyzerTest(AnalyzerBase):
    def make_green(self, source="xoxb-source"):
        analyzer = self.make()
        analyzer.source_bot_token = source
        return analyzer

    def test_green_creates_purge_and_no_analysis_post(self):
        inc = self.incident()
        self.assertTrue(self.make_green().run_once())
        self.assertEqual([o.kind for o in self.outbox() if o.kind in ("analysis", "link")], [])
        done = self.store.read("SELECT analysis_state, completed_epoch FROM incidents WHERE id=?",
                               (inc.id,))[0]
        rows = self.store.purge_rows("incident_id=?", (inc.id,))
        self.assertEqual(done[0], "done")
        self.assertEqual([(r["channel"], r["generation"], r["state"]) for r in rows],
                         [(CH, done[1], "pending")])
        self.assertTrue(rows[0]["analysis_text"].strip())
        self.archive.record_verdict.assert_called()

    def test_not_green_posts_analysis_as_before(self):
        inc = self.incident()
        self.responses = [good(severity="medium")]
        self.make_green().run_once()
        self.assertEqual(self.store.purge_rows("incident_id=?", (inc.id,)), [])
        self.assertEqual([o.kind for o in self.outbox()], ["analysis"])

    def test_never_silence_not_purged(self):
        inc = self.incident()
        self.checks["c1"] = CheckSpec(key="c1", never_silence=True)
        self.make_green().run_once()
        self.assertEqual(self.store.purge_rows("incident_id=?", (inc.id,)), [])
        self.assertIn("analysis", [o.kind for o in self.outbox()])

    def test_disabled_posts_analysis(self):
        inc = self.incident()
        self.make_green(source=None).run_once()
        self.assertEqual(self.store.purge_rows("incident_id=?", (inc.id,)), [])
        self.assertEqual([o.kind for o in self.outbox()], ["analysis"])

    def test_report_for_skips_deleted_root(self):
        inc = self.incident(report=False)
        later = ParsedAlert(channel=CH, ts="1001.0", raw_text="r", parse_ok=True,
                            check_title="T", check_code="c1")
        self.store.insert_message(later, 2.0)
        self.store.attach(inc.id, later)
        (pid,) = self.store.complete_analysis_with_purge(
            inc.id, good(), "m", NOW - 1, channels=[CH], analysis_text="")
        self.store.add_purge_targets(pid, CH, "alert", ["1000.0"])
        self.store.set_target(pid, "alert", "1000.0", "deleted", epoch=NOW)
        report = self.make()._report_for(self.store.get_incident(inc.id), wait=False)
        self.assertEqual(report, {"channel": CH, "root_ts": "1001.0"})

    def test_other_channel_roots_skip_deleted_and_empty_channel(self):
        inc = self.incident()
        for ts, channel in (("2000.0", "C2"), ("2001.0", "C2"), ("3000.0", "C3")):
            a = ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True,
                            check_title="T", check_code="c1")
            self.store.insert_message(a, 3.0)
            self.store.attach(inc.id, a)
        (pid,) = self.store.complete_analysis_with_purge(
            inc.id, good(), "m", NOW - 1, channels=["C2"], analysis_text="")
        self.store.add_purge_targets(pid, "C2", "alert", ["2000.0"])
        self.store.set_target(pid, "alert", "2000.0", "deleted", epoch=NOW)
        (pid3,) = self.store.complete_analysis_with_purge(
            inc.id, good(), "m", NOW - 2, channels=["C3"], analysis_text="")
        self.store.add_purge_targets(pid3, "C3", "alert", ["3000.0"])
        self.store.set_target(pid3, "alert", "3000.0", "gone", epoch=NOW)
        roots = self.make()._other_channel_roots(self.store.get_incident(inc.id), CH)
        self.assertEqual(roots, [("C2", "2001.0")])

    def deleted(self, channel, *ts_list):
        (pid,) = self.store.complete_analysis_with_purge(
            1, good(), "m", NOW - len(self.store.purge_rows("1=1")) - 10, channels=[channel],
            analysis_text="")
        self.store.add_purge_targets(pid, channel, "alert", ts_list)
        for ts in ts_list:
            self.store.set_target(pid, "alert", ts, "deleted", epoch=NOW)

    def test_fallback_report_uses_other_channel_when_anchor_channel_is_empty(self):
        inc = self.incident(report=False)
        other = ParsedAlert(channel="C2", ts="2000.0", raw_text="r", parse_ok=True,
                            check_title="T", check_code="c1")
        self.store.insert_message(other, 2.0)
        self.store.attach(inc.id, other)
        self.deleted(CH, "1000.0")
        report = self.make()._report_for(self.store.get_incident(inc.id), wait=False)
        self.assertEqual(report, {"channel": "C2", "root_ts": "2000.0"})

    def test_no_surviving_alert_gives_rootless_report_and_no_link(self):
        inc = self.incident(report=False)
        self.deleted(CH, "1000.0")
        claimed = self.store.get_incident(inc.id)
        self.assertEqual(self.make()._report_for(claimed, wait=False),
                         {"channel": CH, "root_ts": None})
        self.responses = [good(severity="medium")]
        self.store.request_analysis(inc.id, fresh=True, now=NOW + 1)
        self.now = NOW + analyzer.REPORT_WAIT_SECONDS + 2
        self.make().run_once()
        kinds = [(o.kind, o.thread_ts) for o in self.outbox()]
        self.assertIn(("analysis", None), kinds)
        self.assertNotIn("link", [k for k, _ in kinds])


if __name__ == "__main__":
    unittest.main()
