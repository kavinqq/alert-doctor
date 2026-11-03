import json
import os
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from alert_doctor.archive import Archive, error_key
from alert_doctor.models import Incident, ParsedAlert

DAY = 86400.0
NOW = 1_800_000_000.0


def alert(ts="1800000000.000100", channel="C1", text="錯誤 password='abc' 發生"):
    return ParsedAlert(channel, ts, "raw " + text, True, "檢查", result_message=text)


def ts(epoch):
    return f"{int(epoch)}.100000"


def incident(iid=1, fp="fp1", count=1):
    return Incident(id=iid, fingerprint=fp, group_fp="g", check_code="c", check_title="檢查",
                    channel="C1", anchor_ts="1.0", first_epoch=NOW, last_epoch=NOW, count=count,
                    analysis_state="none")


VERDICT = {
    "category": "code_bug", "severity": "high", "confidence": 0.8, "summary": "摘要",
    "root_cause": "根因", "suggested_action": "做法", "fix_in_system": "sso", "needs_human": False,
    "evidence": [
        {"type": "code", "repo": "acme-sso", "file": "app/a.py", "line": 10},
        {"type": "code", "repo": "acme-sso", "file": "app/a.py", "line": 10},
        {"type": "elk", "key": "total"},
        {"type": "code", "repo": "acme-tx-gateway", "file": "b.py", "line": 3},
    ],
}


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "sub", "archive.db")
        self.arc = Archive(self.path)

    def q(self, sql, args=()):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in con.execute(sql, args)]
        finally:
            con.close()

    def record(self, a=None, inc=None, **kw):
        defaults = dict(category="new", severity=None, source_system="sso",
                        task_label="[SSO] M999", task_pk=118)
        defaults.update(kw)
        self.arc.record_occurrence(a or alert(), incident=inc or incident(), **defaults)

    def test_creates_parent_dir_wal_and_tables(self):
        self.assertEqual(self.q("PRAGMA journal_mode")[0]["journal_mode"], "wal")
        names = {r["name"] for r in self.q("SELECT name FROM sqlite_master")}
        for n in ("occurrences", "incidents", "code_refs", "evidence",
                  "v_file_hotspots", "v_recurring"):
            self.assertIn(n, names)

    def test_record_occurrence_row(self):
        self.record(degraded=True, backfilled=True, severity="high")
        row = self.q("SELECT * FROM occurrences")[0]
        self.assertEqual((row["channel"], row["ts"], row["task_pk"], row["task_label"]),
                         ("C1", "1800000000.000100", 118, "[SSO] M999"))
        self.assertEqual((row["incident_id"], row["fingerprint"], row["category"],
                          row["severity"], row["source_system"]), (1, "fp1", "new", "high", "sso"))
        self.assertEqual((row["degraded"], row["backfilled"]), (1, 1))
        self.assertEqual(row["epoch"], 1800000000.0001)

    def test_message_secrets_stripped_and_truncated(self):
        self.record(alert(text="{'password': 'abc'} " + "x" * 5000))
        msg = self.q("SELECT message FROM occurrences")[0]["message"]
        self.assertNotIn("abc", msg)
        self.assertLessEqual(len(msg), 2000)

    def test_duplicate_channel_ts_ignored_and_not_double_counted(self):
        self.record()
        self.record()
        self.assertEqual(len(self.q("SELECT * FROM occurrences")), 1)
        self.assertEqual(self.q("SELECT occurrence_count c FROM incidents")[0]["c"], 1)

    def test_incident_aggregates_across_occurrences_and_channels(self):
        self.record(alert(ts="1800000000.100000"))
        self.record(alert(ts="1800000100.100000", channel="C2"))
        inc = self.q("SELECT * FROM incidents")[0]
        self.assertEqual(inc["occurrence_count"], 2)
        self.assertEqual((inc["first_epoch"], inc["last_epoch"]), (1800000000.1, 1800000100.1))
        self.assertEqual(sorted(inc["channels"].split(",")), ["C1", "C2"])
        self.assertEqual((inc["task_pk"], inc["task_label"], inc["fingerprint"]),
                         (118, "[SSO] M999", "fp1"))

    def test_record_verdict_updates_incident_and_code_refs(self):
        self.record()
        self.arc.record_verdict(incident(), VERDICT, "sonnet", {"acme-sso": "abc123"}, NOW)
        inc = self.q("SELECT * FROM incidents")[0]
        self.assertEqual((inc["category"], inc["severity"], inc["fix_in_system"], inc["model"]),
                         ("code_bug", "high", "sso", "sonnet"))
        self.assertEqual((inc["summary"], inc["root_cause"], inc["suggested_action"],
                          inc["confidence"], inc["analyzed_epoch"]), ("摘要", "根因", "做法", 0.8, NOW))
        self.assertEqual(json.loads(inc["verdict_json"])["summary"], "摘要")
        self.assertEqual(inc["occurrence_count"], 1)
        refs = self.q("SELECT repo, file, line, sha FROM code_refs ORDER BY repo")
        self.assertEqual(refs, [
            {"repo": "acme-sso", "file": "app/a.py", "line": 10, "sha": "abc123"},
            {"repo": "acme-tx-gateway", "file": "b.py", "line": 3, "sha": None}])

    def test_new_format_verdict_fills_legacy_columns(self):
        self.record()
        verdict = {**{k: v for k, v in VERDICT.items()
                      if k not in ("summary", "root_cause", "suggested_action")},
                   "cause": "原因", "fix": ["改 a", "補發"]}
        self.arc.record_verdict(incident(), verdict, "sonnet", {}, NOW)
        inc = self.q("SELECT summary, root_cause, suggested_action FROM incidents")[0]
        self.assertEqual(dict(inc), {"summary": "原因", "root_cause": "原因",
                                     "suggested_action": "改 a；補發"})

    def test_record_verdict_without_prior_occurrence_creates_incident(self):
        self.arc.record_verdict(incident(5, "fp5"), VERDICT, "opus", {}, NOW)
        self.assertEqual(self.q("SELECT incident_id, fingerprint, model FROM incidents"),
                         [{"incident_id": 5, "fingerprint": "fp5", "model": "opus"}])

    def test_verdict_category_not_overwritten_by_later_occurrence(self):
        self.record()
        self.arc.record_verdict(incident(), VERDICT, "sonnet", {}, NOW)
        self.record(alert(ts="1800000200.1"), category="duplicate")
        self.assertEqual(self.q("SELECT category FROM incidents")[0]["category"], "code_bug")

    def test_record_verdict_twice_replaces_refs_without_duplicates(self):
        self.arc.record_verdict(incident(), VERDICT, "sonnet", {}, NOW)
        self.arc.record_verdict(incident(), VERDICT, "opus", {}, NOW + 1)
        self.assertEqual(len(self.q("SELECT * FROM code_refs")), 2)
        self.assertEqual(self.q("SELECT model FROM incidents")[0]["model"], "opus")

    def test_record_feedback_counts(self):
        self.record()
        self.arc.record_feedback(1, "agree", NOW)
        self.arc.record_feedback(1, "reject", NOW)
        self.arc.record_feedback(1, "reject", NOW)
        inc = self.q("SELECT agree_count a, reject_count r FROM incidents")[0]
        self.assertEqual((inc["a"], inc["r"]), (1, 2))

    def test_record_feedback_unknown_incident_never_raises(self):
        self.arc.record_feedback(404, "agree", NOW)

    def test_record_evidence(self):
        self.arc.record_evidence(1, "elk", {"total": 5}, NOW)
        row = self.q("SELECT * FROM evidence")[0]
        self.assertEqual((row["incident_id"], row["epoch"], row["kind"]), (1, NOW, "elk"))
        self.assertEqual(json.loads(row["json"]), {"total": 5})

    def test_hotspots(self):
        for iid, fp in ((1, "a"), (2, "b")):
            self.record(alert(ts=ts(NOW - DAY * iid)), inc=incident(iid, fp))
            self.arc.record_verdict(incident(iid, fp), VERDICT, "m", {}, NOW)
        old = incident(3, "c")
        self.record(alert(ts=ts(NOW - 100 * DAY)), inc=old)
        self.arc.record_verdict(old, VERDICT, "m", {}, NOW - 100 * DAY)
        rows = self.arc.hotspots(30, NOW)
        self.assertEqual([(r["repo"], r["file"], r["incidents"]) for r in rows],
                         [("acme-sso", "app/a.py", 2), ("acme-tx-gateway", "b.py", 2)])
        self.assertEqual(len(self.arc.hotspots(365, NOW)[0:1]), 1)
        self.assertEqual(self.arc.hotspots(365, NOW)[0]["incidents"], 3)
        only = self.arc.hotspots(30, NOW, repo="acme-tx-gateway")
        self.assertEqual([r["repo"] for r in only], ["acme-tx-gateway"])

    def test_recurring(self):
        for i in range(3):
            self.record(alert(ts=ts(NOW - 8 * DAY * i)), inc=incident(i + 1, "rep"))
        self.record(alert(ts=ts(NOW - 10), channel="C9"), inc=incident(9, "once"))
        rows = self.arc.recurring(30, NOW)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["fingerprint"], rows[0]["task_label"], rows[0]["occurrences"],
                          rows[0]["incidents"]), ("rep", "[SSO] M999", 3, 3))
        self.assertGreaterEqual(rows[0]["weeks"], 2)

    def test_views_exist_and_query(self):
        self.record()
        self.arc.record_verdict(incident(), VERDICT, "m", {}, NOW)
        self.assertEqual(len(self.q("SELECT * FROM v_file_hotspots")), 2)
        self.assertEqual(len(self.q("SELECT * FROM v_recurring")), 1)

    def test_writes_never_raise_and_log(self):
        with mock.patch.object(self.arc, "_connect", side_effect=sqlite3.OperationalError("boom")), \
                self.assertLogs("alert_doctor.archive", level="WARNING"):
            self.record()
            self.arc.record_verdict(incident(), VERDICT, "m", {}, NOW)
            self.arc.record_feedback(1, "agree", NOW)
            self.arc.record_evidence(1, "k", {}, NOW)

    def test_unusable_path_never_raises(self):
        blocker = os.path.join(self.dir, "file")
        open(blocker, "w").close()
        with self.assertLogs("alert_doctor.archive", level="WARNING"):
            bad = Archive(os.path.join(blocker, "x", "a.db"))
            bad.record_occurrence(alert(), incident=incident(), category="new", severity=None,
                                  source_system="s", task_label="", task_pk=None)
        self.assertEqual(bad.hotspots(30, NOW), [])

    def test_thread_safe_writes(self):
        def work(n):
            for i in range(20):
                self.record(alert(ts=ts(NOW + n * 100 + i)), inc=incident(n + 1, f"f{n}"))
        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(self.q("SELECT * FROM occurrences")), 80)

    def test_none_task_pk_and_incident(self):
        self.arc.record_occurrence(alert(), incident=None, category="unparsed", severity=None,
                                   source_system="", task_label="檢查", task_pk=None)
        row = self.q("SELECT incident_id, task_pk FROM occurrences")[0]
        self.assertEqual((row["incident_id"], row["task_pk"]), (None, None))
        self.assertEqual(self.q("SELECT * FROM incidents"), [])


TAIPEI_MIDNIGHT = NOW - 16 * 3600  # NOW is 16:00 in Taipei


class ErrorKeyTest(unittest.TestCase):
    def test_volatile_tokens_do_not_change_the_key(self):
        self.assertEqual(error_key(118, "c", 40, "GET /a 耗時 12 秒 id=7"),
                         error_key(118, "c", 40, "GET /a 耗時 30 秒 id=8"))

    def test_different_template_level_or_task_differ(self):
        base = error_key(118, "c", 40, "GET /a 逾時")
        self.assertNotEqual(base, error_key(118, "c", 40, "GET /b 逾時"))
        self.assertNotEqual(base, error_key(118, "c", 30, "GET /a 逾時"))
        self.assertNotEqual(base, error_key(119, "c", 40, "GET /a 逾時"))

    def test_error_key_merges_keyword_samples_by_structure(self):
        head = "['SSO']服務中出現異常關鍵字「['M999']」，請立即查看系統狀況！"

        def hit(path, uuid, host):
            return (f"{head}「{{'server_hostname': '{host}', 'request_path': '{path}', "
                    f"'request_body': b'{{\"ino\": \"A123456789\"}}', 'req_uuid': '{uuid}', "
                    f"'code': 'M999'}}」")
        a = error_key(118, "c", 40, hit("/user/a/", "7LpHE5s0UP8r", "prod-app-oa-91"))
        self.assertEqual(a, error_key(118, "c", 40, hit("/user/a/", "pWwYHDcZU4o3", "prod-app-tw-92")))
        self.assertNotEqual(a, error_key(118, "c", 40, hit("/user/b/", "7LpHE5s0UP8r", "prod-app-oa-91")))

    def test_task_pk_wins_over_check_code(self):
        self.assertEqual(error_key(118, "c1", 40, "x"), error_key(118, "c2", 40, "x"))

    def test_falls_back_to_check_code(self):
        self.assertEqual(error_key(None, "c1", 40, "x"), error_key(None, "c1", 40, "x"))
        self.assertNotEqual(error_key(None, "c1", 40, "x"), error_key(None, "c2", 40, "x"))
        self.assertNotEqual(error_key(None, "118", None, "x"), error_key(118, None, None, "x"))

    def test_no_identity_is_none(self):
        self.assertIsNone(error_key(None, None, 40, "x"))
        self.assertIsNone(error_key(None, "", 40, "x"))

    def test_source_system_is_part_of_the_key(self):
        self.assertNotEqual(error_key(None, "c1", 40, "x", "sso"), error_key(None, "c1", 40, "x", "cms"))
        self.assertNotEqual(error_key(118, "c1", 40, "x", "sso"), error_key(118, "c1", 40, "x", "cms"))
        self.assertEqual(error_key(118, "c1", 40, "x", "sso"), error_key(118, "c1", 40, "x", "sso"))
        self.assertNotEqual(error_key(118, "c1", 40, "x"), error_key(118, "c1", 40, "x", "sso"))


class OccurrenceKeyTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "archive.db")

    def q(self, sql, args=()):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in con.execute(sql, args)]
        finally:
            con.close()

    def keyed(self, epoch, text="逾時 3 秒"):
        return ParsedAlert("C1", ts(epoch), "raw", True, "檢查", check_code="code", level=40,
                           result_message=text)

    def test_record_stores_error_key_and_level_and_reports_insert(self):
        arc = Archive(self.path)
        a = self.keyed(NOW)
        self.assertTrue(arc.record_occurrence(a, incident=None, category="new", severity=None,
                                              source_system="s", task_label="L", task_pk=118))
        self.assertFalse(arc.record_occurrence(a, incident=None, category="new", severity=None,
                                               source_system="s", task_label="L", task_pk=118))
        row = self.q("SELECT error_key, level, truncated, reliable FROM occurrences")[0]
        self.assertEqual(row, {"error_key": error_key(118, "code", 40, "逾時 3 秒", "s"), "level": 40,
                               "truncated": 0, "reliable": 1})

    def test_truncated_alert_is_marked_unreliable(self):
        arc = Archive(self.path)
        a = ParsedAlert("C1", ts(NOW), "raw", True, "檢查", check_code="code", level=40,
                        result_message="逾時", truncated=True)
        arc.record_occurrence(a, incident=None, category="new", severity=None,
                              source_system="s", task_label="L", task_pk=118)
        self.assertEqual(self.q("SELECT truncated, reliable FROM occurrences"),
                         [{"truncated": 1, "reliable": 0}])

    def test_recording_again_refreshes_a_changed_key(self):
        arc = Archive(self.path)
        kw = dict(incident=None, category="new", severity=None, source_system="s", task_label="L",
                  task_pk=118)
        arc.record_occurrence(self.keyed(NOW, "前段"), **kw)
        self.assertFalse(arc.record_occurrence(self.keyed(NOW, "前段後段"), **kw))
        self.assertEqual(self.q("SELECT error_key FROM occurrences"),
                         [{"error_key": error_key(118, "code", 40, "前段後段", "s")}])

    def test_failed_write_returns_none(self):
        arc = Archive(self.path)
        with mock.patch.object(arc, "_connect", side_effect=sqlite3.OperationalError("x")), \
                self.assertLogs("alert_doctor.archive", level="WARNING"):
            self.assertIsNone(arc.record_occurrence(
                self.keyed(NOW), incident=None, category="new", severity=None,
                source_system="s", task_label="L", task_pk=118))

    def old_archive_with_row(self):
        con = sqlite3.connect(self.path)
        con.executescript(
            "CREATE TABLE occurrences (id INTEGER PRIMARY KEY, channel TEXT NOT NULL, "
            "channel_name TEXT, ts TEXT NOT NULL, epoch REAL NOT NULL, task_pk INTEGER, "
            "task_label TEXT, check_code TEXT, check_title TEXT, source_system TEXT, "
            "category TEXT, severity TEXT, incident_id INTEGER, fingerprint TEXT, message TEXT, "
            "degraded INTEGER NOT NULL DEFAULT 0, backfilled INTEGER NOT NULL DEFAULT 0, "
            "UNIQUE (channel, ts));")
        con.execute("INSERT INTO occurrences (channel, ts, epoch, task_pk, check_code, message) "
                    "VALUES ('C1', ?, ?, 118, 'code', '逾時 3 秒')", (ts(NOW), int(NOW) + 0.1))
        con.commit()
        con.close()

    def test_migration_adds_columns_and_leaves_old_rows_unkeyed(self):
        self.old_archive_with_row()
        Archive(self.path)
        Archive(self.path)
        self.assertEqual(self.q("SELECT error_key, level, truncated, reliable FROM occurrences"),
                         [{"error_key": None, "level": None, "truncated": None, "reliable": None}])
        indexes = {r["name"] for r in self.q("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("ix_occ_key_epoch", indexes)

    def test_recording_an_existing_unkeyed_row_fills_its_key(self):
        self.old_archive_with_row()
        arc = Archive(self.path)
        self.assertFalse(arc.record_occurrence(
            self.keyed(NOW), incident=None, category="historical", severity=None,
            source_system="s", task_label="L", task_pk=118))
        row = self.q("SELECT error_key, level, category FROM occurrences")[0]
        self.assertEqual(row, {"error_key": error_key(118, "code", 40, "逾時 3 秒", "s"),
                               "level": 40, "category": None})


class OccurrenceStatsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.arc = Archive(os.path.join(self.dir, "archive.db"))
        self.key = error_key(118, "code", 40, "逾時", "s")

    def add(self, epoch, text="逾時", channel="C1"):
        a = ParsedAlert(channel, ts(epoch), "raw", True, "檢查", check_code="code", level=40,
                        result_message=text)
        self.arc.record_occurrence(a, incident=None, category="new", severity=None,
                                   source_system="s", task_label="L", task_pk=118)

    def test_windows_first_and_last_before(self):
        for epoch in (NOW - 40 * DAY, NOW - 20 * DAY, NOW - 5 * DAY, TAIPEI_MIDNIGHT - 60,
                      TAIPEI_MIDNIGHT + 60, NOW - 60, NOW):
            self.add(epoch)
        self.add(NOW - 30, text="別的錯誤")
        stats = self.arc.occurrence_stats(self.key, NOW + 1, before=NOW)
        self.assertEqual({k: stats[k] for k in ("today", "d7", "d30")},
                         {"today": 3, "d7": 5, "d30": 6})
        self.assertEqual(stats["first_epoch"], int(NOW - 40 * DAY) + 0.1)
        self.assertEqual(stats["last_before_epoch"], int(NOW - 60) + 0.1)

    def test_last_before_defaults_to_now(self):
        self.add(NOW - 100)
        self.add(NOW - 10)
        self.assertEqual(self.arc.occurrence_stats(self.key, NOW)["last_before_epoch"],
                         int(NOW - 10) + 0.1)

    def test_unknown_key(self):
        self.assertEqual(self.arc.occurrence_stats("nope", NOW),
                         {"today": 0, "d7": 0, "d30": 0, "first_epoch": None,
                          "last_before_epoch": None})

    def test_read_failure_is_none(self):
        with mock.patch.object(self.arc, "_connect", side_effect=sqlite3.OperationalError("x")), \
                self.assertLogs("alert_doctor.archive", level="WARNING"):
            self.assertIsNone(self.arc.occurrence_stats(self.key, NOW))

    def test_key_of_occurrence(self):
        self.add(NOW)
        self.assertEqual(self.arc.key_of("C1", ts(NOW)), (self.key, int(NOW) + 0.1))
        self.assertIsNone(self.arc.key_of("C1", "1.0"))


if __name__ == "__main__":
    unittest.main()
