import json
import tempfile
import unittest
from pathlib import Path

from alert_doctor.models import ParsedAlert
from alert_doctor.watchdog import (
    KEYWORD_QUERY_CODES, alert_label, elk_index_for, elk_query_from_kwargs, load_snapshot,
)

CRON = {"minute": "3-59/5", "hour": "*", "day_of_week": "*", "day_of_month": "*",
        "month_of_year": "*", "timezone": "Asia/Taipei"}

FIXTURE = {
    "exported_at": "2026-10-20T05:37:02+00:00",
    "tasks": [
        {"id": 7, "label": "[SSO] 檢查 M999", "enabled": True, "only_notify_group": True,
         "check_script_id": 2, "cron": CRON, "args": [],
         "kwargs": {"interval": 5, "keywords": ["M999"], "log_tags": ["SSO"],
                    "password": "hunter2", "sql_pwad": "x", "url": "http://u:p@h/x"},
         "groups": [1, 2]},
        {"id": 8, "label": "停用的", "enabled": False, "check_script_id": 99,
         "cron": CRON, "kwargs": {}, "groups": []},
    ],
    "check_scripts": [{"id": 2, "code": "CODE2", "title": "檢查 log", "script": "a.py"}],
    "groups": [
        {"id": 1, "title": "g1", "level": 40, "channels": [10, 11], "users": [20, 21, 22]},
        {"id": 2, "title": "g2", "level": 40, "channels": [11], "users": [20, 23]},
    ],
    "channels": [{"id": 10, "channel_id": "C1", "name": "a"},
                 {"id": 11, "channel_id": "C2", "name": "b"}],
    "users": [
        {"id": 20, "user_id": "U1", "is_deleted": False},
        {"id": 21, "user_id": "U2", "is_deleted": True},
        {"id": 22, "user_id": "U3", "is_deleted": False},
        {"id": 23, "user_id": "U4"},
    ],
}


def write(data) -> str:
    d = tempfile.mkdtemp()
    path = Path(d) / "tasks.json"
    path.write_text(json.dumps(data))
    return str(path)


def alert(vkwargs=None, title="檢查 log"):
    extra = {"vkwargs": vkwargs} if vkwargs is not None else {}
    return ParsedAlert("C1", "1.0", "raw", True, title, extra=extra)


class LoadSnapshotTest(unittest.TestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(load_snapshot("/nonexistent/tasks.json"))

    def test_corrupt_file_returns_none(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "tasks.json"
        p.write_text("{not json")
        self.assertIsNone(load_snapshot(str(p)))

    def test_task_fields_and_group_resolution(self):
        snap = load_snapshot(write(FIXTURE))
        self.assertEqual(snap.exported_at, "2026-10-20T05:37:02+00:00")
        t = snap.task(7)
        self.assertEqual((t.id, t.label, t.enabled), (7, "[SSO] 檢查 M999", True))
        self.assertEqual(t.cron, "3-59/5 * * * *")
        self.assertEqual((t.check_code, t.check_title), ("CODE2", "檢查 log"))
        self.assertEqual(t.channels, ("C1", "C2"))
        self.assertEqual(t.owners, ("U1", "U3", "U4"))

    def test_deleted_users_skipped_and_duplicates_removed(self):
        t = load_snapshot(write(FIXTURE)).task(7)
        self.assertNotIn("U2", t.owners)
        self.assertEqual(len(t.owners), len(set(t.owners)))

    def test_secrets_stripped_from_kwargs(self):
        kw = load_snapshot(write(FIXTURE)).task(7).kwargs
        self.assertEqual(kw["password"], "<redacted>")
        self.assertEqual(kw["sql_pwad"], "<redacted>")
        self.assertEqual(kw["url"], "http://<redacted>@h/x")
        self.assertEqual(kw["keywords"], ["M999"])

    def test_task_without_check_script_has_empty_code(self):
        t = load_snapshot(write(FIXTURE)).task(8)
        self.assertEqual((t.check_code, t.check_title, t.enabled), ("", "", False))

    def test_unknown_or_none_pk(self):
        snap = load_snapshot(write(FIXTURE))
        self.assertIsNone(snap.task(999))
        self.assertIsNone(snap.task(None))

    def test_task_for_alert_uses_crontab_task_pk(self):
        snap = load_snapshot(write(FIXTURE))
        self.assertEqual(snap.task_for_alert(alert({"crontab_task_pk": 7})).id, 7)
        self.assertEqual(snap.task_for_alert(alert({"crontab_task_pk": "7"})).id, 7)
        self.assertIsNone(snap.task_for_alert(alert({"crontab_task_pk": 5})))
        self.assertIsNone(snap.task_for_alert(alert({})))
        self.assertIsNone(snap.task_for_alert(alert(None)))
        self.assertIsNone(snap.task_for_alert(alert({"crontab_task_pk": "abc"})))

    def test_null_lists_tolerated(self):
        data = dict(FIXTURE, groups=None, users=None, channels=None, check_scripts=None)
        data["tasks"] = [dict(FIXTURE["tasks"][0], groups=None, kwargs=None)]
        t = load_snapshot(write(data)).task(7)
        self.assertEqual((t.channels, t.owners, t.kwargs), ((), (), {}))

    def test_all_tasks(self):
        self.assertEqual([t.id for t in load_snapshot(write(FIXTURE)).tasks()], [7, 8])


class AlertLabelTest(unittest.TestCase):
    def test_label_when_task_known_else_check_title(self):
        snap = load_snapshot(write(FIXTURE))
        self.assertEqual(alert_label(alert({"crontab_task_pk": 7}), snap), "[SSO] 檢查 M999")
        self.assertEqual(alert_label(alert({"crontab_task_pk": 5}), snap), "檢查 log")
        self.assertEqual(alert_label(alert({"crontab_task_pk": 7}), None), "檢查 log")


class ElkQueryTest(unittest.TestCase):
    def test_keywords_and_tags(self):
        q = elk_query_from_kwargs({"keywords": ["M999", "x"], "log_tags": ["SSO"]})["bool"]
        self.assertIn({"range": {"@timestamp": {"gte": "{{from}}", "lte": "{{to}}"}}}, q["filter"])
        self.assertIn({"terms": {"log.tags": ["SSO"]}}, q["filter"])
        self.assertEqual(q["must"], [{"match_phrase": {"log.message": "M999"}},
                                     {"match_phrase": {"log.message": "x"}}])
        self.assertNotIn("must_not", q)

    def test_no_tags_and_except_keywords(self):
        q = elk_query_from_kwargs({"keywords": ["a"], "except_keywords": ["b"]})["bool"]
        self.assertEqual(len(q["filter"]), 1)
        self.assertEqual(q["must_not"], [{"match_phrase": {"log.message": "b"}}])

    def test_string_keyword_accepted(self):
        q = elk_query_from_kwargs({"keywords": "M999"})["bool"]
        self.assertEqual(q["must"], [{"match_phrase": {"log.message": "M999"}}])

    def test_none_without_keywords(self):
        self.assertIsNone(elk_query_from_kwargs({}))
        self.assertIsNone(elk_query_from_kwargs({"keywords": []}))
        self.assertIsNone(elk_query_from_kwargs({"keywords": None}))

    def test_query_placeholders_work_with_elk_client(self):
        from alert_doctor.elk_client import _substitute
        q = _substitute(elk_query_from_kwargs({"keywords": ["a"]}),
                        {"from": "F", "to": "T"})
        self.assertEqual(q["bool"]["filter"][0]["range"]["@timestamp"], {"gte": "F", "lte": "T"})

    def test_index(self):
        self.assertEqual(elk_index_for({}), "log*")

    def test_only_check_log_message_derives_a_keyword_query(self):
        self.assertIn("MDlNB90WVnwW-YUfdtieV", KEYWORD_QUERY_CODES)
        self.assertNotIn("riJG42iS-Dl7JNwYe5cP5", KEYWORD_QUERY_CODES)


class RealSnapshotTest(unittest.TestCase):
    def test_real_snapshot_if_present(self):
        path = Path(__file__).resolve().parent.parent / "watchdog_snapshot" / "tasks.json"
        if not path.exists():
            self.skipTest("本機沒有 watchdog 快照")
        task = load_snapshot(str(path)).task(118)
        self.assertIn("M999", task.label)
        self.assertIn(task.check_code, KEYWORD_QUERY_CODES)


if __name__ == "__main__":
    unittest.main()
