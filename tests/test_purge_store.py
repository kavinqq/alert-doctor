import json
import unittest
from unittest import mock

from alert_doctor import slack_io
from alert_doctor.dryrun import DryRunSlack
from alert_doctor.models import ParsedAlert
from alert_doctor.store import Store

NOW = 1_760_000_000.0


def alert(ts, channel="C1"):
    return ParsedAlert(channel=channel, ts=ts, raw_text="r", parse_ok=True,
                       check_title="[L3] 訂單檢查", check_code="ORS1")


class PurgeStoreTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        first = alert("1.000001")
        self.store.insert_message(first, NOW)
        self.iid = self.store.create_incident(first, "fp", "g").id

    def test_complete_with_purge_is_atomic(self):
        ids = self.store.complete_analysis_with_purge(
            self.iid, {"severity": "low"}, "m", NOW, channels=["C1", "C2"], analysis_text="分析")
        self.assertEqual(len(ids), 2)
        state, completed = self.store.read(
            "SELECT analysis_state, completed_epoch FROM incidents WHERE id=?", (self.iid,))[0]
        self.assertEqual((state, completed), ("done", NOW))
        rows = self.store.purge_rows("incident_id=?", (self.iid,))
        self.assertEqual({r["channel"] for r in rows}, {"C1", "C2"})
        self.assertTrue(all(r["generation"] == NOW and r["state"] == "pending"
                            and r["analysis_text"] == "分析" for r in rows))
        self.assertEqual(json.loads(rows[0]["verdict"]), {"severity": "low"})

    def test_unique_generation(self):
        self.store.complete_analysis_with_purge(
            self.iid, {}, "m", NOW, channels=["C1"], analysis_text="")
        again = self.store.complete_analysis_with_purge(
            self.iid, {}, "m", NOW, channels=["C1"], analysis_text="")
        self.assertEqual(again, [])
        self.assertEqual(len(self.store.purge_rows("incident_id=?", (self.iid,))), 1)

    def test_deleted_ts(self):
        (pid,) = self.store.complete_analysis_with_purge(
            self.iid, {}, "m", NOW, channels=["C1"], analysis_text="")
        added = self.store.add_purge_targets(pid, "C1", "alert", ["a", "b", "c", "d"])
        self.assertEqual(added, 4)
        self.assertEqual(self.store.add_purge_targets(pid, "C1", "alert", ["a"]), 0)
        self.store.set_target(pid, "alert", "a", "deleted", epoch=NOW)
        self.store.set_target(pid, "alert", "b", "gone", epoch=NOW)
        self.store.set_target(pid, "alert", "c", "failed", error="x", epoch=NOW)
        self.assertEqual(self.store.deleted_ts("C1"), {"a", "b"})
        self.assertEqual(self.store.deleted_ts("C2"), set())

    def test_active_purge_and_set_purge(self):
        (pid,) = self.store.complete_analysis_with_purge(
            self.iid, {}, "m", NOW, channels=["C1"], analysis_text="")
        self.assertEqual(self.store.active_purge(self.iid, "C1", NOW)["id"], pid)
        self.assertIsNone(self.store.active_purge(self.iid, "C1", NOW + 1))
        self.store.set_purge(pid, state="void", finished_epoch=NOW)
        self.assertIsNone(self.store.active_purge(self.iid, "C1", NOW))


class _Resp:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class DeleteMessageTest(unittest.TestCase):
    def test_slack_delete_message_posts_chat_delete(self):
        seen = []

        def opener(req, timeout):
            seen.append(req)
            return _Resp({"ok": True})

        with mock.patch.object(slack_io, "_opener", opener):
            slack_io.delete_message("xoxb-t", "C1", "1.000001")
        self.assertTrue(seen[0].full_url.endswith("/chat.delete"))
        self.assertEqual(json.loads(seen[0].data), {"channel": "C1", "ts": "1.000001"})

    def test_error_is_raised(self):
        with mock.patch.object(slack_io, "_opener",
                               lambda req, timeout: _Resp({"ok": False, "error": "message_not_found"})):
            with self.assertRaises(slack_io.SlackError) as ctx:
                slack_io.delete_message("xoxb-t", "C1", "1.000001")
        self.assertEqual(ctx.exception.error, "message_not_found")

    def test_dry_run_records(self):
        dry = DryRunSlack()
        dry.delete_message("t", "C1", "1.0")
        self.assertEqual(dry.calls, [("delete_message", {"channel": "C1", "ts": "1.0"})])


if __name__ == "__main__":
    unittest.main()
