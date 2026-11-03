import json
import tempfile
import unittest
from pathlib import Path

from alert_doctor.config import ChannelSpec, Config
from alert_doctor.models import ParsedAlert
from alert_doctor.purge import blocked_thread
from alert_doctor.slack_io import SlackError, SlackRateLimited
from alert_doctor.store import Store
from alert_doctor.wipe import wipe_channel

NOW = 1_760_000_000.0
SOURCE, OURS, OTHER = "B01SRCBOT00", "BOURS", "BOTHER"
ALERT = "<@U1>\n[L3] 訂單檢查\n{'code': 'ORS1', 'result': {'level': 3, 'message': 'boom'}}"


class FakeSlack:
    def __init__(self, top, threads):
        self.top, self.threads = top, threads
        self.deletes, self.errors = [], {}
        self.on_delete = None

    def history(self, token, channel, oldest, limit=200):
        return [dict(m) for m in self.top]

    def thread_replies(self, token, channel, ts):
        return list(self.threads.get(ts, []))

    def delete_message(self, token, channel, ts):
        if self.on_delete:
            self.on_delete(ts)
        error = self.errors.pop(ts, None)
        if error is not None:
            raise error
        self.deletes.append((token, ts))


def m(ts, bot_id=None, user=None, replies=0, text=None, subtype=None):
    msg = {"ts": ts, "text": text if text is not None else f"msg {ts}", "reply_count": replies}
    if bot_id:
        msg["bot_id"] = bot_id
    if user:
        msg["user"] = user
    if subtype:
        msg["subtype"] = subtype
    return msg


def alert(ts, replies=0, text=ALERT):
    return m(ts, SOURCE, replies=replies, text=text)


class WipeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(channels=(ChannelSpec("C1", "alerts-a", ("sys",)),),
                          workspace_url="https://w.slack.com", source_bot_ids=(SOURCE,))
        self.store = Store(":memory:")
        self.slack = FakeSlack(
            top=[alert("1.0", replies=1), m("2.0", user="UHUMAN"), m("3.0", OTHER),
                 alert("4.0"), m("5.0", OURS), alert("6.0", replies=2)],
            threads={"1.0": [m("1.1", OURS)], "6.0": [m("6.1", OURS), m("6.2", user="UHUMAN")]})
        self.sleeps = []
        self.runs = 0

    def run_wipe(self, apply):
        self.runs += 1
        return wipe_channel(self.store, self.slack, self.cfg, "C1", bot_token="xoxb-ours",
                            source_bot_token="xoxb-source", our_bot_id=OURS,
                            archive_dir=str(Path(self.tmp.name, f"run{self.runs}")), apply=apply,
                            now=NOW, sleep=self.sleeps.append, pause=0)

    def deleted(self):
        return [ts for _, ts in self.slack.deletes]

    def test_dry_run_counts_and_archives_but_deletes_nothing(self):
        result = self.run_wipe(apply=False)
        self.assertEqual((result["alerts"], result["ours"], result["kept"]), (2, 2, 5))
        self.assertEqual(result["discussed"], 1)
        self.assertEqual(self.slack.deletes, [])
        archived = json.loads(Path(result["archive"]).read_text())
        self.assertEqual([x["ts"] for x in archived["messages"]],
                         ["1.0", "2.0", "3.0", "4.0", "5.0", "6.0"])
        self.assertEqual([x["ts"] for x in archived["messages"][5]["replies"]], ["6.1", "6.2"])

    def test_apply_deletes_thread_by_thread_with_right_tokens(self):
        self.run_wipe(apply=True)
        self.assertEqual(self.slack.deletes, [("xoxb-source", "1.0"), ("xoxb-ours", "1.1"),
                                              ("xoxb-source", "4.0"), ("xoxb-ours", "5.0")])
        self.assertTrue(blocked_thread(self.store, "C1", "1.0"))
        self.assertFalse(blocked_thread(self.store, "C1", "2.0"))

    def test_thread_with_a_person_reply_is_kept_whole(self):
        self.run_wipe(apply=True)
        self.assertNotIn("6.0", self.deleted())
        self.assertNotIn("6.1", self.deleted())

    def test_broadcast_and_file_replies_count_as_people(self):
        self.slack.threads["1.0"] = [m("1.1", OURS), m("1.2", user="U2", subtype="thread_broadcast")]
        self.slack.threads["4.0"] = [m("4.1", user="U3", subtype="file_share")]
        self.slack.top[3]["reply_count"] = 1
        self.run_wipe(apply=True)
        self.assertEqual(self.deleted(), ["5.0"])

    def test_same_bot_non_alert_notice_is_kept(self):
        self.slack.top.append(m("7.0", SOURCE, text="工作卡 #123 已指派給你"))
        self.run_wipe(apply=True)
        self.assertNotIn("7.0", self.deleted())

    def test_mentioning_notice_from_the_same_bot_is_kept(self):
        self.slack.top.append(m("7.0", SOURCE, text="<@U1> 工作卡 #123 已指派給你"))
        self.run_wipe(apply=True)
        self.assertNotIn("7.0", self.deleted())

    def test_our_reply_under_a_fragment_or_a_kept_notice_is_deleted(self):
        head = "<@U1>\n[L3] 長告警\n{'code': 'K9', 'result': {'level': 40, 'message': 'abc" + "x" * 4000
        self.slack.top = [alert("1.0", text=head[:4000]), m("1.5", SOURCE, text="def'}}", replies=1),
                          m("7.0", SOURCE, text="工作卡 #123", replies=1)]
        self.slack.threads = {"1.5": [m("1.6", OURS)], "7.0": [m("7.1", OURS)]}
        self.run_wipe(apply=True)
        self.assertEqual(sorted(self.deleted()), ["1.0", "1.5", "1.6", "7.1"])

    def test_person_replying_meanwhile_in_another_bots_thread_saves_our_reply(self):
        self.slack.top = [alert("1.0"), m("3.0", OTHER, replies=1)]
        self.slack.threads = {"3.0": [m("3.1", OURS)]}

        def reply_to_other(ts):
            if ts == "1.0":
                self.slack.threads["3.0"] = [m("3.1", OURS), m("3.2", user="UHUMAN")]

        self.slack.on_delete = reply_to_other
        result = self.run_wipe(apply=True)
        self.assertEqual(self.deleted(), ["1.0"])
        self.assertEqual(result["skipped"], 1)

    def test_continuation_pieces_of_an_alert_are_deleted(self):
        head = "<@U1>\n[L3] 長告警\n{'code': 'K9', 'result': {'level': 40, 'message': 'abc" + "x" * 4000
        self.slack.top = [alert("1.0", text=head[:4000]), m("1.5", SOURCE, text="def'}}")]
        self.slack.threads = {}
        self.run_wipe(apply=True)
        self.assertEqual(self.deleted(), ["1.0", "1.5"])

    def test_person_replying_during_the_wipe_saves_that_thread(self):
        def reply_to_four(ts):
            if ts == "1.0":
                self.slack.threads["4.0"] = [m("4.1", user="UHUMAN")]

        self.slack.on_delete = reply_to_four
        result = self.run_wipe(apply=True)
        self.assertNotIn("4.0", self.deleted())
        self.assertEqual(result["skipped"], 1)

    def test_no_source_bot_ids_means_no_alert_deleted(self):
        self.cfg = Config(channels=self.cfg.channels, workspace_url="https://w.slack.com")
        self.run_wipe(apply=True)
        self.assertEqual(self.deleted(), ["1.1", "5.0"])

    def test_our_deleted_top_level_post_blocks_and_drops_its_report(self):
        alert_row = ParsedAlert(channel="C1", ts="0.5", raw_text="r", parse_ok=True,
                                check_title="T", check_code="X")
        self.store.insert_message(alert_row, NOW)
        iid = self.store.create_incident(alert_row, "fp", "g").id
        self.store.upsert_report(iid, "C1", "5.0", now=NOW)
        self.run_wipe(apply=True)
        self.assertTrue(blocked_thread(self.store, "C1", "5.0"))
        self.assertIsNone(self.store.get_report(iid, "C1"))

    def test_rate_limit_waits_and_retries_and_gone_is_success(self):
        self.slack.errors["1.0"] = SlackRateLimited(7)
        self.slack.errors["4.0"] = SlackError("message_not_found")
        result = self.run_wipe(apply=True)
        self.assertEqual(self.sleeps.count(7), 1)
        self.assertEqual((result["deleted"], result["failed"]), (4, 0))

    def test_other_errors_are_counted_and_skipped(self):
        self.slack.errors["1.1"] = SlackError("cant_delete_message")
        result = self.run_wipe(apply=True)
        self.assertEqual(result["failed"], 1)
        self.assertIn(("xoxb-ours", "5.0"), self.slack.deletes)

    def test_report_kept_when_its_root_could_not_be_deleted(self):
        alert_row = ParsedAlert(channel="C1", ts="1.0", raw_text="r", parse_ok=True,
                                check_title="T", check_code="X")
        self.store.insert_message(alert_row, NOW)
        iid = self.store.create_incident(alert_row, "fp", "g").id
        self.store.upsert_report(iid, "C1", "1.0", now=NOW)
        self.slack.errors["1.0"] = SlackError("cant_delete_message")
        self.run_wipe(apply=True)
        self.assertIsNotNone(self.store.get_report(iid, "C1"))

    def test_reports_on_deleted_roots_are_removed(self):
        alert_row = ParsedAlert(channel="C1", ts="1.0", raw_text="r", parse_ok=True,
                                check_title="T", check_code="X")
        self.store.insert_message(alert_row, NOW)
        iid = self.store.create_incident(alert_row, "fp", "g").id
        self.store.upsert_report(iid, "C1", "1.0", now=NOW)
        self.run_wipe(apply=True)
        self.assertIsNone(self.store.get_report(iid, "C1"))

    def test_archive_is_never_overwritten(self):
        first = wipe_channel(self.store, self.slack, self.cfg, "C1", bot_token="t",
                             source_bot_token="p", our_bot_id=OURS, archive_dir=self.tmp.name,
                             apply=False, now=NOW, sleep=self.sleeps.append, pause=0)
        before = Path(first["archive"]).read_text()
        with self.assertRaises(FileExistsError):
            wipe_channel(self.store, self.slack, self.cfg, "C1", bot_token="t",
                         source_bot_token="p", our_bot_id=OURS, archive_dir=self.tmp.name,
                         apply=False, now=NOW, sleep=self.sleeps.append, pause=0)
        self.assertEqual(Path(first["archive"]).read_text(), before)


if __name__ == "__main__":
    unittest.main()
