import dataclasses
import json
import os
import unittest
from pathlib import Path

from alert_doctor import fragments, known_store
from alert_doctor.archive import Archive
from alert_doctor.parse import parse_message
from alert_doctor.redact import strip_secret_text
from tests.test_collector import NOW, Base

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "split_alert.json"
SPLIT_BOT = "B0FIXTURE"


def _restore_length(text: str, length: int) -> str:
    """Put back the ID-list middle the fixture trimmed, so the piece is `length` long again;
    the IDs are spliced in after the first `", "` and keep the list syntax intact."""
    at = text.index('", "') + 4
    missing = length - len(text)
    ids = []
    while missing > 0:
        item = 'A000000000", "'
        if missing < 2 * len(item):
            item = "A" + "0" * (missing - 5) + '", "'
        ids.append(item)
        missing -= len(item)
    return text[:at] + "".join(ids) + text[at:]


def real_messages(shift: float = 0.0) -> list[dict]:
    """The real split sequence: one whole alert, then a head and 9 continuation pieces, each
    split piece restored to its real length (Slack's 4000)."""
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    messages = data["messages"]
    split = messages[-len(data["piece_lengths"]):]
    restored = messages[:-len(split)] + [
        {**m, "text": _restore_length(m["text"], n)} for m, n in zip(split, data["piece_lengths"])]
    return [{**m, "ts": f"{float(m['ts']) + shift:.6f}", "type": "message", "subtype": "bot_message"}
            for m in restored]


CLOSING_HEAD = ("<@U1>\n[L3] 長告警\n{'task_id': 't9', 'code': 'K9', 'vkwargs': {'crontab_task_pk': 9},"
                " 'result': {'level': 40, 'message': 'abc")
FILLER = "x" * (4000 - len(CLOSING_HEAD))


def closing_pair(ts_head: str, ts_tail: str, bot: str = SPLIT_BOT) -> list[dict]:
    """A head Slack cut at 4000 characters inside its message, and the tail that closes it."""
    return [{"type": "message", "subtype": "bot_message", "bot_id": bot, "ts": ts_head,
             "text": CLOSING_HEAD + FILLER},
            {"type": "message", "subtype": "bot_message", "bot_id": bot, "ts": ts_tail,
             "text": "def'}}"}]


class RealSequenceTest(unittest.TestCase):
    def setUp(self):
        self.messages = real_messages()
        self.texts = [m["text"] for m in self.messages]

    def test_heads_and_continuations(self):
        self.assertEqual([fragments.looks_like_head(t) for t in self.texts],
                         [True, True] + [False] * 9)

    def test_slack_cut_mid_token_so_pieces_join_without_separator(self):
        # Every real piece is exactly 4000 chars and the cut lands inside a quoted ID.
        self.assertEqual(json.loads(FIXTURE.read_text())["piece_lengths"], [4000] * 10)
        self.assertEqual([len(t) for t in self.texts[1:]], [4000] * 10)
        self.assertTrue(self.texts[1].endswith('"A'))
        self.assertRegex(self.texts[2], r'^\d{9}", ')
        self.assertIn('"A159662006"', fragments.join_texts(self.texts[1:3]))

    def test_each_piece_alone_is_incomplete(self):
        head = parse_message("C", self.messages[1]["ts"], self.texts[1])
        self.assertFalse(fragments.is_complete(head))
        self.assertFalse(parse_message("C", self.messages[2]["ts"], self.texts[2]).parse_ok)
        self.assertTrue(fragments.is_complete(parse_message("C", "1.0", self.texts[0])))

    def test_reassemble_joins_the_split_alert_only(self):
        groups = fragments.reassemble(self.messages, 15)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].fragments, ())
        whole = groups[1]
        self.assertEqual(whole.head["ts"], self.messages[1]["ts"])
        self.assertEqual([m["ts"] for m in whole.fragments], [m["ts"] for m in self.messages[2:]])
        self.assertEqual(whole.text, "".join(self.texts[1:]))
        alert = parse_message("C", whole.head["ts"], whole.text)
        self.assertTrue(alert.parse_ok)
        self.assertTrue(alert.truncated)
        self.assertEqual(alert.check_code, "MDlNB90WVnwW-YUfdtieV")
        self.assertEqual(alert.extra["vkwargs"]["crontab_task_pk"], 118)
        self.assertIn("'request_path': '/user/pkms/get_credit_data/'", alert.result_message)

    def test_gap_bot_and_head_shape_break_the_chain(self):
        late = [dict(m) for m in self.messages[1:4]]
        late[2]["ts"] = f"{float(late[1]['ts']) + 16:.6f}"
        self.assertEqual([len(g.fragments) for g in fragments.reassemble(late, 15)], [1, 0])
        other = [dict(m) for m in self.messages[1:3]]
        other[1]["bot_id"] = "BOTHER"
        self.assertEqual([len(g.fragments) for g in fragments.reassemble(other, 15)], [0, 0])
        human = [dict(m) for m in self.messages[1:3]]
        human[1].pop("bot_id")
        self.assertEqual([len(g.fragments) for g in fragments.reassemble(human, 15)], [0, 0])

    def test_complete_head_takes_no_continuation(self):
        pair = closing_pair("10.0", "10.5")
        pair.append({**pair[1], "ts": "11.0", "text": "stray tail"})
        groups = fragments.reassemble(pair, 15)
        self.assertEqual([len(g.fragments) for g in groups], [1, 0])
        alert = parse_message("C", "10.0", groups[0].text)
        self.assertTrue(fragments.is_complete(alert))
        self.assertEqual(alert.result_message, f"abc{FILLER}def")

    def test_short_malformed_bot_message_is_not_glued(self):
        malformed = {"type": "message", "subtype": "bot_message", "bot_id": SPLIT_BOT, "ts": "10.0",
                     "text": CLOSING_HEAD}
        tail = {**malformed, "ts": "10.5", "text": "def'}}"}
        self.assertEqual([len(g.fragments) for g in fragments.reassemble([malformed, tail], 15)],
                         [0, 0])

    def test_piece_after_a_short_piece_is_not_glued(self):
        pieces = self.messages[1:4]
        pieces[1] = {**pieces[1], "text": pieces[1]["text"][:3000]}
        self.assertEqual([len(g.fragments) for g in fragments.reassemble(pieces, 15)], [1, 0])


class CollectorReassemblyTest(Base):
    """Live intake of the real split alert: one reply for the whole alert, none per piece."""

    def setUp(self):
        super().setUp()
        self.cfg = dataclasses.replace(self.cfg, fragment_join_seconds=15)

    def split(self):
        messages = real_messages(shift=NOW - 1_790_000_000.0)
        return messages[0], messages[1], messages[2:]

    def feed_event(self, c, message):
        c.on_socket_event("events_api", {"event": {**message, "channel": "C1"}})

    def row(self, ts):
        return self.store.read(
            "SELECT status, category, fragment_of, parse_ok, raw_text FROM messages WHERE ts=?",
            (ts,))[0]

    def assert_reassembled(self, c, head, pieces):
        for piece in pieces:
            status, category, fragment_of, _, _ = self.row(piece["ts"])
            self.assertEqual((status, category, fragment_of), ("handled", "fragment", head["ts"]))
        self.now = float(pieces[-1]["ts"]) + 16
        self.assertEqual(c.process_pending(), 1)
        status, category, _, parse_ok, raw_text = self.row(head["ts"])
        self.assertEqual(status, "handled")
        self.assertNotEqual(category, "unparsed")
        self.assertEqual(parse_ok, 1)
        self.assertEqual(raw_text, strip_secret_text(head["text"] + "".join(p["text"] for p in pieces)))
        self.assertNotIn("xxxxxxxx", raw_text)
        self.publish(c)
        self.assertEqual(len(self.slack.posts), 1)
        self.assertNotIn("grey_question", [name for _, name in self.slack.reactions])

    def test_live_pieces_join_and_head_waits_for_the_window(self):
        c = self.make()
        _, head, pieces = self.split()
        self.now = float(head["ts"]) + 0.2
        for message in [head, *pieces]:
            self.feed_event(c, message)
        self.assertEqual(c.process_pending(), 0)
        self.assertEqual(self.store.counter_sum("intake", 0, NOW + 100), 1)
        self.assertEqual(self.store.count_received(NOW - 60, NOW + 60), 1)
        self.assert_reassembled(c, head, pieces)
        coverage = self.store.coverage("C1", NOW - 60, NOW + 60)
        self.assertEqual((coverage["total"], coverage["unhandled"]), (1, []))
        self.assertNotIn("fragment", coverage["by_category"])

    def test_backfill_reassembles_the_same_way(self):
        c = self.make()
        before, head, pieces = self.split()
        self.slack.history_result = [before, head, *pieces]
        self.now = float(pieces[-1]["ts"]) + 600
        c.backfill(since=float(before["ts"]) - 1)
        self.assertEqual(self.row(before["ts"])[2], None)
        self.now += 16
        self.assertEqual(c.process_pending(), 2)
        self.assertEqual(self.row(pieces[0]["ts"])[1:3], ("fragment", head["ts"]))
        self.assertEqual(self.row(head["ts"])[3], 1)

    def test_piece_arriving_before_its_head_is_claimed(self):
        c = self.make()
        _, head, pieces = self.split()
        self.now = float(head["ts"]) + 0.2
        self.feed_event(c, pieces[0])
        self.assertEqual(c.process_pending(), 0)
        for message in [head, *pieces[1:]]:
            self.feed_event(c, message)
        self.assert_reassembled(c, head, pieces)

    def test_head_is_handled_at_once_when_the_tail_closes_it(self):
        c = self.make()
        head, tail = closing_pair(f"{NOW:.6f}", f"{NOW + 0.5:.6f}")
        self.now = NOW + 1
        self.feed_event(c, head)
        self.assertEqual(c.process_pending(), 0)
        self.feed_event(c, tail)
        self.assertEqual(c.process_pending(), 1)
        rows = self.store.read("SELECT result_message FROM messages WHERE ts=?", (head["ts"],))
        self.assertEqual(rows, [(f"abc{FILLER}def",)])

    def test_short_malformed_message_is_not_glued_live(self):
        c = self.make()
        head, tail = closing_pair(f"{NOW:.6f}", f"{NOW + 0.5:.6f}")
        head["text"] = CLOSING_HEAD
        self.now = NOW + 1
        self.feed_event(c, head)
        self.feed_event(c, tail)
        self.now = NOW + 30
        self.assertEqual(c.process_pending(), 2)
        self.assertEqual(self.row(tail["ts"])[1:3], ("unparsed", None))

    def test_late_piece_after_the_head_was_handled_is_appended_with_a_note(self):
        c = self.make()
        _, head, pieces = self.split()
        self.now = float(head["ts"]) + 0.2
        for message in [head, *pieces[:-1]]:
            self.feed_event(c, message)
        self.now = float(pieces[-2]["ts"]) + 16
        self.assertEqual(c.process_pending(), 1)
        incidents_before = self.store.read("SELECT COUNT(*) FROM incidents")
        self.publish(c)
        self.now += 60
        self.feed_event(c, pieces[-1])
        status, category, fragment_of, _, raw_text = self.row(pieces[-1]["ts"])
        self.assertEqual((status, category, fragment_of), ("handled", "fragment", head["ts"]))
        self.assertTrue(self.row(head["ts"])[4].endswith(strip_secret_text(pieces[-1]["text"])))
        self.assertEqual(self.row(head["ts"])[4],
                         strip_secret_text(head["text"] + "".join(p["text"] for p in pieces)))
        self.assertEqual(c.process_pending(), 0)
        self.assertEqual(self.store.read("SELECT COUNT(*) FROM incidents"), incidents_before)
        [(kind, payload)] = self.store.read(
            "SELECT kind, payload FROM outbox WHERE kind='late_fragment'")
        self.assertEqual(json.loads(payload)["text"], "📎 此告警後段晚到,已補入(共 10 段)")
        self.publish(c)
        self.assertEqual(self.slack.posts[-1][1], "📎 此告警後段晚到,已補入(共 10 段)")
        self.assertEqual(self.slack.posts[-1][2], head["ts"])

    def test_late_piece_that_changes_the_error_key_is_recorded_not_reanalysed(self):
        archive = Archive(os.path.join(self.tmp.name, "archive.db"))
        c = self.make(archive=archive)
        head, tail = closing_pair(f"{NOW:.6f}", f"{NOW + 0.5:.6f}")
        self.now = NOW + 1
        self.feed_event(c, head)
        self.now = NOW + 20
        self.assertEqual(c.process_pending(), 1)
        state = self.store.read("SELECT analysis_state FROM incidents")
        self.feed_event(c, tail)
        self.assertEqual(self.store.read("SELECT result_message FROM messages WHERE ts=?",
                                         (head["ts"],)), [(f"abc{FILLER}def",)])
        self.assertEqual(self.store.read("SELECT analysis_state FROM incidents"), state)
        self.assertEqual(self.store.counter_sum("late_fragment_rekeyed", 0, NOW + 100), 1)
        self.assertEqual(c.process_pending(), 0)
        joined = self.store.get_message("C1", head["ts"])
        self.assertEqual(archive.key_of("C1", head["ts"])[0],
                         known_store.alert_error_key(joined, source_system="sys"))

    def test_continuation_after_a_complete_head_is_its_own_message(self):
        c = self.make()
        head, tail = closing_pair(f"{NOW:.6f}", f"{NOW + 0.5:.6f}")
        head["text"] = head["text"].replace("'abc", "'abc'}}")
        self.now = NOW + 1
        self.feed_event(c, head)
        self.feed_event(c, {**tail, "text": "長訊息的尾巴"})
        self.assertEqual(c.process_pending(), 1)
        self.now = NOW + 30
        self.assertEqual(c.process_pending(), 1)
        self.assertEqual(self.row(tail["ts"])[1:3], ("unparsed", None))

    def test_piece_from_another_bot_is_not_joined(self):
        c = self.make()
        head, tail = closing_pair(f"{NOW:.6f}", f"{NOW + 0.5:.6f}")
        tail["bot_id"] = "BOTHER"
        self.now = NOW + 1
        self.feed_event(c, head)
        self.feed_event(c, tail)
        self.now = NOW + 30
        self.assertEqual(c.process_pending(), 2)
        self.assertEqual(self.row(tail["ts"])[1:3], ("unparsed", None))


if __name__ == "__main__":
    unittest.main()
