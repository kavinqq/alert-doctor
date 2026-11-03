import unittest

from alert_doctor.parse import parse_message

CH = "C123"
TS = "1760000000.000100"
TITLE = "檢查 FastPxy 5xx"
EXTRA = (
    "{'task_id': 'b1c', 'code': 'fastpxy_5xx', 'vargs': [], "
    "'vkwargs': {'crontab_task_pk': 12}, 'check_script': '檢查 FastPxy 5xx', "
    "'result': {'level': 40, 'message': '5xx 次數 37 超過門檻 20'}}"
)


class ParseMessageTest(unittest.TestCase):
    def test_parse_plain(self):
        a = parse_message(CH, TS, f"{TITLE}\n{EXTRA}")
        self.assertTrue(a.parse_ok)
        self.assertEqual(a.channel, CH)
        self.assertEqual(a.ts, TS)
        self.assertEqual(a.check_title, TITLE)
        self.assertEqual(a.check_code, "fastpxy_5xx")
        self.assertEqual(a.task_id, "b1c")
        self.assertEqual(a.level, 40)
        self.assertEqual(a.result_message, "5xx 次數 37 超過門檻 20")
        self.assertEqual(a.mentions, ())
        self.assertEqual(a.extra["vkwargs"], {"crontab_task_pk": 12})

    def test_parse_with_mentions(self):
        text = f"<@U01AAAAAAAA> <@U01BBBBBBBB>\n\n{TITLE}\n{EXTRA}"
        a = parse_message(CH, TS, text)
        self.assertTrue(a.parse_ok)
        self.assertEqual(a.mentions, ("U01AAAAAAAA", "U01BBBBBBBB"))
        self.assertEqual(a.check_title, TITLE)
        self.assertEqual(a.check_code, "fastpxy_5xx")

    def test_parse_slack_escaped(self):
        extra = EXTRA.replace("5xx 次數 37", "a<b && c>d 37")
        escaped = extra.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        a = parse_message(CH, TS, f"&lt;@U01AAAAAAAA&gt;\n\n{TITLE}\n{escaped}")
        self.assertTrue(a.parse_ok)
        self.assertEqual(a.mentions, ("U01AAAAAAAA",))
        self.assertEqual(a.check_title, TITLE)
        self.assertEqual(a.result_message, "a<b && c>d 37 超過門檻 20")

    def test_amp_unescaped_last(self):
        a = parse_message(CH, TS, "t\n{'result': {'message': 'x &amp;lt; y'}}")
        self.assertEqual(a.result_message, "x &lt; y")

    def test_parse_garbage(self):
        a = parse_message(CH, TS, "hello\nnot a dict")
        self.assertFalse(a.parse_ok)
        self.assertEqual(a.check_title, "hello")
        self.assertEqual(a.result_message, "not a dict")
        self.assertIsNone(a.check_code)

    def test_parse_extra_not_dict(self):
        a = parse_message(CH, TS, "hello\n[1, 2, 3]")
        self.assertFalse(a.parse_ok)
        self.assertEqual(a.check_title, "hello")
        self.assertEqual(a.result_message, "[1, 2, 3]")

    def test_parse_title_only(self):
        a = parse_message(CH, TS, "hello")
        self.assertFalse(a.parse_ok)
        self.assertEqual(a.check_title, "hello")
        self.assertEqual(a.result_message, "")

    def test_parse_empty(self):
        a = parse_message(CH, TS, "")
        self.assertFalse(a.parse_ok)
        self.assertEqual(a.check_title, "")

    def test_garbage_keeps_mentions_and_skips_them_for_title(self):
        a = parse_message(CH, TS, "<@U1ABC>\n\nhello\nnope")
        self.assertFalse(a.parse_ok)
        self.assertEqual(a.check_title, "hello")
        self.assertEqual(a.mentions, ("U1ABC",))

    def test_multiline_extra(self):
        a = parse_message(CH, TS, "t\n{'code': 'c',\n 'result': {'level': 30, 'message': 'm'}}")
        self.assertTrue(a.parse_ok)
        self.assertEqual(a.level, 30)

    def test_missing_result_fields(self):
        a = parse_message(CH, TS, "t\n{'code': 'c'}")
        self.assertTrue(a.parse_ok)
        self.assertIsNone(a.level)
        self.assertEqual(a.result_message, "")

    def test_raw_text_preserved(self):
        text = f"&lt;@U1&gt;\n{TITLE}\n{EXTRA}"
        self.assertEqual(parse_message(CH, TS, text).raw_text, text)


class MentionLineTest(unittest.TestCase):
    def test_broadcast_and_subteam_tokens_are_mention_lines(self):
        for line in ("<!here>", "<!channel>", "<!subteam^S123|@oncall>", "<!subteam^S123>", "<!here> <@U1ABC>"):
            with self.subTest(line=line):
                a = parse_message(CH, TS, f"{line}\n{TITLE}\n{EXTRA}")
                self.assertTrue(a.parse_ok)
                self.assertEqual(a.check_title, TITLE)

    def test_only_user_ids_collected(self):
        a = parse_message(CH, TS, f"<!here> <@U1ABC> <!subteam^S9|@x>\n{TITLE}\n{EXTRA}")
        self.assertEqual(a.mentions, ("U1ABC",))

    def test_mention_mixed_with_text_is_title(self):
        a = parse_message(CH, TS, f"<!here> 出事了\n{EXTRA}")
        self.assertEqual(a.check_title, "<!here> 出事了")


class SalvageTest(unittest.TestCase):
    def test_non_literal_extra_falls_back_to_regex(self):
        extra = (
            "{'task_id': 'b1c', 'code': 'fastpxy_5xx', 'at': datetime.datetime(2026, 10, 19, 1, 2), "
            "'amount': Decimal('1'), 'id': UUID('12345678-1234-5678-1234-567812345678'), "
            "'result': {'level': 40, 'message': '5xx 次數 37'}}"
        )
        a = parse_message(CH, TS, f"{TITLE}\n{extra}")
        self.assertTrue(a.parse_ok)
        self.assertEqual(
            (a.check_code, a.task_id, a.level, a.result_message, a.extra),
            ("fastpxy_5xx", "b1c", 40, "5xx 次數 37", {}),
        )

    def test_double_quoted_and_escaped(self):
        extra = '{"code": "c1", "d": Decimal(\'2\'), "result": {"level": 30, "message": "say \\"hi\\" ok"}}'
        a = parse_message(CH, TS, f"{TITLE}\n{extra}")
        self.assertTrue(a.parse_ok)
        self.assertEqual((a.check_code, a.level, a.result_message), ("c1", 30, 'say "hi" ok'))

    def test_message_taken_from_result_not_vkwargs(self):
        extra = "{'code': 'c', 'vkwargs': {'message': 'other', 'd': Decimal('1')}, 'result': {'message': 'real'}}"
        a = parse_message(CH, TS, f"{TITLE}\n{extra}")
        self.assertEqual(a.result_message, "real")
        self.assertIsNone(a.level)

    def test_missing_code_or_message_stays_unparsed(self):
        for extra in ("{'code': 'c', 'd': Decimal('1')}", "{'d': Decimal('1'), 'result': {'message': 'm'}}"):
            with self.subTest(extra=extra):
                a = parse_message(CH, TS, f"{TITLE}\n{extra}")
                self.assertFalse(a.parse_ok)
                self.assertEqual(a.result_message, extra)



class TruncatedTest(unittest.TestCase):
    HEAD = ("[check_log_message]檢查\n{'task_id': 't', 'code': 'K1', 'vkwargs': {'crontab_task_pk': 118},"
            " 'result': {'level': 40, 'message': '服務異常「{\\'request_path\\': \\'/a/\\', "
            "\\'request_body\\': b\\'{\"ids\": [\"A1\", \"A2")

    def test_message_cut_before_its_closing_quote_is_salvaged_and_flagged(self):
        a = parse_message("C", "1.0", self.HEAD)
        self.assertTrue(a.parse_ok)
        self.assertTrue(a.truncated)
        self.assertEqual((a.check_code, a.level, a.task_id), ("K1", 40, "t"))
        self.assertTrue(a.result_message.startswith("服務異常「{'request_path': '/a/'"), a.result_message)
        self.assertEqual(a.extra, {"vkwargs": {"crontab_task_pk": 118}})

    def test_salvaged_vkwargs_lose_secrets(self):
        text = ("T\n{'code': 'K1', 'vkwargs': {'crontab_task_pk': 7, 'access': 'c2VjcmV0', 'n': {'a': '}'}},"
                " 'result': {'level': 40, 'message': 'cut here")
        vkwargs = parse_message("C", "1.0", text).extra["vkwargs"]
        self.assertEqual(vkwargs["crontab_task_pk"], 7)
        self.assertEqual(vkwargs["n"], {"a": "}"})
        self.assertNotEqual(vkwargs.get("access"), "c2VjcmV0")

    def test_dangling_backslash_at_cut(self):
        a = parse_message("C", "1.0", self.HEAD + "\\")
        self.assertTrue(a.parse_ok and a.truncated)
        self.assertTrue(a.result_message.endswith('"A2'), a.result_message[-10:])
        b = parse_message("C", "1.0", self.HEAD + "\\\\")
        self.assertTrue(b.result_message.endswith('"A2\\'), b.result_message[-10:])

    def test_complete_messages_are_not_truncated(self):
        whole = "T\n{'code': 'K1', 'result': {'level': 40, 'message': 'x'}}"
        self.assertFalse(parse_message("C", "1.0", whole).truncated)
        salvaged = "T\n{'code': 'K1', 'when': datetime.datetime(2026, 1, 1), 'result': {'message': 'x'}}"
        a = parse_message("C", "1.0", salvaged)
        self.assertTrue(a.parse_ok)
        self.assertFalse(a.truncated)

    def test_multiline_message_cut(self):
        a = parse_message("C", "1.0", "T\n{'code': 'K1', 'result': {'level': 40, 'message': 'line1\nline2")
        self.assertTrue(a.parse_ok and a.truncated)
        self.assertEqual(a.result_message, "line1\nline2")

    def test_cut_before_message_is_unparsed(self):
        self.assertFalse(parse_message("C", "1.0", "T\n{'code': 'K1', 'result': {'lev").parse_ok)


if __name__ == "__main__":
    unittest.main()
