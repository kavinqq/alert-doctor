import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alert_doctor import known
from alert_doctor.models import ParsedAlert

TAIPEI = timezone(timedelta(hours=8))
EXAMPLE = Path(__file__).resolve().parent.parent / "known.example.toml"
COUPON_P999 = (
    "['Pxy', 'PE']服務中出現異常關鍵字「['P999']」，請立即查看系統狀況！"
    "「[取得折抵金優惠券]失敗 ino='F127894093' 原因: 經管錯誤 經管回傳 code: P999, error message: None」"
)


def at(y, mo, d, h, mi, s=0):
    return datetime(y, mo, d, h, mi, s, tzinfo=TAIPEI).timestamp()


def alert(message="連線逾時", title="t", code="c", raw="", task_pk=None):
    extra = {"vkwargs": {"crontab_task_pk": task_pk}} if task_pk is not None else {}
    return ParsedAlert(channel="C1", ts="1.0", raw_text=raw, parse_ok=True, check_title=title,
                       check_code=code, result_message=message, extra=extra)


def write(text):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
    tmp.write(text)
    tmp.close()
    return tmp.name


ENTRY = """
[[known]]
id = "{id}"
title = "測試維護窗"
description = "說明"
source = "測試"
action = "{action}"
windows = [{windows}]
{extra}
[known.match]
any_regex = ["連線"]
{scope}
{match}
"""
SCOPE = 'systems = ["cms"]\ncheck_codes = ["c"]'


def entry_text(id="e1", action="known", windows='{ start = "03:00", end = "03:10" }', extra="",
               match="", scope=SCOPE):
    return ENTRY.format(id=id, action=action, windows=windows, extra=extra, match=match, scope=scope)


def load(windows='{ start = "03:00", end = "03:10" }', action="known", extra="", match="", id="e1",
         scope=SCOPE):
    path = write(entry_text(id, action, windows, extra, match, scope))
    try:
        return known.load_known(path)
    finally:
        os.unlink(path)


class LoadTest(unittest.TestCase):
    def test_missing_file_is_empty(self):
        self.assertEqual(known.load_known("/nonexistent/known.toml"), [])

    def test_parses_entry(self):
        [entry] = load(extra="grace_minutes = 2\nexpires = 2027-01-01")
        self.assertEqual((entry.id, entry.title, entry.action, entry.grace_minutes, entry.source),
                         ("e1", "測試維護窗", "known", 2, "測試"))
        self.assertEqual(entry.windows[0].start, 180)
        self.assertEqual(entry.windows[0].end, 190)
        self.assertEqual(entry.windows[0].days, frozenset(range(7)))

    def test_default_grace_is_two_minutes_for_known_and_five_for_context(self):
        self.assertEqual(load()[0].grace_minutes, 2)
        self.assertEqual(load(action="context")[0].grace_minutes, 5)

    def test_bad_entries_name_the_id(self):
        cases = [
            dict(windows='{ start = "25:00", end = "03:10" }'),
            dict(windows='{ start = "03:00", end = "03:00" }'),
            dict(windows='{ start = "03:00", end = "03:10", days = "sometimes" }'),
            dict(windows='{ start = "03:00", end = "03:10", days = [7] }'),
            dict(windows='{ start = "03:00", end = "03:10", colour = "red" }'),
            dict(windows=""),
            dict(action="silence"),
            dict(extra="typo_key = 1"),
            dict(extra="grace_minutes = -1"),
            dict(extra='expires = "tomorrow"'),
            dict(match='task_pks = ["x"]'),
            dict(match='colour = "red"'),
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError, "e1"):
                    load(**case)

    def test_bad_regex_names_the_id(self):
        path = write(entry_text(id="bad").replace('["連線"]', '["(未關"]'))
        self.addCleanup(os.unlink, path)
        with self.assertRaisesRegex(ValueError, "bad"):
            known.load_known(path)

    def test_known_action_requires_systems_and_a_task_or_check_scope(self):
        for scope in ("", 'systems = ["cms"]', 'check_codes = ["c"]', 'task_pks = [35]'):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(ValueError, "wide"):
                    load(id="wide", scope=scope)
        self.assertEqual(len(load(scope='systems = ["cms"]\ntask_pks = [35]')), 1)

    def test_context_may_stay_broad(self):
        self.assertEqual(load(action="context", scope="")[0].systems, ())

    def test_bad_all_regex_names_the_id(self):
        with self.assertRaisesRegex(ValueError, "e1"):
            load(match='all_regex = ["(未關"]')

    def test_duplicate_id_rejected(self):
        text = entry_text(id="dup")
        path = write(text + text)
        self.addCleanup(os.unlink, path)
        with self.assertRaisesRegex(ValueError, "dup"):
            known.load_known(path)

    def test_example_file_loads(self):
        entries = {e.id: e.action for e in known.load_known(str(EXAMPLE))}
        self.assertEqual(entries, {"ddsc-nightly-restart": "known", "ddsc-nightly-context": "context",
                                   "middle-platform-midnight-restart": "known",
                                   "middle-platform-midnight-context": "context"})


class WindowTest(unittest.TestCase):
    def hit(self, entries, epoch, a=None, system="cms"):
        return known.match_known(entries, a or alert(), epoch, system)

    def test_inside_and_outside(self):
        entries = load()
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 3, 5)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 10, 0)))

    def test_grace_extends_both_edges(self):
        entries = load(extra="grace_minutes = 5")
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 2, 55)))
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 3, 15)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 3, 15, 1)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 2, 54, 59)))

    def test_zero_grace_is_exact(self):
        entries = load(extra="grace_minutes = 0")
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 3, 10)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 3, 10, 1)))

    def test_window_crossing_midnight(self):
        entries = load(windows='{ start = "23:50", end = "00:10" }', extra="grace_minutes = 0")
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 23, 55)))
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 22, 0, 5)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 22, 0, 11)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 23, 49)))

    def test_grace_crosses_midnight(self):
        entries = load(windows='{ start = "00:00", end = "00:01" }', extra="grace_minutes = 5")
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 23, 56)))

    def test_day_filter_uses_the_day_the_window_starts(self):
        # 2026-10-23 is a Friday, 10-24 a Saturday.
        entries = load(windows='{ start = "23:50", end = "00:10", days = "weekdays" }',
                       extra="grace_minutes = 0")
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 24, 0, 5)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 24, 23, 55)))

    def test_day_list(self):
        entries = load(windows='{ start = "03:00", end = "03:10", days = [2] }')
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 21, 3, 5)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 22, 3, 5)))

    def test_weekends(self):
        entries = load(windows='{ start = "03:00", end = "03:10", days = "weekends" }')
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 24, 3, 5)))
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 3, 5)))

    def test_expired_entry_never_matches(self):
        entries = load(extra="expires = 2026-10-20")
        self.assertIsNone(self.hit(entries, at(2026, 10, 21, 3, 5)))
        self.assertIsNotNone(self.hit(entries, at(2026, 10, 20, 3, 5)))

    def test_most_specific_window_wins(self):
        entries = load(windows='{ start = "00:00", end = "03:55", label = "整段" },'
                               '{ start = "03:00", end = "03:10", label = "62 號主機重啟" }')
        hit = self.hit(entries, at(2026, 10, 21, 3, 5))
        self.assertEqual(hit.window.label, "62 號主機重啟")
        self.assertEqual(hit.label, "03:00 62 號主機重啟")

    def test_unlabelled_window_label_is_its_span(self):
        hit = self.hit(load(), at(2026, 10, 21, 3, 5))
        self.assertEqual(hit.label, "03:00–03:10")


class MatchTest(unittest.TestCase):
    def test_regex_searches_message_title_and_raw_text(self):
        entries = load()
        epoch = at(2026, 10, 21, 3, 5)
        for a in (alert(message="連線失敗"), alert(message="x", title="連線檢查"),
                  alert(message="x", raw="...連線...")):
            self.assertIsNotNone(known.match_known(entries, a, epoch, "cms"))
        self.assertIsNone(known.match_known(entries, alert(message="KeyError"), epoch, "cms"))

    def test_regex_is_case_insensitive(self):
        path = write(entry_text(id="e").replace('["連線"]', '["connection refused"]'))
        self.addCleanup(os.unlink, path)
        self.assertIsNotNone(known.match_known(
            known.load_known(path), alert(message="Connection Refused"), at(2026, 10, 21, 3, 5), "cms"))

    def test_all_regex_needs_every_pattern(self):
        entries = load(match='all_regex = ["廠商甲", "Errno 111"]')
        epoch = at(2026, 10, 21, 3, 5)
        self.assertIsNotNone(known.match_known(entries, alert(message="廠商甲連線 Errno 111"), epoch, "cms"))
        for message in ("廠商甲連線失敗", "連線 Errno 111", "廠商甲 Errno 111"):
            self.assertIsNone(known.match_known(entries, alert(message=message), epoch, "cms"), message)

    def test_all_regex_alone_is_a_text_filter(self):
        path = write(entry_text(match='all_regex = ["廠商甲", "socket"]').replace('any_regex = ["連線"]\n', ""))
        self.addCleanup(os.unlink, path)
        entries = known.load_known(path)
        epoch = at(2026, 10, 21, 3, 5)
        self.assertIsNotNone(known.match_known(entries, alert(message="廠商甲 socket closed"), epoch, "cms"))
        self.assertIsNone(known.match_known(entries, alert(message="KeyError"), epoch, "cms"))
        [found] = known.background(entries, alert(message="廠商甲 socket"), epoch, epoch, "cms")
        self.assertTrue(found["text_match"])

    def test_systems_filter(self):
        entries = load(scope='systems = ["cms", "pxy"]\ncheck_codes = ["c"]')
        epoch = at(2026, 10, 21, 3, 5)
        self.assertIsNotNone(known.match_known(entries, alert(), epoch, "pxy"))
        self.assertIsNone(known.match_known(entries, alert(), epoch, "sso"))

    def test_check_code_and_task_filters(self):
        entries = load(scope='systems = ["cms"]\ncheck_codes = ["c9"]\ntask_pks = [35]')
        epoch = at(2026, 10, 21, 3, 5)
        self.assertIsNotNone(known.match_known(entries, alert(code="c9", task_pk=35), epoch, "cms"))
        self.assertIsNone(known.match_known(entries, alert(code="c1", task_pk=35), epoch, "cms"))
        self.assertIsNone(known.match_known(entries, alert(code="c9", task_pk=36), epoch, "cms"))

    def test_action_filter(self):
        entries = load(action="context")
        epoch = at(2026, 10, 21, 3, 5)
        self.assertIsNotNone(known.match_known(entries, alert(), epoch, "cms"))
        self.assertIsNone(known.match_known(entries, alert(), epoch, "cms", action="known"))

    def test_reply(self):
        hit = known.match_known(load(), alert(), at(2026, 10, 21, 3, 5), "cms")
        text = known.known_reply(hit)
        self.assertTrue(text.startswith("🔖 *固定維護窗*:測試維護窗(03:00–03:10),屬已知現象,不另行分析"))
        self.assertIn("說明", text)
        self.assertIn("測試", text)


class ExampleFileTest(unittest.TestCase):
    def setUp(self):
        self.entries = known.load_known(str(EXAMPLE))

    def test_1021_coupon_p999_gets_host_62_context_not_known(self):
        for epoch in (at(2026, 10, 21, 3, 0, 33), at(2026, 10, 21, 3, 5, 0)):
            message = alert(message=COUPON_P999)
            self.assertIsNone(known.match_known(self.entries, message, epoch, "cms", action="known"))
            hit = known.match_known(self.entries, message, epoch, "cms", action="context")
            self.assertIsNotNone(hit)
            self.assertIn("62", hit.label)
            [found] = [b for b in known.background(self.entries, message, epoch, epoch, "cms")
                       if b["id"] == "ddsc-nightly-context"]
            self.assertTrue(found["in_window"] and found["text_match"])

    def test_ddsc_marker_plus_connection_failure_in_scope_is_known(self):
        for message in ("廠商甲 602 電文查詢失敗 [Errno 111] Connection refused",
                        "DDSC socket closed", "查詢 705 失敗 timeout", "經管回傳 P999 廠商甲連線被拒",
                        "電文 socket 錯誤 timed out"):
            for system, pk in (("cms", 35), ("sso", 118)):
                hit = known.match_known(self.entries, alert(message=message, task_pk=pk),
                                        at(2026, 10, 21, 3, 5), system, action="known")
                self.assertIsNotNone(hit, (message, system))
                self.assertEqual(hit.entry.id, "ddsc-nightly-restart")
                self.assertIn("62", hit.label)

    def test_ddsc_known_needs_both_markers(self):
        epoch = at(2026, 10, 21, 3, 5)
        for message in ("[Errno 111] Connection refused", "socket closed", "廠商甲 602 電文查詢失敗",
                        "查詢 705 失敗"):
            self.assertIsNone(known.match_known(self.entries, alert(message=message, task_pk=35),
                                                epoch, "cms", action="known"), message)

    def test_ddsc_known_is_scoped_to_the_calling_systems_and_tasks(self):
        message = "廠商甲 602 電文查詢失敗 [Errno 111] Connection refused"
        epoch = at(2026, 10, 21, 3, 5)
        for system, pk in (("pxy", 35), ("cms", 99), ("cms", None), ("fastpxy", 118)):
            self.assertIsNone(known.match_known(self.entries, alert(message=message, task_pk=pk),
                                                epoch, system, action="known"), (system, pk))
        self.assertIsNotNone(known.match_known(self.entries, alert(message=message, task_pk=99),
                                               epoch, "cms", action="context"))

    def test_bare_p999_or_management_error_is_context_only(self):
        for message in ("code: P999", "經管錯誤", "經管回傳 code: P001"):
            epoch = at(2026, 10, 21, 1, 30)
            self.assertIsNone(known.match_known(self.entries, alert(message=message, task_pk=35),
                                                epoch, "cms", action="known"), message)
            self.assertIsNotNone(known.match_known(self.entries, alert(message=message), epoch,
                                                   "cms", action="context"), message)

    def test_real_and_example_files_agree(self):
        real = EXAMPLE.with_name("known.toml")
        if not real.exists():
            self.skipTest("known.toml 不在 repo")
        self.assertEqual(real.read_text(encoding="utf-8"), EXAMPLE.read_text(encoding="utf-8"))

    def test_known_entries_default_to_two_minutes_grace_unless_justified(self):
        grace = {e.id: e.grace_minutes for e in self.entries if e.action == "known"}
        self.assertEqual(grace["middle-platform-midnight-restart"], 2)

    def test_ddsc_error_at_ten_does_not_match(self):
        message = "廠商甲 602 電文查詢失敗 [Errno 111] Connection refused"
        self.assertIsNone(known.match_known(self.entries, alert(message=message, task_pk=35),
                                            at(2026, 10, 21, 10, 0), "cms"))

    def test_middle_platform_restart_needs_marker_and_connection_failure(self):
        epoch = at(2026, 10, 21, 0, 0, 30)
        hit = known.match_known(self.entries, alert(message="中台 電文連線失敗", task_pk=35),
                                epoch, "cms", action="known")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.entry.id, "middle-platform-midnight-restart")
        hit = known.match_known(self.entries, alert(message="middleware Connection refused",
                                                    task_pk=118), epoch, "sso", action="known")
        self.assertEqual(hit.entry.id, "middle-platform-midnight-restart")
        self.assertIsNone(known.match_known(self.entries, alert(message="電文連線失敗", task_pk=35),
                                            epoch, "pxy", action="known"))

    def test_bare_p999_at_midnight_is_context_only(self):
        for epoch in (at(2026, 10, 20, 23, 56), at(2026, 10, 21, 0, 0, 30), at(2026, 10, 21, 0, 5)):
            message = alert(message="經管回傳 code: P999", task_pk=35)
            self.assertIsNone(known.match_known(self.entries, message, epoch, "cms", action="known"))
            hit = known.match_known(self.entries, message, epoch, "cms", action="context")
            self.assertIsNotNone(hit)

    def test_middle_platform_grace_is_two_minutes(self):
        message = alert(message="中台 電文連線失敗", task_pk=35)
        self.assertIsNotNone(known.match_known(self.entries, message, at(2026, 10, 21, 0, 3), "cms",
                                               action="known"))
        hit = known.match_known(self.entries, message, at(2026, 10, 20, 23, 57), "cms", action="known")
        self.assertTrue(hit is None or hit.entry.id != "middle-platform-midnight-restart")

    def test_unrelated_error_inside_window_does_not_match(self):
        self.assertIsNone(known.match_known(
            self.entries, alert(message="KeyError: 'phone'", task_pk=35), at(2026, 10, 21, 3, 5), "cms"))


class BackgroundTest(unittest.TestCase):
    def test_overlapping_window_included_even_without_text_match(self):
        entries = load()
        found = known.background(entries, alert(message="KeyError"), at(2026, 10, 21, 3, 20),
                                 at(2026, 10, 21, 3, 30), "cms")
        self.assertEqual([b["id"] for b in found], ["e1"])
        self.assertTrue(found[0]["in_window"])
        self.assertFalse(found[0]["text_match"])
        self.assertEqual(found[0]["overlapping_windows"], ["03:00–03:10"])

    def test_text_match_included_outside_window(self):
        found = known.background(load(), alert(), at(2026, 10, 21, 10, 0), at(2026, 10, 21, 10, 5), "cms")
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0]["in_window"])
        self.assertTrue(found[0]["text_match"])

    def test_unrelated_and_expired_entries_left_out(self):
        self.assertEqual(known.background(load(), alert(message="KeyError"), at(2026, 10, 21, 10, 0),
                                          at(2026, 10, 21, 10, 5), "cms"), [])
        self.assertEqual(known.background(load(extra="expires = 2026-10-01"), alert(),
                                          at(2026, 10, 21, 3, 0), at(2026, 10, 21, 3, 5), "cms"), [])

    def test_long_incident_overlaps(self):
        found = known.background(load(), alert(message="x"), at(2026, 10, 18, 12, 0),
                                 at(2026, 10, 21, 1, 0), "cms")
        self.assertEqual(len(found), 1)


class SourceTest(unittest.TestCase):
    def test_reloads_on_change_and_keeps_last_good_on_error(self):
        path = write(entry_text(id="a"))
        self.addCleanup(os.unlink, path)
        source = known.KnownSource(path)
        self.assertEqual([e.id for e in source.entries()], ["a"])
        Path(path).write_text("[[known]]\nid = \"broken\"\n", encoding="utf-8")
        later = time.time() + 5
        os.utime(path, (later, later))
        self.assertEqual([e.id for e in source.entries()], ["a"])

    def test_static_list(self):
        entries = load()
        self.assertEqual(known.as_source(entries).entries(), entries)

    def test_missing_path(self):
        self.assertEqual(known.KnownSource("").entries(), [])


if __name__ == "__main__":
    unittest.main()
