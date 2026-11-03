import unittest

from alert_doctor import replies
from alert_doctor.models import Evidence, Incident, RuleMatch


def incident(**kw):
    base = dict(id=7, fingerprint="f", group_fp="g", check_code="C1", check_title="t",
                channel="C", anchor_ts="1.0", first_epoch=0, last_epoch=0, count=3,
                analysis_state="none")
    base.update(kw)
    return Incident(**base)


VERDICT = {"category": "code_bug", "severity": "high", "confidence": 0.8,
           "cause": "發簡訊時 KeyError,排程中斷", "impact": "客戶收不到 T+1 通知",
           "project": "acme-backend", "action": "fix_code", "fix": ["改用 .get()", "手動補發"],
           "logs": ["10/20 14:00:01 | 開始", "10/20 14:00:07 | KeyError: 'phone'"],
           "remark": "需業務確認名單", "fix_in_system": "cms", "needs_human": False,
           "evidence": [{"type": "code", "repo": "acme-backend", "file": "app/a.py",
                         "line": 12, "note": "直接取 phone"},
                        {"type": "elk", "key": "total"}]}
OLD_VERDICT = {"category": "unknown", "severity": "medium", "confidence": 0.4,
               "summary": "SSO 沒取到回檔", "root_cause": "很長的根因說明",
               "suggested_action": "1. 查 ELK 2. 問廠商乙", "fix_in_system": "unknown",
               "needs_human": True,
               "evidence": [{"type": "code", "repo": "acme-sso", "file": "utils/ftp.py",
                             "line": 213},
                            {"type": "elk", "key": "candidates"}]}


class TestReplies(unittest.TestCase):
    def test_spike_followup(self):
        text = replies.spike_followup(incident(count=9), "https://w/p1")
        for part in ("⚠️ 突增中", "累計 9 則", "分析見 → https://w/p1"):
            self.assertIn(part, text)

    def test_noise_with_evidence(self):
        ev = Evidence(True, "2026-10-19T10:00:00+08:00", "2026-10-19T10:17:00+08:00",
                      total=4, per_host={"a": 4})
        text = replies.noise(RuleMatch("r", "noise", note="重啟抖動"), ev)
        for part in ("🔇", "重啟抖動", "近 15 分鐘", "4 筆", "1 台", "已恢復"):
            self.assertIn(part, text)

    def test_noise_without_evidence(self):
        text = replies.noise(RuleMatch("r", "noise", note="x"), None)
        self.assertNotIn("ELK", text)

    def test_known_with_and_without_link(self):
        self.assertIn("https://l", replies.known(RuleMatch("r", "known", note="n", link="https://l")))
        self.assertTrue(replies.known(RuleMatch("r", "known", note="n")).endswith("n"))

    def test_duplicate(self):
        text = replies.duplicate(incident(), "https://p")
        for part in ("#7", "3", "https://p"):
            self.assertIn(part, text)

    def test_analyzing(self):
        self.assertIn("新錯誤", replies.analyzing(incident(), False))
        self.assertIn("突增", replies.analyzing(incident(), True))

    def test_critical_mentions_owners(self):
        text = replies.critical(incident(), ("U1", "U2"), False)
        self.assertTrue(text.startswith("<@U1> <@U2>"))
        self.assertNotIn("<@", replies.critical(incident(), (), False))

    def test_unparsed(self):
        self.assertIn("無法解析", replies.unparsed())

    def test_verdict_exact_layout(self):
        text = replies.verdict(VERDICT, title="[CMS] T+1交割款不足自動通知執行結果",
                               source_system="cms", project_system="cms")
        self.assertEqual(text, "\n".join([
            "🟠 *[CMS] T+1交割款不足自動通知執行結果*",
            "",
            "*錯誤原因*:\n  發簡訊時 KeyError,排程中斷",
            "",
            "*影響功能*:\n  客戶收不到 T+1 通知",
            "",
            "*專案*:\n  acme-backend(CMS 後台)",
            "",
            "*錯誤的程式碼*:",
            "  • `app/a.py:12`(acme-backend)直接取 phone",
            "",
            "*建議修正方法*:",
            "  🛠️ 需修改程式",
            "  1. 改用 .get()",
            "  2. 手動補發",
            "",
            "*真實Log*:",
            "```",
            "10/20 14:00:01 | 開始",
            "10/20 14:00:07 | KeyError: 'phone'",
            "```",
            "",
            "*備註*:\n  需業務確認名單",
        ]))

    def test_sections_separated_by_exactly_one_blank_line(self):
        full = ["🟠 *t*", "*錯誤原因*", "*影響功能*", "*專案*", "*錯誤的程式碼*", "*建議修正方法*",
                "*真實Log*", "*備註*"]
        cases = ((VERDICT, None, full),
                 ({**VERDICT, "logs": [], "evidence": [], "needs_human": True}, 1,
                  full + ["_沿用 1 小時前的分析_"]),
                 (OLD_VERDICT, 3, ["🟡 *t*", "*錯誤原因*", "*專案*", "*錯誤的程式碼*",
                                   "*建議修正方法*", "*真實Log*", "*備註*",
                                   "_沿用 3 小時前的分析_"]))
        for v, reused, expected in cases:
            text = replies.verdict(v, reused, title="t", human_owners=("U1",))
            self.assertNotIn("\n\n\n", text)
            self.assertFalse(text.startswith("\n") or text.endswith("\n"))
            sections = text.split("\n\n")
            self.assertEqual([sec.split("\n")[0].split(":")[0] for sec in sections], expected)

    def test_no_model_footer_category_or_essay_fields(self):
        text = replies.verdict({**VERDICT, "root_cause": "長篇根因"}, title="t")
        for absent in ("模型", "類別", "*根因*", "證據", "長篇根因", "candidates", "total", "@"):
            self.assertNotIn(absent, text)

    def test_empty_code_and_logs_fallbacks(self):
        text = replies.verdict({**VERDICT, "logs": [], "evidence": [{"type": "elk", "key": "x"}]})
        self.assertIn("\n\n*錯誤的程式碼*:\n  無(非程式問題)\n\n", text)
        self.assertIn("\n\n*真實Log*:\n  無(ELK 查無相關紀錄)", text)
        self.assertNotIn("```", text)

    def test_limits_truncate_with_ellipsis(self):
        v = {**VERDICT, "cause": "因" * 300, "impact": "影" * 200, "remark": "備" * 200,
             "fix": ["修" * 200, "b", "c", "d"], "logs": [f"line {i}" for i in range(9)],
             "evidence": [{"type": "code", "repo": "r", "file": f"f{i}.py", "line": i,
                           "note": "說" * 99} for i in range(1, 6)]}
        text = replies.verdict(v)
        self.assertIn("*錯誤原因*:\n  " + "因" * 239 + "…\n", text)
        self.assertIn("*影響功能*:\n  " + "影" * 119 + "…\n", text)
        self.assertIn("  1. " + "修" * 119 + "…\n", text)
        self.assertNotIn("4. d", text)
        self.assertIn("*備註*:\n  " + "備" * 119 + "…", text)
        self.assertIn("說" * 59 + "…", text)
        self.assertEqual(text.count("• `"), 3)
        self.assertIn("line 4\n```", text)
        self.assertNotIn("line 5", text)

    def test_slightly_over_prompt_length_is_not_cut(self):
        cause = "台網登入查無帳號,user_cm.get 丟 CacheManagerException(非 User.DoesNotExist)" * 2
        step = "user/views.py TWCALoginAPIView 的 except 加 CacheManagerException,查無資料回 INVALID_USER"
        text = replies.verdict({**VERDICT, "cause": cause, "fix": [step]})
        self.assertIn(cause + "\n", text)
        self.assertIn(step + "\n", text)

    def test_cap_inside_code_block_closes_the_fence(self):
        text = replies._cap("head\n```\n" + "x" * 5000)
        self.assertLessEqual(len(text), replies.MAX_CHARS)
        self.assertEqual(text.count("```") % 2, 0)
        self.assertTrue(text.endswith(replies.TRUNCATION_NOTE))

    def test_confidence_shown_only_below_threshold(self):
        self.assertNotIn("信心", replies.verdict(VERDICT))
        self.assertNotIn("信心", replies.verdict({**VERDICT, "confidence": 0.6}))
        text = replies.verdict({**VERDICT, "confidence": 0.35})
        self.assertIn("*備註*:\n  需業務確認名單 · 信心 35%", text)
        text = replies.verdict({**VERDICT, "confidence": 0.35, "remark": ""})
        self.assertIn("*備註*:\n  信心 35%", text)

    def test_remark_line_omitted_when_nothing_to_say(self):
        self.assertNotIn("備註", replies.verdict({**VERDICT, "remark": ""}))

    def test_verdict_reused_is_last_line(self):
        text = replies.verdict({**VERDICT, "needs_human": True}, 3)
        self.assertTrue(text.endswith("\n\n_沿用 3 小時前的分析_"))
        self.assertIn("需人工確認", text)
        self.assertNotIn("沿用", replies.verdict(VERDICT))

    def test_needs_human_mentions_human_owners_only_when_needed(self):
        text = replies.verdict({**VERDICT, "needs_human": True, "confidence": 0.4},
                               human_owners=("<@U5>", "S6"))
        self.assertIn("*備註*:\n  需業務確認名單 · 信心 40% · 需人工確認 <@U5> <!subteam^S6>", text)
        text = replies.verdict(VERDICT, human_owners=("<@U5>",))
        self.assertNotIn("<@U5>", text)

    def test_old_format_verdict_renders(self):
        text = replies.verdict(OLD_VERDICT, title="[check_oa_file_return] 久未處理開戶收檔-廠商乙",
                               source_system="sso")
        self.assertEqual(text, "\n".join([
            "🟡 *[check_oa_file_return] 久未處理開戶收檔-廠商乙*",
            "",
            "*錯誤原因*:\n  SSO 沒取到回檔",
            "",
            "*專案*:\n  acme-sso",
            "",
            "*錯誤的程式碼*:",
            "  • `utils/ftp.py:213`(acme-sso)",
            "",
            "*建議修正方法*:",
            "  1. 查 ELK 2. 問廠商乙",
            "",
            "*真實Log*:\n  無(ELK 查無相關紀錄)",
            "",
            "*備註*:\n  信心 40% · 需人工確認",
        ]))

    def test_project_falls_back_to_system_with_chinese_name(self):
        v = {**OLD_VERDICT, "evidence": []}
        self.assertIn("*專案*:\n  sso(SSO 會員)", replies.verdict(v, source_system="sso"))
        self.assertIn("*專案*:\n  未知", replies.verdict(v))

    def test_title_defaults_when_missing(self):
        self.assertTrue(replies.verdict(VERDICT).startswith("🟠 *分析結果*\n\n"))

    def test_log_lines_mask_tokens_and_customer_data(self):
        text = replies.verdict({**VERDICT, "logs": [
            "10/20 14:40:00 | 重新連線 L221849269, login_token 21O4obuGox6mYHmpOg4U, 0912345678"]})
        self.assertIn("10/20 14:40:00 | 重新連線 [身分證], login_token <redacted>, [手機]", text)
        self.assertNotIn("21O4obuGox", text)

    def test_log_fence_cannot_break_out(self):
        text = replies.verdict({**VERDICT, "logs": ["a ``` b"]})
        self.assertEqual(text.count("```"), 2)

    def test_critical_accepts_resolved_mentions(self):
        from alert_doctor.models import Incident
        inc = Incident(1, "f", "g", "c", "t", "C1", "1.0", 0, 0, 1, "none")
        text = replies.critical(inc, ("<@U1>", "U2", "<!subteam^S3>"), False)
        self.assertTrue(text.startswith("<@U1> <@U2> <!subteam^S3> "))

    def test_first_line_starts_with_severity_emoji(self):
        for sev, emoji in (("low", "🟢"), ("medium", "🟡"), ("high", "🟠"), ("critical", "🔴"),
                           ("weird", "⚪")):
            text = replies.verdict({**VERDICT, "severity": sev}, title="t")
            self.assertTrue(text.splitlines()[0].startswith(f"{emoji} *t*"), sev)

    def test_cross_system_note_and_mentions(self):
        v = {**VERDICT, "fix_in_system": "sso"}
        text = replies.verdict(v, source_system="pxy", owners=("U1", "<!subteam^S2>"))
        self.assertIn("*專案*:\n  acme-backend ↪️ 根因在 sso,請 <@U1> <!subteam^S2> 協助確認\n", text)
        self.assertTrue(text.splitlines()[0].startswith("🟠"))

    def test_no_cross_system_note_when_same_unknown_or_missing(self):
        for fix, src in (("pxy", "pxy"), ("unknown", "pxy"), ("sso", ""), (None, "pxy")):
            text = replies.verdict({**VERDICT, "fix_in_system": fix},
                                   source_system=src, owners=("U1",))
            self.assertNotIn("↪️", text)
            self.assertNotIn("<@U1>", text)

    def test_cross_system_without_owners_has_note_but_no_mention(self):
        text = replies.verdict({**VERDICT, "fix_in_system": "sso"}, source_system="pxy")
        self.assertIn("↪️ 根因在 sso\n", text)
        self.assertNotIn("<@", text)

    def test_code_evidence_without_repo_or_note(self):
        v = {**VERDICT, "evidence": [{"type": "code", "file": "a.py", "line": 3}]}
        self.assertIn("\n  • `a.py:3`\n", replies.verdict(v))

    def test_verdict_truncated(self):
        text = replies.verdict({**VERDICT, "logs": ["x" * 3000, "y" * 3000]})
        self.assertLessEqual(len(text), replies.MAX_CHARS)
        text = replies.verdict({**VERDICT, "logs": ["x" * 199] * 5, "evidence": [
            {"type": "code", "repo": "r" * 900, "file": "f" * 900, "line": 1}] * 3})
        self.assertLessEqual(len(text), replies.MAX_CHARS)
        self.assertIn("已截斷", text)

    def test_over_budget(self):
        self.assertIn("opus", replies.over_budget("opus"))

    def test_daily_report(self):
        cov = {"total": 10, "handled": 8, "failed": 1, "pending": 1,
               "unhandled": [("1.0", "T")], "by_category": {"noise": 5}}
        text = replies.daily_report(cov, {"sonnet": 3}, 2, "2026-10-19")
        for part in ("2026-10-19", "10", "已處理 8", "失敗 1", "noise 5", "sonnet 3", "積壓:2", "T"):
            self.assertIn(part, text)

    def test_health_alert(self):
        text = replies.health_alert(["a 壞了", "b 壞了"])
        self.assertIn("1. a 壞了", text)
        self.assertIn("2. b 壞了", text)


class TestV3Replies(unittest.TestCase):
    def test_first_report_mentions_first_line_then_decision_then_summary(self):
        text = replies.first_report(
            decision_text="🔍 新錯誤,已排入分析",
            summary={"count": 12, "hosts": 3, "window": "13:42", "severity": "high"},
            mentions=("<@U1>", "<@U2>"))
        lines = text.splitlines()
        self.assertEqual(lines[0], "<@U1> <@U2>")
        self.assertEqual(lines[1], "🔍 新錯誤,已排入分析")
        self.assertEqual(lines[2], "🟠 本分鐘 12 則 · 主機 3 台 · 13:42 起")

    def test_first_report_without_mentions_or_optional_summary(self):
        text = replies.first_report(decision_text="d", summary={"count": 1}, mentions=())
        self.assertEqual(text, "d\n本分鐘 1 則")

    def test_first_report_capped(self):
        text = replies.first_report(decision_text="x" * 9000, summary={}, mentions=())
        self.assertLessEqual(len(text), replies.MAX_CHARS)

    def test_minute_update_spec_shape_and_no_mention(self):
        text = replies.minute_update(incident_id=7, window_label="13:43", batch_count=180,
                                     total=650, hosts=3, changes=["量級翻倍", "嚴重度升級為 🔴"])
        self.assertEqual(text.splitlines(), [
            "📈 13:43 這一分鐘 180 則(累計 650 則),主機 3 台",
            "↑ 量級翻倍", "↑ 嚴重度升級為 🔴"])
        self.assertNotIn("<@", text)
        self.assertNotIn("<!", text)

    def test_minute_update_without_hosts_or_changes(self):
        text = replies.minute_update(incident_id=7, window_label="13:43", batch_count=1,
                                     total=2, hosts=None, changes=[])
        self.assertEqual(text, "📈 13:43 這一分鐘 1 則(累計 2 則)")

    def test_backfill_summary(self):
        text = replies.backfill_summary(count=40, first_ts_label="13:01", last_ts_label="13:20")
        for part in ("補撈", "40 則", "13:01", "13:20"):
            self.assertIn(part, text)

    def test_storm_overview(self):
        top = [{"incident_id": 3, "title": "DB 連線逾時", "count": 500, "hosts": 4,
                "severity": "critical", "link": "https://w/p3"},
               {"incident_id": 5, "title": "timeout", "count": 90, "hosts": None,
                "severity": "low", "link": ""}]
        text = replies.storm_overview(window_label="13:43", top=top, deferred=7, total_incidents=9)
        lines = text.splitlines()
        self.assertEqual(lines[0], "🌪️ 告警風暴(已降級)13:43")
        self.assertIn("9", lines[1])
        self.assertTrue(lines[2].startswith("1. "))
        for part in ("🔴", "#3", "DB 連線逾時", "500 則", "4 台", "https://w/p3"):
            self.assertIn(part, lines[2])
        self.assertTrue(lines[3].startswith("2. "))
        self.assertNotIn("台", lines[3])
        self.assertEqual(lines[-1], "另有 7 件未列出(皆已分類記錄)")
        self.assertNotIn("延後", text)
        self.assertNotIn("<@", text)

    def test_storm_overview_lists_the_rest_compactly(self):
        top = [{"incident_id": 1, "title": "A", "count": 50, "link": "https://w/p1"}]
        others = [{"incident_id": 2, "title": "B", "count": 7},
                  {"incident_id": 3, "title": "C", "count": 1}]
        text = replies.storm_overview(window_label="13:43", top=top, others=others,
                                      total_incidents=3)
        lines = text.splitlines()
        self.assertEqual(lines[-3:], ["其餘 2 件:", "#2 B · 7 則", "#3 C · 1 則"])
        self.assertNotIn("延後", text)
        self.assertNotIn("另", lines[-1])

    def test_storm_overview_caps_long_tail_with_overflow_count(self):
        top = [{"incident_id": i, "title": "很長的檢查名稱" * 5, "count": 9, "link": "https://w/p"}
               for i in range(10)]
        others = [{"incident_id": 100 + i, "title": "排程檢查名稱" * 3, "count": 1}
                  for i in range(500)]
        text = replies.storm_overview(window_label="13:43", top=top, others=others,
                                      total_incidents=510)
        self.assertLessEqual(len(text), replies.MAX_CHARS)
        self.assertNotIn("截斷", text)
        listed = sum(1 for line in text.splitlines() if line.startswith("#"))
        self.assertGreater(listed, 10)
        self.assertEqual(text.splitlines()[-1], f"…另 {500 - listed} 件")

    def test_storm_overview_without_deferred_omits_line(self):
        text = replies.storm_overview(window_label="13:43", top=[], deferred=0, total_incidents=0)
        self.assertNotIn("延後", text)

    def test_protection_notice_entering_and_exiting(self):
        enter = replies.protection_notice(entering=True, reason="intake 1200 則/分鐘",
                                          mentions=("<@U1>",))
        self.assertTrue(enter.startswith("<@U1>"))
        for part in ("🌪️", "降級", "intake 1200 則/分鐘", "CRITICAL", "不會被合併",
                     "前 3", "30 分鐘"):
            self.assertIn(part, enter)
        self.assertNotIn("逐則處理", enter)
        leave = replies.protection_notice(entering=False, reason="已連續 5 分鐘低於門檻",
                                          mentions=())
        for part in ("✅", "恢復", "已連續 5 分鐘低於門檻"):
            self.assertIn(part, leave)
        self.assertNotIn("<@", leave)

    def test_report_link(self):
        text = replies.report_link("https://w/p1")
        self.assertIn("https://w/p1", text)


# 2026-09-28 10:00 Taipei
SEP_28 = 1790560800.0


class OccurrenceLineTest(unittest.TestCase):
    def stats(self, **kw):
        return {"today": 3, "d7": 5, "d30": 12, "first_epoch": SEP_28,
                "last_before_epoch": None, **kw}

    def test_full_line(self):
        self.assertEqual(replies.occurrence_line(self.stats()),
                         "📊 出現次數:今日 3 次 · 近 7 日 5 次 · 近 30 日 12 次 · 首次 09/28")

    def test_first_date_in_taipei(self):
        late_utc = SEP_28 + 14 * 3600  # 09/29 00:00 Taipei, still 09/28 in UTC
        self.assertTrue(replies.occurrence_line(self.stats(first_epoch=late_utc))
                        .endswith("首次 09/29"))

    def test_unknown_first_omitted(self):
        self.assertEqual(replies.occurrence_line(self.stats(first_epoch=None)),
                         "📊 出現次數:今日 3 次 · 近 7 日 5 次 · 近 30 日 12 次")

    def test_single_occurrence_in_30_days(self):
        self.assertEqual(replies.occurrence_line(self.stats(today=1, d7=1, d30=1)),
                         "📊 出現次數:近 30 日首次出現")

    def test_nothing_counted_is_empty(self):
        self.assertEqual(replies.occurrence_line(self.stats(today=0, d7=0, d30=0)), "")
        self.assertEqual(replies.occurrence_line(None), "")

    def test_append_section_blank_line_and_survives_cap(self):
        self.assertEqual(replies.append_section("a\nb", "📊 x"), "a\nb\n\n📊 x")
        self.assertEqual(replies.append_section("a", ""), "a")
        long = replies.append_section("x" * replies.MAX_CHARS, "📊 x")
        self.assertLessEqual(len(long), replies.MAX_CHARS)
        self.assertTrue(long.endswith("\n\n📊 x"))
        self.assertIn(replies.TRUNCATION_NOTE, long)


if __name__ == "__main__":
    unittest.main()
