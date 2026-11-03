import unittest

from alert_doctor import known_store
from alert_doctor.archive import error_key
from alert_doctor.models import ParsedAlert
from alert_doctor.store import Store

NOW = 1_792_523_100.0  # 2026-10-21 03:05 Taipei


DAY = 86400
CUT_SAMPLE = ("['SSO']服務中出現異常關鍵字「['M999']」，請立即查看系統狀況！"
              "「{'request_path': '/user/a/', 'request_body': b'{\"ino_list\": [\"A1\"")


def alert(message="經管回傳 code: P999 ino='F1'", pk=35, code="MDl", level=40, truncated=False):
    extra = {"vkwargs": {"crontab_task_pk": pk, "crontab_task_label": "檢查 P999"}} if pk else {}
    return ParsedAlert(channel="C1", ts="1.0", raw_text="", parse_ok=True, check_title="[check]",
                       check_code=code, level=level, result_message=message, extra=extra,
                       truncated=truncated)


class Base(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        known_store.ensure_schema(self.store)


class EntryAndLinkTest(Base):
    def test_error_key_is_the_archive_key(self):
        self.assertEqual(known_store.alert_error_key(alert(), source_system="cms"),
                         error_key(35, "MDl", 40, alert().result_message, "cms"))
        self.assertEqual(known_store.alert_error_key(alert(pk=None), source_system="cms"),
                         error_key(None, "MDl", 40, alert().result_message, "cms"))
        self.assertIsNone(known_store.alert_error_key(alert(pk=None, code=None)))

    def test_error_key_is_per_source_system(self):
        self.assertNotEqual(known_store.alert_error_key(alert(), source_system="cms"),
                            known_store.alert_error_key(alert(), source_system="sso"))

    def test_same_template_different_volatile_tokens_share_a_key(self):
        a = known_store.alert_error_key(alert(message="ino='F127894093' 經管回傳 code: P999"))
        b = known_store.alert_error_key(alert(message="ino='A223456789' 經管回傳 code: P999"))
        self.assertEqual(a, b)

    def test_ensure_schema_is_idempotent(self):
        known_store.ensure_schema(self.store)

    def test_add_is_idempotent_and_keeps_the_first(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW, description="一")
        again = known_store.add_entry(self.store, "ddsc", "別的", now=NOW + 1)
        self.assertEqual((again.title, again.description), ("廠商甲重啟", "一"))

    def test_add_validates(self):
        with self.assertRaises(ValueError):
            known_store.add_entry(self.store, "", "t", now=NOW)
        with self.assertRaises(ValueError):
            known_store.add_entry(self.store, "x", "t", now=NOW, expires="明天")

    def test_link_lookup_unlink(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW, description="凌晨重啟")
        key = known_store.alert_error_key(alert())
        self.assertIsNone(known_store.lookup(self.store, key))
        known_store.link(self.store, key, "ddsc", now=NOW, linked_by="U1", sample_message="m")
        hit = known_store.lookup(self.store, key, NOW)
        self.assertEqual((hit.entry.id, hit.linked_by, hit.sample_message), ("ddsc", "U1", "m"))
        self.assertIn("廠商甲重啟", hit.reply_text())
        self.assertIn("凌晨重啟", hit.reply_text())
        self.assertEqual(known_store.unlink(self.store, key).id, "ddsc")
        self.assertIsNone(known_store.lookup(self.store, key))
        self.assertIsNone(known_store.unlink(self.store, key))

    def test_lookup_without_key(self):
        self.assertIsNone(known_store.lookup(self.store, None))

    def test_relink_moves_the_key(self):
        for entry_id in ("a", "b"):
            known_store.add_entry(self.store, entry_id, entry_id, now=NOW)
        known_store.link(self.store, "k", "a", now=NOW)
        known_store.link(self.store, "k", "b", now=NOW)
        self.assertEqual(known_store.lookup(self.store, "k").entry.id, "b")

    def test_link_to_missing_entry_rejected(self):
        with self.assertRaises(ValueError):
            known_store.link(self.store, "k", "nope", now=NOW)

    def test_link_expires_after_fourteen_days_by_default(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        known_store.link(self.store, "k", "ddsc", now=NOW, linked_by="U1")
        hit = known_store.lookup(self.store, "k", NOW + 14 * DAY - 1)
        self.assertEqual(hit.expires_at, NOW + 14 * DAY)
        self.assertIsNone(known_store.lookup(self.store, "k", NOW + 14 * DAY))

    def test_link_days_are_capped(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        known_store.link(self.store, "k", "ddsc", now=NOW, days=365)
        self.assertEqual(known_store.lookup(self.store, "k", NOW).expires_at, NOW + 90 * DAY)
        with self.assertRaises(ValueError):
            known_store.link(self.store, "k", "ddsc", now=NOW, days=0)

    def test_relink_is_a_review_that_keeps_creator_and_counters(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        self.assertTrue(known_store.link(self.store, "k", "ddsc", now=NOW, linked_by="U1"))
        known_store.record_hit(self.store, "k", NOW + 10)
        self.assertFalse(known_store.link(self.store, "k", "ddsc", now=NOW + DAY, linked_by="U2",
                                          days=30))
        [row] = known_store.links_of(self.store, "ddsc")
        self.assertEqual((row["created_by"], row["linked_by"], row["last_reviewed_by"],
                          row["last_reviewed_at"], row["hit_count"], row["expires_at"]),
                         ("U1", "U2", "U2", NOW + DAY, 1, NOW + 31 * DAY))

    def test_hits_update_counters(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        known_store.link(self.store, "k", "ddsc", now=NOW)
        known_store.record_hit(self.store, "k", NOW + 5)
        known_store.record_hit(self.store, "k", NOW + 9)
        known_store.record_hit(self.store, "missing", NOW + 9)
        hit = known_store.lookup(self.store, "k", NOW + 10)
        self.assertEqual((hit.hit_count, hit.first_hit_at, hit.last_hit_at), (2, NOW + 5, NOW + 9))

    def test_old_links_table_is_migrated_with_an_expiry(self):
        store = Store(":memory:")
        with store.tx() as db:
            db.execute("CREATE TABLE known_links (error_key TEXT PRIMARY KEY, known_id TEXT NOT NULL,"
                       " linked_by TEXT NOT NULL DEFAULT '', linked_at REAL NOT NULL,"
                       " sample_message TEXT NOT NULL DEFAULT '', sample_label TEXT NOT NULL DEFAULT '')")
            db.execute("INSERT INTO known_links VALUES ('k', 'ddsc', 'U1', ?, '', '')", (NOW,))
        known_store.ensure_schema(store)
        known_store.ensure_schema(store)
        known_store.add_entry(store, "ddsc", "廠商甲重啟", now=NOW)
        hit = known_store.lookup(store, "k", NOW)
        self.assertEqual((hit.expires_at, hit.hit_count), (NOW + 14 * DAY, 0))
        [row] = known_store.links_of(store, "ddsc")
        self.assertEqual(row["created_by"], "U1")

    def test_expired_entry_is_not_a_hit(self):
        known_store.add_entry(self.store, "old", "舊", now=NOW, expires="2026-10-20")
        known_store.link(self.store, "k", "old", now=NOW)
        self.assertIsNone(known_store.lookup(self.store, "k", NOW))
        self.assertIsNotNone(known_store.lookup(self.store, "k", NOW - 86400))

    def test_search_and_list(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW, description="主機輪流重啟")
        known_store.add_entry(self.store, "sso", "SSO 逾時", now=NOW + 1)
        known_store.link(self.store, "k1", "ddsc", now=NOW, sample_message="602 Connection refused")
        known_store.link(self.store, "k2", "ddsc", now=NOW + 5, sample_message="P999 經管回傳")
        self.assertEqual([r["id"] for r in known_store.search(self.store, "輪流")], ["ddsc"])
        self.assertEqual([r["id"] for r in known_store.search(self.store, "refused")], ["ddsc"])
        [found] = known_store.search(self.store, "廠商甲")
        self.assertEqual((found["links"], found["sample"]), (2, "P999 經管回傳"))
        self.assertEqual(known_store.search(self.store, "沒有這個"), [])
        listed = {r["id"]: r["links"] for r in known_store.list_entries(self.store)}
        self.assertEqual(listed, {"ddsc": 2, "sso": 0})

    def test_search_limit(self):
        for i in range(15):
            known_store.add_entry(self.store, f"e{i}", f"廠商甲 {i}", now=NOW + i)
        self.assertEqual(len(known_store.search(self.store, "廠商甲")), 10)

    def test_slug(self):
        self.assertEqual(known_store.slug("廠商甲 主機/重啟"), "廠商甲-主機-重啟")
        self.assertEqual(known_store.slug("  DDSC Restart! "), "ddsc-restart")
        self.assertEqual(known_store.slug("!!!"), "known")


class CommandTest(Base):
    def test_parse_command(self):
        self.assertEqual(known_store.parse_command("<@UBOT> 固定錯誤 廠商甲重啟"), ("固定錯誤", "廠商甲重啟"))
        self.assertEqual(known_store.parse_command("<@UBOT|alertdoctor> 取消固定"), ("取消固定", ""))
        self.assertEqual(known_store.parse_command("<@UBOT> 查 P999"), ("查", "P999"))
        self.assertIsNone(known_store.parse_command("<@UBOT> 這是什麼"))
        self.assertIsNone(known_store.parse_command("<@UBOT> 查詢一下"))

    def run_command(self, text, a=None, user="U1", can_edit=True):
        return known_store.handle_command(self.store, *known_store.parse_command(text), alert=a,
                                          user=user, now=NOW, source_system="cms",
                                          can_edit=can_edit)

    def key(self, a=None):
        return known_store.alert_error_key(a or alert(), source_system="cms")

    def test_link_creates_entry_and_links_anchor_error(self):
        reply = self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", alert())
        self.assertEqual(reply, "已將此錯誤樣式連結到【廠商甲主機重啟】,之後相同錯誤直接回覆不再分析"
                                "(連結 2026-11-04 到期,到期後恢復分析)")
        hit = known_store.lookup(self.store, self.key())
        self.assertEqual((hit.entry.id, hit.entry.created_by, hit.linked_by, hit.sample_label),
                         ("廠商甲主機重啟", "U1", "U1", "檢查 P999"))
        self.assertIn("<@U1>", hit.entry.source)

    def test_link_to_existing_id_reuses_it(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        self.assertIn("【廠商甲重啟】", self.run_command("<@UBOT> 固定錯誤 ddsc", alert()))
        self.assertEqual(len(known_store.list_entries(self.store)), 1)

    def test_link_by_existing_title(self):
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW)
        self.run_command("<@UBOT> 固定錯誤 廠商甲重啟", alert())
        self.assertEqual(known_store.lookup(self.store, self.key()).entry.id, "ddsc")

    def test_link_with_days(self):
        reply = self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟 30天", alert())
        self.assertIn("【廠商甲主機重啟】", reply)
        self.assertIn("2026-11-20 到期", reply)
        self.assertEqual(known_store.lookup(self.store, self.key(), NOW).expires_at, NOW + 30 * DAY)

    def test_link_days_over_the_cap_say_so(self):
        reply = self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟 120 天", alert())
        self.assertIn("最多 90 天", reply)
        self.assertEqual(known_store.lookup(self.store, self.key(), NOW).expires_at, NOW + 90 * DAY)

    def test_non_editors_cannot_link_or_unlink(self):
        reply = self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", alert(), user="U9", can_edit=False)
        self.assertIn("known_editors", reply)
        self.assertIsNone(known_store.lookup(self.store, self.key()))
        self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", alert())
        self.assertIn("known_editors",
                      self.run_command("<@UBOT> 取消固定", alert(), user="U9", can_edit=False))
        self.assertIsNotNone(known_store.lookup(self.store, self.key()))
        self.assertIn("`廠商甲主機重啟`", self.run_command("<@UBOT> 查 P999", user="U9", can_edit=False))

    def test_unreliable_signature_is_not_linked(self):
        for a in (alert(truncated=True), alert(message=CUT_SAMPLE)):
            with self.subTest(a=a.result_message[:20]):
                reply = self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", a)
                self.assertIn("無法固定", reply)
                self.assertIsNone(known_store.lookup(self.store, self.key(a)))
        self.assertIn("截斷", self.run_command("<@UBOT> 固定錯誤 x", alert(truncated=True)))

    def test_link_outside_alert_thread(self):
        self.assertEqual(self.run_command("<@UBOT> 固定錯誤 x", None), known_store.NEED_THREAD)
        self.assertEqual(known_store.list_entries(self.store), [])

    def test_link_without_title_shows_usage(self):
        self.assertIn("用法", self.run_command("<@UBOT> 固定錯誤", alert()))

    def test_unlink(self):
        self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", alert())
        self.assertIn("已取消", self.run_command("<@UBOT> 取消固定", alert()))
        self.assertIsNone(known_store.lookup(self.store, self.key()))
        self.assertIn("沒有連結", self.run_command("<@UBOT> 取消固定", alert()))

    def test_search(self):
        self.run_command("<@UBOT> 固定錯誤 廠商甲主機重啟", alert())
        reply = self.run_command("<@UBOT> 查 P999")
        self.assertIn("`廠商甲主機重啟`", reply)
        self.assertIn("已連結 1 種錯誤", reply)
        self.assertIn("找不到", self.run_command("<@UBOT> 查 不存在"))


class ReviewTest(Base):
    def setUp(self):
        super().setUp()
        known_store.add_entry(self.store, "ddsc", "廠商甲重啟", now=NOW - 30 * DAY)

    def link(self, key, at, days=14):
        known_store.link(self.store, key, "ddsc", now=at, linked_by="U1", sample_label=key, days=days)

    def test_review_buckets(self):
        self.link("expiring", NOW - 12 * DAY)
        self.link("expired", NOW - 20 * DAY)
        self.link("idle", NOW - 20 * DAY, days=60)
        self.link("busy", NOW - DAY, days=30)
        self.link("fine", NOW - DAY, days=30)
        known_store.record_hit(self.store, "fine", NOW - 3600)
        for i in range(50):
            known_store.record_hit(self.store, "busy", NOW - 6 * DAY + i)
        known_store.record_hit(self.store, "expiring", NOW - 3600)
        found = known_store.review(self.store, NOW)
        keys = {bucket: [r["error_key"] for r in rows] for bucket, rows in found.items()}
        self.assertEqual(keys, {"expiring": ["expiring"], "expired": ["expired"], "idle": ["idle"],
                                "busy": ["busy"]})
        self.assertEqual(found["busy"][0]["hits_7d"], 50)

    def test_a_recent_review_is_not_idle(self):
        self.link("k", NOW - 20 * DAY, days=60)
        self.link("k", NOW - DAY, days=60)
        self.assertEqual(known_store.review(self.store, NOW)["idle"], [])

    def test_hits_older_than_seven_days_are_not_busy(self):
        self.link("old", NOW - 20 * DAY, days=60)
        for i in range(60):
            known_store.record_hit(self.store, "old", NOW - 9 * DAY + i)
        self.assertEqual(known_store.review(self.store, NOW)["busy"], [])

    def test_expired_link_is_not_looked_up_but_is_reviewed(self):
        self.link("k", NOW - 15 * DAY)
        self.assertIsNone(known_store.lookup(self.store, "k", NOW))
        self.assertEqual([r["error_key"] for r in known_store.review(self.store, NOW)["expired"]], ["k"])


if __name__ == "__main__":
    unittest.main()
