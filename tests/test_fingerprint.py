import hashlib
import unittest

from alert_doctor.fingerprint import (
    FINGERPRINT_VERSION, fine_fp, group_fp, signature, signature_is_reliable, template,
)
from alert_doctor.models import ParsedAlert


def alert(message, code="c1", level=40, title="T"):
    return ParsedAlert(
        channel="C", ts="1.0", raw_text="", parse_ok=True,
        check_title=title, check_code=code, level=level, result_message=message,
    )


class TemplateTest(unittest.TestCase):
    def test_numbers(self):
        self.assertEqual(template("5xx 次數 37 超過門檻 20"), "5xx 次數 <n> 超過門檻 <n>")

    def test_http_status_kept_and_ip(self):
        self.assertEqual(template("status 502 from 10.0.0.100"), "status 502 from <ip>")

    def test_alnum_codes_kept(self):
        self.assertEqual(template("ORS111 failed in 12.5 sec"), "ORS111 failed in <n> sec")
        self.assertEqual(template("code M999 x"), "code M999 x")

    def test_status_range_edges(self):
        self.assertEqual(template("99 100 599 600"), "<n> 100 599 <n>")

    def test_status_adjacent_to_alnum_not_kept(self):
        self.assertEqual(template("502ms"), "502ms")
        self.assertEqual(template("狀態 502 次 503次"), "狀態 502 次 503次")
        self.assertEqual(template("37次"), "<n>次")
        self.assertEqual(template("502.5"), "<n>")

    def test_uuid(self):
        self.assertEqual(
            template("task 123e4567-e89b-12d3-a456-426614174000 done"), "task <uuid> done"
        )

    def test_jwt(self):
        self.assertEqual(template("token eyJhbGci.eyJzdWIi.sig-_1 bad"), "token <jwt> bad")

    def test_iso_time(self):
        self.assertEqual(template("at 2026-10-19T09:30:15+08:00 x"), "at <time> x")
        self.assertEqual(template("at 2026-10-19 09:30:15.123Z x"), "at <time> x")
        self.assertEqual(template("at 2026-10-19 09:30 x"), "at <time> x")

    def test_long_hex(self):
        self.assertEqual(template("id deadbeefdeadbeef0123 x"), "id <hex> x")
        self.assertEqual(template("id deadbeef x"), "id deadbeef x")

    def test_whitespace_collapsed(self):
        self.assertEqual(template("a   b\n\tc"), "a b c")


class FingerprintTest(unittest.TestCase):
    def test_fine_fp_shape(self):
        fp = fine_fp(alert("x"))
        self.assertEqual(len(fp), 40)
        int(fp, 16)

    def test_fine_equal_when_only_numbers_differ(self):
        self.assertEqual(
            fine_fp(alert("5xx 次數 37 超過門檻 20")), fine_fp(alert("5xx 次數 51 超過門檻 20"))
        )

    def test_fine_differs_on_status(self):
        self.assertNotEqual(fine_fp(alert("status 502")), fine_fp(alert("status 504")))

    def test_group_equal_across_status(self):
        self.assertEqual(group_fp(alert("status 502")), group_fp(alert("status 504")))

    def test_level_separates(self):
        self.assertNotEqual(fine_fp(alert("x", level=30)), fine_fp(alert("x", level=40)))
        self.assertNotEqual(group_fp(alert("x", level=30)), group_fp(alert("x", level=40)))

    def test_falls_back_to_title(self):
        a = alert("x", code=None, title="Title A")
        b = alert("x", code=None, title="Title B")
        self.assertNotEqual(fine_fp(a), fine_fp(b))
        self.assertNotEqual(group_fp(a), group_fp(b))
        self.assertEqual(fine_fp(a), fine_fp(alert("x", code=None, title="Title A")))

    def test_code_wins_over_title(self):
        self.assertEqual(
            fine_fp(alert("x", code="k", title="A")), fine_fp(alert("x", code="k", title="B"))
        )



KEYWORD_HEAD = "['SSO']服務中出現異常關鍵字「['M999']」，請立即查看系統狀況！"


def keyword_hit(path="/user/eligible_account/", host="prod-app-oa-91", uuid="7LpHE5s0UP8r",
                body='{"encrypted":"gnV/rAUYhj9jgB22PTEbSBvjjnIsFjnh"}', code="M999",
                msg="無法預期的錯誤 timed out", head=KEYWORD_HEAD, close="」"):
    hit = {"remote_address": "198.51.100.253", "server_hostname": host, "request_method": "POST",
           "request_path": path, "request_body": body.encode(), "response_status": 200,
           "req_uuid": uuid, "code": code, "msg": msg, "run_time": 10.019}
    return f"{head}「{hit!r}{close}"


class BracketIdTest(unittest.TestCase):
    def test_short_random_ids_in_brackets_masked(self):
        for raw in ("[sD4Urd]", "[nZpChK]", "[CCKMR0]", "[lF2VGG]", "[a1b2c3d4]"):
            self.assertEqual(template(f"{raw} 無效的使用者 ES 異常"), "[<id>] 無效的使用者 ES 異常", raw)

    def test_words_codes_and_long_tokens_in_brackets_kept(self):
        for raw in ("[ERROR]", "[Warning]", "[M999]", "[SSO]", "[L3]", "[sso]", "[abcdefghi1]"):
            self.assertEqual(template(f"{raw} x"), f"{raw} x", raw)


class SignatureTest(unittest.TestCase):
    def test_plain_message_is_its_template(self):
        message = "ES連線出現異常，請立即檢查：[10.0.0.100] Connection timed out"
        self.assertEqual(signature(message), template(message))

    def test_volatile_parts_of_the_sample_dropped(self):
        a = keyword_hit()
        b = keyword_hit(host="prod-app-oa-tc-91", uuid="pWwYHDcZU4o3",
                        body='{"encrypted":"gnV/rAUYhj99M1j/GPXYgkULs0/zqbhU"}')
        self.assertEqual(signature(a), signature(b))
        self.assertNotIn("prod-app", signature(a))
        self.assertNotIn("gnV", signature(a))
        self.assertIn("/user/eligible_account/", signature(a))
        self.assertIn("M999", signature(a))

    def test_different_path_code_or_exception_stay_apart(self):
        base = signature(keyword_hit())
        self.assertNotEqual(base, signature(keyword_hit(path="/bcgw/user/login/")))
        self.assertNotEqual(base, signature(keyword_hit(code="P999")))
        self.assertNotEqual(base, signature(keyword_hit(
            msg="無法預期的錯誤 ConnectionTimeout caused by - ReadTimeoutError(x)")))
        self.assertNotEqual(base, signature(keyword_hit(msg="[Errno 111] Connection refused")))
        self.assertNotEqual(base, signature(keyword_hit(
            head="['SSO']服務中出現異常關鍵字「['M998']」，請立即查看系統狀況！")))

    def test_body_values_do_not_become_codes(self):
        a = keyword_hit(body='{"code": "P123", "sys_code": "005", "pawd": "KeyError"}')
        self.assertEqual(signature(a), signature(keyword_hit(body="{}")))

    def test_plain_text_sample_ids_dropped(self):
        a = KEYWORD_HEAD + "「\x1b[91m [sD4Urd] H124579395 台股 來源:008 無效的使用者 ES 異常 \x1b[0m」"
        b = KEYWORD_HEAD + "「\x1b[91m [nZpChK] F125045449 台股 來源:005 無效的使用者 ES 異常 \x1b[0m」"
        self.assertEqual(signature(a), signature(b))

    def test_code_and_exception_tokens_from_text_sample(self):
        sig = signature(KEYWORD_HEAD + "「[取得折抵金]失敗 原因: 經管回傳 code: P999, KeyError: 'x'」")
        self.assertIn("P999", sig)
        self.assertIn("KeyError", sig)
        self.assertNotEqual(sig, signature(KEYWORD_HEAD + "「[取得折抵金]失敗 原因: 經管回傳 code: P001」"))

    def test_truncated_sample_still_signed(self):
        whole = keyword_hit()
        cut = keyword_hit(body='{"ino_list": ["A1", "A2"' + ', "A3"' * 50, close="")[:300]
        self.assertIn("/user/eligible_account/", signature(cut))
        self.assertEqual(signature(cut).split("「")[0], signature(whole).split("「")[0])

    def test_fine_fp_uses_signature(self):
        self.assertEqual(fine_fp(alert(keyword_hit())), fine_fp(alert(keyword_hit(uuid="QR9VQQcg0pLc"))))
        self.assertNotEqual(fine_fp(alert(keyword_hit())),
                            fine_fp(alert(keyword_hit(path="/x/"))))


class ReliabilityTest(unittest.TestCase):
    def test_plain_and_complete_samples_are_reliable(self):
        self.assertTrue(signature_is_reliable("ES連線出現異常 Connection timed out"))
        self.assertTrue(signature_is_reliable(keyword_hit()))

    def test_cut_sample_without_codes_is_unreliable(self):
        cut = KEYWORD_HEAD + "「{'request_path': '/user/a/', 'request_body': b'{\"ino_list\": [\"A1\""
        self.assertFalse(signature_is_reliable(cut))

    def test_cut_sample_with_codes_is_reliable(self):
        cut = KEYWORD_HEAD + "「{'request_path': '/user/a/', 'response_status': 500, 'request_body': b'{"
        self.assertTrue(signature_is_reliable(cut))

    def test_truncated_parse_is_unreliable(self):
        self.assertFalse(signature_is_reliable(keyword_hit(), truncated=True))
        self.assertFalse(signature_is_reliable("plain", truncated=True))


class VersionTest(unittest.TestCase):
    def test_version_is_part_of_the_fine_fingerprint(self):
        self.assertEqual(FINGERPRINT_VERSION, 2)
        expected = hashlib.sha1("|".join(("v2", "c1", "40", signature("x"))).encode()).hexdigest()
        self.assertEqual(fine_fp(alert("x")), expected)


if __name__ == "__main__":
    unittest.main()


class NginxSampleSignatureTest(unittest.TestCase):
    """Keyword checks that quote a raw nginx access line instead of a 「…」 record."""
    BASE = ('pxy服務中出現X999異常情況，請立即查看系統狀況！192.0.2.75 - [21/Oct/2026:00:35:{s} +0800] '
            '"POST {path} HTTP/1.1" {status} {size} "" "AppClient/{ua}"')

    def line(self, path="/pxy/account/basic/", status=200, s="12", size=512, ua="1.0"):
        return self.BASE.format(path=path, status=status, s=s, size=size, ua=ua)

    def test_same_path_and_status_compare_equal(self):
        from alert_doctor.fingerprint import signature
        self.assertEqual(signature(self.line(s="12", size=512, ua="1.0")),
                         signature(self.line(s="59", size=9031, ua="2.3 (iPhone)")))

    def test_different_path_or_status_stay_apart(self):
        from alert_doctor.fingerprint import signature
        base = signature(self.line())
        self.assertNotEqual(base, signature(self.line(path="/pxy/account/get_cust_sb_fee/")))
        self.assertNotEqual(base, signature(self.line(status=502)))

    def test_query_string_ignored(self):
        from alert_doctor.fingerprint import signature
        self.assertEqual(signature(self.line(path="/pxy/a/?id=1")), signature(self.line(path="/pxy/a/?id=2")))
