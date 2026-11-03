import io
import json
import unittest
import urllib.error
from unittest import mock

from alert_doctor import slack_io


class FakeResponse:
    def __init__(self, body: dict):
        self.body = json.dumps(body).encode()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_returning(*bodies):
    queue = list(bodies)
    calls = []

    def opener(req, timeout=None):
        calls.append(req)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeResponse(item)

    opener.calls = calls
    return opener


class TestSlackIo(unittest.TestCase):
    def patch(self, *bodies):
        opener = opener_returning(*bodies)
        patcher = mock.patch.object(slack_io, "_opener", opener)
        patcher.start()
        self.addCleanup(patcher.stop)
        return opener

    def test_post_message_sends_thread_ts_and_returns_ts(self):
        opener = self.patch({"ok": True, "ts": "1.2"})
        self.assertEqual(slack_io.post_message("tok", "C1", "hi", thread_ts="9.9"), "1.2")
        req = opener.calls[0]
        self.assertEqual(json.loads(req.data)["thread_ts"], "9.9")
        self.assertEqual(req.get_header("Authorization"), "Bearer tok")

    def test_post_message_omits_thread_ts_by_default(self):
        opener = self.patch({"ok": True, "ts": "1.2"})
        slack_io.post_message("tok", "C1", "hi")
        self.assertNotIn("thread_ts", json.loads(opener.calls[0].data))

    def test_not_ok_raises_slack_error(self):
        self.patch({"ok": False, "error": "channel_not_found"})
        with self.assertRaises(slack_io.SlackError) as cm:
            slack_io.post_message("tok", "C1", "hi")
        self.assertEqual(cm.exception.error, "channel_not_found")

    def test_429_raises_rate_limited(self):
        err = urllib.error.HTTPError("u", 429, "Too Many", {"Retry-After": "7"}, io.BytesIO(b""))
        self.patch(err)
        with self.assertRaises(slack_io.SlackRateLimited) as cm:
            slack_io.post_message("tok", "C1", "hi")
        self.assertEqual(cm.exception.retry_after, 7)

    def test_other_http_error_propagates(self):
        err = urllib.error.HTTPError("u", 500, "Boom", {}, io.BytesIO(b""))
        self.patch(err)
        with self.assertRaises(urllib.error.HTTPError):
            slack_io.post_message("tok", "C1", "hi")

    def test_already_reacted_and_no_reaction_are_success(self):
        self.patch({"ok": False, "error": "already_reacted"},
                   {"ok": False, "error": "no_reaction"})
        slack_io.add_reaction("tok", "C1", "1.0", "mag")
        slack_io.remove_reaction("tok", "C1", "1.0", "mag")

    def test_reaction_other_error_raises(self):
        self.patch({"ok": False, "error": "invalid_name"})
        with self.assertRaises(slack_io.SlackError):
            slack_io.add_reaction("tok", "C1", "1.0", "nope")

    def test_history_follows_cursor_and_sorts_ascending(self):
        opener = self.patch(
            {"ok": True, "messages": [{"ts": "5.0"}, {"ts": "3.0"}],
             "response_metadata": {"next_cursor": "abc"}},
            {"ok": True, "messages": [{"ts": "4.0"}, {"ts": "1.0"}],
             "response_metadata": {"next_cursor": ""}})
        out = slack_io.history("tok", "C1", oldest="0")
        self.assertEqual([m["ts"] for m in out], ["1.0", "3.0", "4.0", "5.0"])
        self.assertIn("cursor=abc", opener.calls[1].full_url)
        self.assertNotIn("cursor", opener.calls[0].full_url)
        self.assertIn("oldest=0", opener.calls[0].full_url)

    def test_auth_test(self):
        self.patch({"ok": True, "user_id": "U1", "bot_id": "B1"})
        self.assertEqual(slack_io.auth_test("tok")["user_id"], "U1")

    def test_apps_connections_open_posts_form(self):
        opener = self.patch({"ok": True, "url": "wss://x"})
        self.assertEqual(slack_io.apps_connections_open("xapp"), "wss://x")
        self.assertEqual(opener.calls[0].get_header("Content-type"),
                         "application/x-www-form-urlencoded")

    def test_apps_connections_open_failure(self):
        self.patch({"ok": False, "error": "invalid_auth"})
        with self.assertRaises(slack_io.SlackError):
            slack_io.apps_connections_open("xapp")


if __name__ == "__main__":
    unittest.main()


class RawResponse:
    def __init__(self, data: bytes):
        self.stream = io.BytesIO(data)

    def read(self, n=-1):
        return self.stream.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestLookupAndDownload(unittest.TestCase):
    def patch_opener(self, opener):
        patcher = mock.patch.object(slack_io, "_opener", opener)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_lookup_user_by_email_returns_id(self):
        opener = opener_returning({"ok": True, "user": {"id": "U42"}})
        self.patch_opener(opener)
        self.assertEqual(slack_io.lookup_user_by_email("tok", "a@b.c"), "U42")
        self.assertIn("email=a%40b.c", opener.calls[0].full_url)

    def test_lookup_user_by_email_not_found_is_none(self):
        self.patch_opener(opener_returning({"ok": False, "error": "users_not_found"}))
        self.assertIsNone(slack_io.lookup_user_by_email("tok", "x@b.c"))

    def test_lookup_user_by_email_other_error_raises(self):
        self.patch_opener(opener_returning({"ok": False, "error": "missing_scope"}))
        with self.assertRaises(slack_io.SlackError):
            slack_io.lookup_user_by_email("tok", "x@b.c")

    def test_download_file_sends_bearer_and_returns_bytes(self):
        calls = []

        def opener(req, timeout=None):
            calls.append(req)
            return RawResponse(b"hello")
        self.patch_opener(opener)
        self.assertEqual(slack_io.download_file("tok", "https://files.slack.com/x"), b"hello")
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer tok")

    def test_download_file_over_limit_raises(self):
        self.patch_opener(lambda req, timeout=None: RawResponse(b"x" * 11))
        with self.assertRaises(slack_io.FileTooLarge):
            slack_io.download_file("tok", "https://files.slack.com/x", max_bytes=10)
