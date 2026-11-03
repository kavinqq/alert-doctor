import os
import tempfile
import unittest

from alert_doctor import attachments
from alert_doctor.slack_io import FileTooLarge
from alert_doctor.store import Store


class FakeSlack:
    def __init__(self, data=b"line1\nline2\n"):
        self.data = data
        self.calls = []

    def download_file(self, token, url, max_bytes=2_000_000):
        self.calls.append((token, url, max_bytes))
        if len(self.data) > max_bytes:
            raise FileTooLarge("big")
        return self.data


class AttachmentsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dest = os.path.join(self.tmp.name, "7", "attachments")

    def test_safe_name_strips_paths(self):
        self.assertEqual(attachments.safe_name("../../etc/passwd"), "passwd")
        self.assertEqual(attachments.safe_name("a\\b\\..\\c.txt"), "c.txt")
        self.assertEqual(attachments.safe_name(".."), "file")
        self.assertEqual(attachments.safe_name(""), "file")

    def test_text_file_downloaded_with_head(self):
        slack = FakeSlack(b"\n".join(f"l{i}".encode() for i in range(300)))
        files = [{"name": "../err.log", "url_private": "https://f/1", "size": 10, "mimetype": "text/plain"}]
        out = attachments.fetch(slack, "tok", files, self.dest)
        self.assertTrue(out[0]["saved"])
        self.assertEqual(out[0]["path"], "attachments/err.log")
        self.assertTrue(os.path.exists(os.path.join(self.dest, "err.log")))
        self.assertEqual(len(out[0]["head"].splitlines()), 200)
        self.assertEqual(slack.calls[0][:2], ("tok", "https://f/1"))

    def test_text_file_pii_redacted_on_disk_and_in_head(self):
        slack = FakeSlack("客戶 A123456789 手機 0912345678\n".encode())
        files = [{"name": "ids.csv", "url_private": "u", "size": 40, "mimetype": "text/csv"}]
        out = attachments.fetch(slack, "tok", files, self.dest, redact_pii=True)
        with open(os.path.join(self.dest, "ids.csv"), encoding="utf-8") as f:
            on_disk = f.read()
        for text in (on_disk, out[0]["head"]):
            self.assertNotIn("A123456789", text)
            self.assertIn("[身分證]", text)
            self.assertIn("[手機]", text)

    def test_image_saved_without_head(self):
        out = attachments.fetch(FakeSlack(b"\x89PNG"), "tok",
                                [{"name": "shot.png", "url_private": "u", "mimetype": "image/png"}], self.dest)
        self.assertTrue(out[0]["saved"])
        self.assertNotIn("head", out[0])

    def test_oversize_by_metadata_not_downloaded(self):
        slack = FakeSlack()
        out = attachments.fetch(slack, "tok", [{"name": "big.log", "url_private": "u", "size": 3_000_000}],
                                self.dest)
        self.assertFalse(out[0]["saved"])
        self.assertIn("未下載", out[0]["note"])
        self.assertEqual(slack.calls, [])

    def test_download_failure_is_noted_not_raised(self):
        slack = FakeSlack(b"x" * 20)
        out = attachments.fetch(slack, "tok", [{"name": "a.txt", "url_private": "u"}], self.dest, max_bytes=10)
        self.assertFalse(out[0]["saved"])
        self.assertIn("下載失敗", out[0]["note"])

    def test_existing_file_not_downloaded_again(self):
        slack = FakeSlack()
        files = [{"name": "a.txt", "url_private": "u"}]
        attachments.fetch(slack, "tok", files, self.dest)
        attachments.fetch(slack, "tok", files, self.dest)
        self.assertEqual(len(slack.calls), 1)

    def test_store_roundtrip(self):
        store = Store(":memory:")
        attachments.ensure_schema(store)
        attachments.ensure_schema(store)
        attachments.save_files(store, "C1", "1.0", [{"name": "a.txt", "url_private": "u", "junk": 1}])
        self.assertEqual(attachments.files_for(store, "C1", "1.0"), [{"name": "a.txt", "url_private": "u"}])
        self.assertEqual(attachments.files_for(store, "C1", "2.0"), [])


if __name__ == "__main__":
    unittest.main()
