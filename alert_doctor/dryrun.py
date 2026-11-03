"""Slack stand-in for `replay`: same function names as slack_io, records calls, never touches the network."""
from __future__ import annotations


class DryRunSlack:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self._seq = 0

    def post_message(self, token, channel, text, thread_ts=None) -> str:
        self._seq += 1
        ts = f"9000000000.{self._seq:06d}"
        self.calls.append(("post_message", {"channel": channel, "text": text,
                                            "thread_ts": thread_ts, "ts": ts}))
        return ts

    def delete_message(self, token, channel, ts) -> None:
        self.calls.append(("delete_message", {"channel": channel, "ts": ts}))

    def add_reaction(self, token, channel, ts, name) -> None:
        self.calls.append(("add_reaction", {"channel": channel, "ts": ts, "name": name}))

    def remove_reaction(self, token, channel, ts, name) -> None:
        self.calls.append(("remove_reaction", {"channel": channel, "ts": ts, "name": name}))

    def history(self, token, channel, oldest, limit=200) -> list[dict]:
        return []

    def auth_test(self, token) -> dict:
        return {"ok": True, "user_id": "UDRYRUN", "bot_id": "BDRYRUN"}

    def lookup_user_by_email(self, token, email) -> str | None:
        return None

    def download_file(self, token, url, max_bytes=2_000_000) -> bytes:
        self.calls.append(("download_file", {"url": url}))
        return b""

    def apps_connections_open(self, app_token) -> str:
        return "wss://dry-run.invalid"

    def replies_to(self, thread_ts: str, channel: str | None = None) -> list[str]:
        return [c["text"] for name, c in self.calls
                if name == "post_message" and c["thread_ts"] == thread_ts
                and channel in (None, c["channel"])]

    def reactions_on(self, ts: str, channel: str | None = None) -> list[str]:
        return [c["name"] for name, c in self.calls
                if name == "add_reaction" and c["ts"] == ts and channel in (None, c["channel"])]
