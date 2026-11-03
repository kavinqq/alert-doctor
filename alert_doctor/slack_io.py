"""Thin Slack Web API wrapper (urllib only).

Scopes: `chat:write`, `reactions:write`, `reactions:read`, `channels:history`
(+ `groups:history` for private channels), `users:read.email` (owner emails),
`files:read` (attachments). Socket Mode needs an app-level token (`connections:write`).
"""
import json
import urllib.error
import urllib.parse
import urllib.request

HTTP_TIMEOUT = 10
_opener = urllib.request.urlopen


class SlackError(RuntimeError):
    def __init__(self, error: str):
        super().__init__(f"Slack API error: {error}")
        self.error = error


class FileTooLarge(ValueError):
    pass


class SlackRateLimited(SlackError):
    def __init__(self, retry_after: int):
        super().__init__("ratelimited")
        self.retry_after = retry_after


def _call(req: urllib.request.Request) -> dict:
    try:
        with _opener(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise SlackRateLimited(int(exc.headers.get("Retry-After") or 1)) from exc
        raise


def _checked(resp: dict, accept: tuple[str, ...] = ()) -> dict:
    if not resp.get("ok") and resp.get("error") not in accept:
        raise SlackError(resp.get("error") or "unknown")
    return resp


def _get(method: str, token: str, params: dict) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    req = urllib.request.Request(f"https://slack.com/api/{method}?{query}",
                                 headers={"Authorization": f"Bearer {token}"})
    return _call(req)


def _post(method: str, token: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"https://slack.com/api/{method}", data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json; charset=utf-8"})
    return _call(req)


def _post_form(method: str, token: str, params: dict) -> dict:
    """apps.connections.open rejects JSON bodies."""
    req = urllib.request.Request(
        f"https://slack.com/api/{method}", data=urllib.parse.urlencode(params).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/x-www-form-urlencoded"})
    return _call(req)


def post_message(token: str, channel: str, text: str, thread_ts: str | None = None) -> str:
    payload = {"channel": channel, "text": text, "unfurl_links": False}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    return _checked(_post("chat.postMessage", token, payload))["ts"]


def delete_message(token: str, channel: str, ts: str) -> None:
    """A bot token can only delete messages its own bot posted (`chat:write`)."""
    _checked(_post("chat.delete", token, {"channel": channel, "ts": ts}))


def add_reaction(token: str, channel: str, ts: str, name: str) -> None:
    _checked(_post("reactions.add", token,
                   {"channel": channel, "timestamp": ts, "name": name}),
             accept=("already_reacted",))


def remove_reaction(token: str, channel: str, ts: str, name: str) -> None:
    _checked(_post("reactions.remove", token,
                   {"channel": channel, "timestamp": ts, "name": name}),
             accept=("no_reaction",))


def history(token: str, channel: str, oldest: str, limit: int = 200) -> list[dict]:
    """Top-level messages newer than `oldest`, ts ascending, all pages."""
    messages: list[dict] = []
    cursor = None
    while True:
        resp = _checked(_get("conversations.history", token, {
            "channel": channel, "oldest": oldest, "limit": limit, "cursor": cursor}))
        messages.extend(resp.get("messages") or [])
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return sorted(messages, key=lambda m: float(m["ts"]))


def thread_replies(token: str, channel: str, ts: str, limit: int = 200) -> list[dict]:
    """Replies in the thread of `ts`, without the parent, ts ascending, all pages."""
    messages: list[dict] = []
    cursor = None
    while True:
        resp = _checked(_get("conversations.replies", token, {
            "channel": channel, "ts": ts, "limit": limit, "cursor": cursor}))
        messages.extend(m for m in resp.get("messages") or () if m.get("ts") != ts)
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return sorted(messages, key=lambda m: float(m["ts"]))


def auth_test(token: str) -> dict:
    return _checked(_get("auth.test", token, {}))


def apps_connections_open(app_token: str) -> str:
    return _checked(_post_form("apps.connections.open", app_token, {}))["url"]


def lookup_user_by_email(token: str, email: str) -> str | None:
    """User ID for `email`; None when no such user. Other API errors raise SlackError."""
    resp = _checked(_get("users.lookupByEmail", token, {"email": email}), accept=("users_not_found",))
    return (resp.get("user") or {}).get("id") if resp.get("ok") else None


def download_file(token: str, url: str, max_bytes: int = 2_000_000) -> bytes:
    """Fetch a `url_private` file; raises FileTooLarge beyond `max_bytes`."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with _opener(req, timeout=HTTP_TIMEOUT) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FileTooLarge(f"檔案超過 {max_bytes} bytes")
    return data
