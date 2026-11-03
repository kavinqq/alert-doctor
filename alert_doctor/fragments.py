"""Reassembly of alerts Slack split into several messages.

watchdog posts long alerts (a check quoting a request with thousands of customer IDs) as
consecutive 4000-character messages, cut mid-token, and Slack caps the whole at 40000
characters, so the dict of a very long alert never closes. Only the first piece looks like an
alert; the rest are continuation text from the same bot within a fraction of a second.

A message continues the previous one only when that previous piece is a full Slack split
(MIN_SPLIT_LENGTH): a short malformed bot message followed by more text is two messages.
A piece arriving after its head was already handled (Slack delay, restart) is appended to
the head and announced in its report thread; the alert is not analysed again even when the
completed text changes its error_key (the archive records the new key).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from alert_doctor.models import ParsedAlert
from alert_doctor.parse import parse_message

DEFAULT_JOIN_SECONDS = 15
# Slack splits at exactly 4000; the margin is a guess for characters counted differently
# (entity escapes such as &amp;) between Slack's cut and the text the API returns.
MIN_SPLIT_LENGTH = 3990
_LEADING_MENTION = re.compile(r"\s*<(?:@U\w+|!here|!channel|!subteam\^)")
_DICT_START = ("{", "[")


@dataclass(frozen=True)
class Assembled:
    """`head` and its continuation `fragments` (Slack message dicts, ts order); `text` is
    the joined text of all of them."""

    head: dict
    fragments: tuple
    text: str


def looks_like_head(text: str) -> bool:
    """True for text that starts an alert: a leading mention, or a title line followed by a
    line opening a dict/list. Continuation pieces start mid-content and have neither."""
    if _LEADING_MENTION.match(text):
        return True
    lines = [line for line in text.splitlines() if line.strip()]
    return len(lines) >= 2 and lines[1].lstrip().startswith(_DICT_START)


def is_split_piece(length: int | None) -> bool:
    """True when a message of `length` characters can be followed by a continuation."""
    return (length or 0) >= MIN_SPLIT_LENGTH


def is_complete(alert: ParsedAlert) -> bool:
    """Parsed and not cut inside its message: nothing further can belong to it."""
    return alert.parse_ok and not alert.truncated


def join_texts(texts) -> str:
    # Slack cuts at a fixed length inside tokens ('"L' + '123773828"'); any separator would
    # corrupt them.
    return "".join(texts)


def reassemble(messages: list[dict], join_seconds: float,
               parse=lambda text: parse_message("", "0", text)) -> list[Assembled]:
    """Group one channel's messages (ts ascending) into alerts.

    A message joins the open group of its bot (`bot_id`) when it does not look like a head,
    arrives within `join_seconds` of that group's last piece, that last piece is a full split
    (`is_split_piece`), and the group's joined text is still incomplete. Messages without a
    bot_id are never joined.
    """
    groups: list[list[dict]] = []
    open_by_bot: dict[str, int] = {}
    for message in messages:
        bot = message.get("bot_id")
        text = message.get("text") or ""
        index = open_by_bot.get(bot) if bot else None
        if index is not None and not looks_like_head(text):
            group = groups[index]
            if (float(message["ts"]) - float(group[-1]["ts"]) <= join_seconds
                    and is_split_piece(len(group[-1].get("text") or ""))
                    and not is_complete(parse(_text(group)))):
                group.append(message)
                continue
        groups.append([message])
        if bot:
            if looks_like_head(text):
                open_by_bot[bot] = len(groups) - 1
            else:
                open_by_bot.pop(bot, None)
    return [Assembled(g[0], tuple(g[1:]), _text(g)) for g in groups]


def _text(group: list[dict]) -> str:
    return join_texts(m.get("text") or "" for m in group)
