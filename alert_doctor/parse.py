from __future__ import annotations

import ast
import re

from alert_doctor.models import ParsedAlert
from alert_doctor.redact import redact, strip_secret_text, strip_secrets

_MENTION = re.compile(r"<@(U\w+)>")
_MENTION_LINE_TOKEN = re.compile(r"<@U\w+>|<!(?:here|channel)>|<!subteam\^\w+(?:\|[^>]*)?>")
VKWARGS_MAX_BRACES = 200
_STR = r"""(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"""


def _field(key: str, value_pattern: str, text: str) -> re.Match | None:
    return re.search(rf"""['"]{key}['"]\s*:\s*{value_pattern}""", text)


def _str_field(key: str, text: str) -> str | None:
    match = _field(key, _STR, text)
    if not match:
        return None
    body = match.group(1) if match.group(1) is not None else match.group(2)
    quote = "'" if match.group(1) is not None else '"'
    try:
        return ast.literal_eval(f"{quote}{body}{quote}")
    except (ValueError, SyntaxError):
        return body


def _unescape(text: str) -> str:
    # &amp; last, otherwise "&amp;lt;" would be double-decoded to "<".
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


def _as_dict(text: str) -> dict | None:
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _unterminated_str_field(key: str, text: str) -> str | None:
    """The value of `key` when its string runs to the end of `text` without a closing quote."""
    match = _field(key, r"""(['"])([\s\S]*)\Z""", text.rstrip())
    if not match:
        return None
    quote, body = match.group(1), match.group(2)
    # The cut can land inside an escape sequence; drop the dangling backslash.
    if (len(body) - len(body.rstrip("\\"))) % 2:
        body = body[:-1]
    try:
        return ast.literal_eval(f"{quote}{body}{quote}")
    except (ValueError, SyntaxError):
        return body


def _dict_field(key: str, text: str) -> dict | None:
    """`key`'s dict value when it is a complete literal, even though the text around it is not."""
    start = _field(key, r"\{", text)
    if not start:
        return None
    begin = start.end() - 1
    end = text.find("}", begin)
    # Shortest literal that parses: a '}' inside a string value just fails and the scan goes on.
    for _ in range(VKWARGS_MAX_BRACES):
        if end < 0:
            return None
        value = _as_dict(text[begin:end + 1])
        if value is not None:
            return value
        end = text.find("}", end + 1)
    return None


def _salvage_fields(text: str) -> dict | None:
    """Regex fallback for extras holding non-literal reprs (datetime.datetime(...), Decimal('1'), UUID('...'))
    or cut short inside `result.message` (then `truncated` is set).

    Needs at least `code` and `message`; `message` and `level` are read from after `'result'` when present,
    since vkwargs may carry same-named keys.
    """
    result_at = re.search(r"""['"]result['"]\s*:""", text)
    result_text = text[result_at.end():] if result_at else text
    code = _str_field("code", text)
    message = _str_field("message", result_text)
    truncated = False
    if message is None:
        message = _unterminated_str_field("message", result_text)
        truncated = message is not None
    if code is None or message is None:
        return None
    found = {"code": code, "message": message, "truncated": truncated}
    task_id = _str_field("task_id", text)
    if task_id is not None:
        found["task_id"] = task_id
    level = _field("level", r"(\d+)", result_text)
    if level:
        found["level"] = int(level.group(1))
    vkwargs = _dict_field("vkwargs", text[:result_at.start()] if result_at else text)
    found["extra"] = {"vkwargs": strip_secrets(vkwargs)} if vkwargs is not None else {}
    return found


def parse_message(channel: str, ts: str, text: str, *, redact_pii: bool = False) -> ParsedAlert:
    """Parse a watchdog Slack message (`[mention line] title\\n{extra repr}`).

    Never raises: when `extra` cannot be recovered as a dict the result has
    `parse_ok=False`, `check_title` is the first non-mention line and
    `result_message` holds the remaining raw text. With `redact_pii` customer PII is
    removed from every field, including `raw_text`.
    """
    text = strip_secret_text(text)
    if redact_pii:
        text = redact(text)
    lines = _unescape(text).splitlines()
    mentions: list[str] = []
    title_index = None
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        if not _MENTION_LINE_TOKEN.sub("", line).strip():
            mentions.extend(_MENTION.findall(line))
            continue
        title_index = i
        break

    if title_index is None:
        return ParsedAlert(
            channel=channel, ts=ts, raw_text=text, parse_ok=False,
            check_title="", mentions=tuple(mentions),
        )

    title = lines[title_index].strip()
    rest = "\n".join(lines[title_index + 1:]).strip()
    extra = _as_dict(rest) if rest else None
    if extra is None and rest:
        salvaged = _salvage_fields(rest)
        if salvaged:
            return ParsedAlert(
                channel=channel, ts=ts, raw_text=text, parse_ok=True,
                check_title=title,
                check_code=salvaged["code"],
                task_id=salvaged.get("task_id"),
                level=salvaged.get("level"),
                result_message=salvaged["message"],
                extra=salvaged["extra"],
                mentions=tuple(mentions),
                truncated=salvaged["truncated"],
            )
    if extra is None:
        return ParsedAlert(
            channel=channel, ts=ts, raw_text=text, parse_ok=False,
            check_title=title, result_message=rest, mentions=tuple(mentions),
        )

    extra = strip_secrets(extra)
    result = extra.get("result")
    if not isinstance(result, dict):
        result = {}
    level = result.get("level")
    return ParsedAlert(
        channel=channel, ts=ts, raw_text=text, parse_ok=True,
        check_title=title,
        check_code=extra.get("code"),
        task_id=extra.get("task_id"),
        level=level if isinstance(level, int) else None,
        result_message=result.get("message", ""),
        extra=extra,
        mentions=tuple(mentions),
    )
