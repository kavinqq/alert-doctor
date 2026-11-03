"""Optional PII stripping for alert text (config `redact_pii`, off by default).

Off by default because log masking is planned server-wide; `TAIWAN_ID` is also used by
fingerprinting so alerts naming different customers still group together.
"""
from __future__ import annotations

import re

# Second character: 1/2 citizens, 8/9 new-style resident certificates, A-D old-style ones.
TAIWAN_ID = re.compile(r"(?<![A-Za-z0-9])[A-Z][1289A-D]\d{8}(?![A-Za-z0-9])")
_MOBILE = re.compile(r"(?<!\d)09\d{2}-?\d{3}-?\d{3}(?!\d)")


# Unlike PII this is unconditional: watchdog posts each task's kwargs, which carry ELK, DB and
# SFTP credentials, so every alert would spread them into storage and LLM prompts.
SECRET_KEY = re.compile(r"(?i)passw|pwd|pwad|secret|token|^access$|api_?key|credential")
_URL_CREDENTIALS = re.compile(r"(://)[^/\s@'\"]+@")
_SECRET_ITEM = re.compile(
    r"""(['"])([^'"]*?(?:passw|pwd|secret|token|access|api_?key|credential)[^'"]*?)\1(\s*:\s*)(['"])(.*?)(?<!\\)\4""",
    re.I)


def strip_secrets(value):
    """Return `value` with secret-looking dict entries and URL credentials replaced."""
    if isinstance(value, dict):
        return {k: "<redacted>" if isinstance(k, str) and SECRET_KEY.search(k) else strip_secrets(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(strip_secrets(v) for v in value)
    if isinstance(value, str):
        return _URL_CREDENTIALS.sub(r"\1<redacted>@", value)
    return value


def strip_secret_text(text: str) -> str:
    """Same as `strip_secrets` for the raw repr text kept alongside the parsed dict."""
    text = _SECRET_ITEM.sub(lambda m: f"{m[1]}{m[2]}{m[1]}{m[3]}{m[4]}<redacted>{m[4]}", text)
    return _URL_CREDENTIALS.sub(r"\1<redacted>@", text)


_BARE_SECRET = re.compile(
    r"(?i)\b((?:\w*_)?(?:token|passw\w*|pwd|secret|api_?key))(\s*[:=]?\s*)([A-Za-z0-9._\-+/=]{8,})")


def for_slack(text: str) -> str:
    """Raw log lines quoted in a Slack post: credentials (also the bare `login_token abc…`
    form app logs print) and customer IDs / mobile numbers are masked regardless of
    `redact_pii`, since the post is readable by the whole channel."""
    text = _BARE_SECRET.sub(r"\1\2<redacted>", strip_secret_text(text))
    return redact(text)


def redact(text: str) -> str:
    text = TAIWAN_ID.sub("[身分證]", text)
    return _MOBILE.sub("[手機]", text)
