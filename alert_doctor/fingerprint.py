from __future__ import annotations

import hashlib
import re

from alert_doctor.models import ParsedAlert
from alert_doctor.redact import TAIWAN_ID

# v2 (2026-10-21): fine_fp hashes `signature()` instead of `template()`, so keyword alerts got new
# fingerprints; auto rules, fp_blocks and tuner baselines keyed by v1 fingerprints no longer match
# and are rebuilt from new traffic (see README.md).
FINGERPRINT_VERSION = 2

_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_JWT = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
_ISO_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([+-]\d{2}:?\d{2}|Z)?"
)
_LONG_HEX = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{16,}(?![A-Za-z0-9])")
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
# ASCII-only boundaries: \w would treat CJK as word chars and keep "37次" unmasked.
_NUMBER = re.compile(r"(?<![A-Za-z0-9_])\d+(?:\.\d+)?(?![A-Za-z0-9_])")
# Request ids like [sD4Urd]: at least two of upper/lower/digit, so [ERROR], [sso], [M999] (too
# short) stay; a capitalised word ([Warning]) is excluded explicitly.
_BRACKET_ID = re.compile(
    r"\[(?![A-Z]?[a-z]+\])(?=[A-Za-z0-9]{5,8}\])"
    r"(?:(?=[^\]]*[A-Z])(?=[^\]]*[a-z])|(?=[^\]]*[A-Z])(?=[^\]]*\d)|(?=[^\]]*[a-z])(?=[^\]]*\d))"
    r"[A-Za-z0-9]{5,8}\]")

# watchdog keyword checks append the first matching log line as 「…」 after this phrase; that
# sample carries request ids, hosts and bodies, so only its structure identifies the error.
_SAMPLE_START = re.compile(r"請立即(?:查看|檢查)[^「」\n]{0,20}?「")
# Some checks append the raw sample after 「…系統狀況！」 without quoting it (e.g. an nginx line).
_BARE_SAMPLE_START = re.compile(r"請立即(?:查看|檢查)[^「」\n！!]{0,20}?[！!]\s*")
_HTTP_REQUEST = re.compile(r'"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (/[^\s"?]*)[^"]*"\s+(\d{3})\b')
_REQUEST_PATH = re.compile(r"""request_path['"]?\s*[:=]\s*['"]?([^'"\s,}]+)""")
# A truncated alert can cut the body before its closing quote; then everything after it goes.
_REQUEST_BODY = re.compile(
    r"""['"]?request_body['"]?\s*[:=]\s*b?(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|.*\Z)""",
    re.DOTALL)
_CODE_TOKENS = (
    re.compile(r"(?<![A-Za-z0-9])([MP]\d{3})(?![A-Za-z0-9])"),
    re.compile(r"""\b(?:response_)?status(?:_code)?['"]?\s*[:=]\s*['"]?([1-5]\d{2})(?!\d)"""),
    re.compile(r"\b([A-Z][A-Za-z0-9]*(?:Error|Exception|Timeout))\b"),
    re.compile(r"\b(Errno \d+)"),
    re.compile(r"""\bcode['"]?\s*[:=]\s*['"]?(\w+)"""),
)


def _mask_number(m: re.Match) -> str:
    s = m.group(0)
    if s.isdigit() and len(s) == 3 and 100 <= int(s) <= 599:
        return s
    return "<n>"


def template(text: str) -> str:
    """Replace volatile tokens with placeholders so recurring messages compare equal.

    Standalone integers 100-599 are kept (HTTP status); tokens mixing letters and
    digits (`ORS111`) are kept whole.
    """
    text = _UUID.sub("<uuid>", text)
    text = _JWT.sub("<jwt>", text)
    text = _ISO_TIME.sub("<time>", text)
    text = _LONG_HEX.sub("<hex>", text)
    text = _IPV4.sub("<ip>", text)
    text = TAIWAN_ID.sub("<id>", text)
    text = _BRACKET_ID.sub("[<id>]", text)
    text = _NUMBER.sub(_mask_number, text)
    return re.sub(r"\s+", " ", text).strip()


def _keyword_sample(text: str) -> tuple[str, bool] | None:
    """(sample, closed) of a keyword check's quoted log line, or None for other messages."""
    start = _SAMPLE_START.search(text)
    if start is None:
        bare = _BARE_SAMPLE_START.search(text)
        if bare is None or not text[bare.end():].strip():
            return None
        return text[bare.end():], True
    sample = text[start.end():]
    end = sample.rfind("」")
    return (sample[:end], True) if end >= 0 else (sample, False)


def _codes(sample: str) -> list[str]:
    return sorted({m.group(1) for pattern in _CODE_TOKENS for m in pattern.finditer(sample)})


def signature(text: str) -> str:
    """`template(text)`, except for a message quoting a log sample in 「…」 after
    「請立即查看系統狀況」 (or 檢查): the text before the sample (keywords, tags) plus the
    sample's request_path and error-code tokens (M/P codes, HTTP status, exception classes,
    `Errno n`, `code: x`), so samples differing only in ids, hosts or bodies compare equal.
    """
    found = _keyword_sample(text)
    if found is None:
        return template(text)
    sample = found[0]
    codes = _codes(_REQUEST_BODY.sub("", sample))
    path = _REQUEST_PATH.search(sample)
    path_text = path.group(1) if path else ""
    access = _HTTP_REQUEST.search(sample)
    if access:
        # An access-log line: method/path/status say which error it is; size, agent and
        # timestamp are noise. Its status is the code that matters, not other 3-digit fields.
        path_text = path_text or access.group(1)
        codes = sorted(set(codes) | {access.group(2)})
    quoted = _SAMPLE_START.search(text)
    head = template(text[:quoted.end() - 1] if quoted else text[:_BARE_SAMPLE_START.search(text).end()])
    return f"{head}「path={template(path_text) if path_text else ''} codes={','.join(codes)}」"


def signature_is_reliable(text: str, truncated: bool = False) -> bool:
    """False when `signature(text)` may lump different errors together: the alert text was
    cut (`truncated`, from the parser), or a keyword sample lost its end and kept no code
    token to tell its error apart."""
    if truncated:
        return False
    found = _keyword_sample(text)
    if found is None or found[1]:
        return True
    return bool(_codes(_REQUEST_BODY.sub("", found[0])))


def _sha1(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


def _key(alert: ParsedAlert) -> str:
    return alert.check_code or alert.check_title


def _level(alert: ParsedAlert) -> str:
    return "" if alert.level is None else str(alert.level)


def fine_fp(alert: ParsedAlert) -> str:
    """40-char sha1 over FINGERPRINT_VERSION, check key, level and the result message's
    `signature`."""
    return _sha1(f"v{FINGERPRINT_VERSION}", _key(alert), _level(alert), signature(alert.result_message))


def group_fp(alert: ParsedAlert) -> str:
    """Coarser fingerprint (check key and level only) for grouping related incidents."""
    return _sha1(_key(alert), _level(alert))
