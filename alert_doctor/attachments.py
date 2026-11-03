"""Slack files attached to an alert: remembered at intake, downloaded into the incident's run dir."""
from __future__ import annotations

import json
import logging
import os
import re

from alert_doctor.redact import redact

log = logging.getLogger(__name__)

MAX_BYTES = 2_000_000
HEAD_LINES = 200
HEAD_CHARS = 20_000
TEXT_EXTENSIONS = (".log", ".txt", ".json", ".csv")
TEXT_FILETYPES = ("text", "json", "csv", "log")
_KEEP = ("id", "name", "title", "url_private", "size", "mimetype", "filetype")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS message_files (
    channel TEXT NOT NULL,
    ts TEXT NOT NULL,
    files TEXT NOT NULL,
    PRIMARY KEY (channel, ts)
)
"""


def ensure_schema(store) -> None:
    with store.tx() as db:
        db.execute(_SCHEMA)


def save_files(store, channel: str, ts: str, files) -> None:
    kept = [{k: f[k] for k in _KEEP if k in f} for f in files or () if isinstance(f, dict)]
    if not kept:
        return
    with store.tx() as db:
        db.execute("INSERT OR IGNORE INTO message_files (channel, ts, files) VALUES (?,?,?)",
                   (channel, ts, json.dumps(kept, ensure_ascii=False)))


def files_for(store, channel: str, ts: str) -> list[dict]:
    rows = store.read("SELECT files FROM message_files WHERE channel=? AND ts=?", (channel, ts))
    return json.loads(rows[0][0]) if rows else []


def safe_name(name: str, fallback: str = "file") -> str:
    """Basename only, without path separators or leading dots, so it cannot escape the directory."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[\x00-\x1f]", "", base).lstrip(".").strip()
    return base or fallback


def _is_text(meta: dict) -> bool:
    name = (meta.get("name") or "").lower()
    return (name.endswith(TEXT_EXTENSIONS)
            or (meta.get("mimetype") or "").startswith("text/")
            or (meta.get("filetype") or "") in TEXT_FILETYPES)


def _head(data: bytes) -> str:
    lines = data.decode("utf-8", errors="replace").splitlines()[:HEAD_LINES]
    return "\n".join(lines)[:HEAD_CHARS]


def fetch(slack, bot_token: str, files: list[dict], dest_dir: str,
          max_bytes: int = MAX_BYTES, *, redact_pii: bool = False) -> list[dict]:
    """Download `files` into `dest_dir`; returns one summary per file, never raises.

    A file already on disk is not downloaded again (message retries). Text files carry
    their first 200 lines in `head`.
    """
    summaries = []
    for i, meta in enumerate(files):
        name = safe_name(meta.get("name") or meta.get("title") or "", f"file{i + 1}")
        summary = {"name": name, "size": meta.get("size"), "mimetype": meta.get("mimetype"),
                   "path": f"attachments/{name}", "saved": False}
        summaries.append(summary)
        size = meta.get("size")
        if isinstance(size, int) and size > max_bytes:
            summary["note"] = f"超過 {max_bytes} bytes,未下載"
            continue
        if not meta.get("url_private"):
            summary["note"] = "沒有下載網址"
            continue
        target = os.path.join(dest_dir, name)
        try:
            if os.path.exists(target):
                with open(target, "rb") as f:
                    data = f.read()
            else:
                data = slack.download_file(bot_token, meta["url_private"], max_bytes=max_bytes)
                if redact_pii and _is_text(meta):
                    data = redact(data.decode("utf-8", errors="replace")).encode("utf-8")
                os.makedirs(dest_dir, exist_ok=True)
                with open(target, "wb") as f:
                    f.write(data)
        except Exception as exc:
            log.warning("附件 %s 下載失敗:%s", name, exc)
            summary["note"] = f"下載失敗:{type(exc).__name__}"
            continue
        summary["saved"] = True
        if _is_text(meta):
            summary["head"] = _head(data)
    return summaries
