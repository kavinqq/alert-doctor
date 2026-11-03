"""One-off clean-up of a monitoring channel: archive everything, then delete what our tokens may.

Deleted: alerts from `cfg.source_bot_ids` (the head and its continuation pieces, recognised
the way the collector reassembles them; the same bot also posts other notices, which stay),
with Rocket Message Bot's token; and anything our own bot posted, with our token. A thread
someone has replied in is a conversation and is kept whole, re-checked right before its root
is deleted. Every deletion is recorded in `purge_targets`, so the publisher will not post
into a wiped thread afterwards.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from alert_doctor import fragments
from alert_doctor.parse import parse_message
from alert_doctor.slack_io import SlackError, SlackRateLimited

WIPE_INCIDENT = 0
# Not "pending": the collector's Purger would claim it and void it (incident 0 does not exist).
WIPING = "wiping"
GONE_ERRORS = ("message_not_found",)
NOT_PEOPLE_SUBTYPES = ("bot_message", "channel_join", "channel_leave")
# chat.delete is Tier 3 (about 50 per minute); pausing keeps a long wipe clear of 429s.
DEFAULT_PAUSE = 1.2
JOIN_SECONDS = 60


def _archive(path: Path, channel: str, now: float, messages: list[dict]) -> None:
    """Never overwrites: an archive may be the only copy of what was deleted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="utf-8") as handle:
        json.dump({"channel": channel, "fetched_at": now, "messages": messages}, handle,
                  ensure_ascii=False, indent=1)


def _by_person(message: dict) -> bool:
    return (bool(message.get("user")) and not message.get("bot_id")
            and message.get("subtype") not in NOT_PEOPLE_SUBTYPES)


def _alert_groups(channel: str, messages: list[dict], sources: set[str]) -> list[list[str]]:
    """ts lists (head first) of the source bot's top-level messages that are alerts."""
    own = [m for m in messages if m.get("bot_id") in sources]
    groups = []
    for group in fragments.reassemble(own, JOIN_SECONDS):
        # A leading mention alone is not enough: the same bot tags people in other notices.
        if parse_message(channel, group.head["ts"], group.text).parse_ok:
            groups.append([group.head["ts"], *(m["ts"] for m in group.fragments)])
    return groups


def _steps(top: list[dict], groups: list[list[str]], sources: set[str],
           our_bot_id: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """(thread root ts, [(kind, ts)]) in deletion order: root, its pieces, our replies in any
    of their threads; for any other top-level message, just our replies in its thread."""
    by_ts = {m["ts"]: m for m in top}

    def ours_in(message: dict) -> list[tuple[str, str]]:
        return [("reply", r["ts"]) for r in message["replies"] if r.get("bot_id") == our_bot_id]

    steps = [(g[0], [("alert", g[0])] + [("fragment", ts) for ts in g[1:]]
              + [item for ts in g for item in ours_in(by_ts[ts])]) for g in groups]
    in_groups = {ts for g in groups for ts in g}
    for message in top:
        if message["ts"] in in_groups:
            continue
        if message.get("bot_id") == our_bot_id:
            steps.append((message["ts"], [("own_root", message["ts"])] + ours_in(message)))
        else:
            steps.append((message["ts"], ours_in(message)))
    return sorted(((root, items) for root, items in steps if items), key=lambda s: float(s[0]))


def wipe_channel(store, slack, cfg, channel: str, *, bot_token: str,
                 source_bot_token: str | None, our_bot_id: str, archive_dir: str, apply: bool,
                 now: float, sleep=time.sleep, pause: float = DEFAULT_PAUSE, out=print) -> dict:
    """Returns counts: alerts / ours (to delete), kept, discussed threads, and after `apply`
    deleted / failed / skipped (a thread that got a person's reply meanwhile), plus the
    archive path. The archive is always written first."""
    top = slack.history(bot_token, channel, "0")
    for message in top:
        message["replies"] = (slack.thread_replies(bot_token, channel, message["ts"])
                              if message.get("reply_count") else [])
    archive = Path(archive_dir, f"{channel}.json")
    _archive(archive, channel, now, top)

    discussed = {m["ts"] for m in top if any(_by_person(r) for r in m["replies"])}
    open_top = [m for m in top if m["ts"] not in discussed]
    sources = set(cfg.source_bot_ids)
    groups = _alert_groups(channel, open_top, sources) if sources else []
    steps = _steps(open_top, groups, sources, our_bot_id)
    kinds = [kind for _, items in steps for kind, _ in items]
    alerts = sum(kind in ("alert", "fragment") for kind in kinds)
    total = len(top) + sum(len(m["replies"]) for m in top)
    result = {"archive": str(archive), "alerts": alerts, "ours": len(kinds) - alerts,
              "kept": total - len(kinds), "discussed": len(discussed),
              "deleted": 0, "failed": 0, "skipped": 0}
    if not apply:
        return result
    if alerts and not source_bot_token:
        raise RuntimeError("讀不到 Rocket Message Bot 的 token,無法刪告警")

    with store.tx() as db:
        purge_id = db.execute(
            "INSERT INTO purges (incident_id, channel, generation, verdict, analysis_text,"
            " state, created_epoch, error) VALUES (?,?,?,?,?,?,?,?)",
            (WIPE_INCIDENT, channel, now, "{}", "", WIPING, now, "wipe")).lastrowid
    removed_roots = []
    done = 0
    for root, items in steps:
        if _discussed_now(slack, bot_token, channel, root, items):
            result["skipped"] += len(items)
            continue
        for kind, ts in items:
            store.add_purge_targets(purge_id, channel, kind, [ts])
            token = source_bot_token if kind in ("alert", "fragment") else bot_token
            state, error = _delete(slack, token, channel, ts, sleep)
            store.set_target(purge_id, kind, ts, state, error=error, epoch=time.time())
            result["deleted" if state != "failed" else "failed"] += 1
            if kind in ("alert", "own_root") and state != "failed":
                removed_roots.append(ts)
            done += 1
            if done % 50 == 0:
                out(f"  {channel}:{done}/{len(kinds)}")
            sleep(pause)
    if removed_roots:
        marks = ",".join("?" * len(removed_roots))
        with store.tx() as db:
            db.execute(f"DELETE FROM reports WHERE channel=? AND root_ts IN ({marks})",
                       (channel, *removed_roots))
    store.set_purge(purge_id, state="done", finished_epoch=time.time())
    return result


def _discussed_now(slack, token: str, channel: str, root: str, items) -> bool:
    """Someone may have replied since the history was read: re-read every thread this step
    touches (the root's, and each continuation piece's) right before deleting in it."""
    threads = [root] + [ts for kind, ts in items if kind == "fragment"]
    return any(_by_person(r) for ts in threads for r in slack.thread_replies(token, channel, ts))


def _delete(slack, token: str, channel: str, ts: str, sleep) -> tuple[str, str | None]:
    while True:
        try:
            slack.delete_message(token, channel, ts)
            return "deleted", None
        except SlackRateLimited as exc:
            sleep(exc.retry_after)
        except SlackError as exc:
            if exc.error in GONE_ERRORS:
                return "gone", None
            return "failed", exc.error
