"""`python -m alert_doctor known ...`: list, search and edit known errors and their links."""
from __future__ import annotations

import time
from datetime import datetime

from alert_doctor import known, known_store
from alert_doctor.known import TAIPEI

SUBCOMMANDS = ("list", "search", "show", "link", "unlink", "add", "review")
REVIEW_BUCKETS = (
    ("expiring", f"{known_store.REVIEW_EXPIRING_DAYS} 天內到期"),
    ("expired", "已過期(不再比對,恢復分析)"),
    ("idle", f"{known_store.REVIEW_IDLE_DAYS} 天沒有命中"),
    ("busy", f"{known_store.REVIEW_BUSY_DAYS} 天命中 ≥ {known_store.REVIEW_BUSY_HITS} 次"),
)


def add_arguments(parser) -> None:
    """Configure an argparse parser for `known`; the result lands in `args.known_command`."""
    sub = parser.add_subparsers(dest="known_command", required=True)
    sub.add_parser("list", help="列出所有固定錯誤(資料庫連結 + known.toml 時段)")
    p = sub.add_parser("search", help="以文字搜尋固定錯誤與已連結的錯誤樣本")
    p.add_argument("text")
    p = sub.add_parser("show", help="顯示一筆固定錯誤與它連結的錯誤")
    p.add_argument("id")
    p = sub.add_parser("link", help="把錯誤樣式(error_key)連結到固定錯誤;已連結的會續期並記為複查")
    p.add_argument("error_key")
    p.add_argument("id")
    p.add_argument("--days", type=int, default=known_store.DEFAULT_LINK_DAYS,
                   help=f"連結有效天數(預設 {known_store.DEFAULT_LINK_DAYS},最多 {known_store.MAX_LINK_DAYS})")
    p = sub.add_parser("unlink", help="取消錯誤樣式的連結")
    p.add_argument("error_key")
    p = sub.add_parser("add", help="新增固定錯誤")
    p.add_argument("id")
    p.add_argument("--title", required=True)
    p.add_argument("--description", default="")
    p.add_argument("--source", default="")
    p.add_argument("--expires", default=None, help="YYYY-MM-DD(台北日期),過了就失效")
    sub.add_parser("review", help="列出該複查的連結:快到期、已過期、久未命中、命中過多")


def _when(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, TAIPEI).strftime("%Y-%m-%d %H:%M")


def _link_lifecycle(link: dict) -> str:
    parts = []
    if link.get("expires_at"):
        parts.append(f"{_when(link['expires_at'])} 到期")
    parts.append(f"命中 {link.get('hit_count') or 0} 次")
    if link.get("last_hit_at"):
        parts.append(f"最後 {_when(link['last_hit_at'])}")
    if link.get("last_reviewed_by"):
        parts.append(f"複查 {link['last_reviewed_by']} {_when(link['last_reviewed_at'])}")
    return " · ".join(parts)


def _review(store, now: float, out) -> int:
    found = known_store.review(store, now)
    if not any(found.values()):
        out("沒有需要複查的連結")
        return 0
    for bucket, title in REVIEW_BUCKETS:
        rows = found[bucket]
        out(f"{title} {len(rows)} 筆:")
        for row in rows:
            extra = f" · 7 天命中 {row['hits_7d']} 次" if bucket == "busy" else ""
            out(f"  {row['error_key']} → {row['known_id']} {row['title']}  {row['sample_label']}")
            out(f"    {_link_lifecycle(row)}{extra} · 建立 {row['created_by'] or '—'}")
    return 0


def _summary_line(row: dict) -> str:
    line = f"{row['id']}  {row['title']}  · 已連結 {row['links']} 種錯誤"
    if row.get("expires"):
        line += f" · {row['expires']} 失效"
    if row["sample"]:
        line += f"\n    例:{' '.join(row['sample'].split())[:120]}"
    return line


def _window_entries(cfg) -> list:
    return known.as_source(getattr(cfg, "known_path", "")).entries()


def _window_line(entry) -> str:
    spans = "、".join(known.KnownHit(entry, w).label for w in entry.windows)
    return f"{entry.id}  {entry.title}  · {entry.action} · {spans}"


def cmd_known(cfg, args, slack=None, elk=None, *, store=None, out=print, clock=time.time) -> int:
    """Run `args.known_command` against `cfg.db_path` (or `store`). Returns the exit code:
    0 done, 1 not found / invalid input."""
    if store is None:
        from alert_doctor.store import Store
        store = Store(cfg.db_path)
    known_store.ensure_schema(store)
    command = args.known_command
    if command == "list":
        rows = known_store.list_entries(store)
        out(f"資料庫固定錯誤 {len(rows)} 筆:")
        for row in rows:
            out("  " + _summary_line(row))
        windows = _window_entries(cfg)
        out(f"known.toml 時段 {len(windows)} 筆:")
        for entry in windows:
            out("  " + _window_line(entry))
        return 0
    if command == "search":
        rows = known_store.search(store, args.text)
        text = args.text.lower()
        windows = [e for e in _window_entries(cfg)
                   if text in f"{e.id}\n{e.title}\n{e.description}".lower()]
        for row in rows:
            out(_summary_line(row))
        for entry in windows:
            out(_window_line(entry))
        if not rows and not windows:
            out(f"找不到符合「{args.text}」的固定錯誤")
            return 1
        return 0
    if command == "show":
        entry = known_store.get_entry(store, args.id)
        if entry is None:
            out(f"沒有固定錯誤 {args.id}")
            return 1
        out(f"{entry.id}  {entry.title}")
        if entry.description:
            out(f"  說明:{entry.description}")
        out(f"  來源:{entry.source or '—'} · 建立 {_when(entry.created_at)}"
            + (f" · {entry.expires} 失效" if entry.expires else ""))
        links = known_store.links_of(store, entry.id)
        out(f"  已連結 {len(links)} 種錯誤:")
        for link in links:
            who = f" by {link['linked_by']}" if link["linked_by"] else ""
            out(f"    {link['error_key']}  {_when(link['linked_at'])}{who}  {link['sample_label']}")
            out(f"      {_link_lifecycle(link)}")
            if link["sample_message"]:
                out(f"      {' '.join(link['sample_message'].split())[:160]}")
        return 0
    if command == "link":
        now = clock()
        try:
            known_store.link(store, args.error_key, args.id, now=now, linked_by="cli", days=args.days)
        except ValueError as exc:
            out(str(exc))
            return 1
        expires = now + min(args.days, known_store.MAX_LINK_DAYS) * known_store.DAY
        out(f"已連結 {args.error_key} → {args.id}({_when(expires)} 到期)")
        return 0
    if command == "review":
        return _review(store, clock(), out)
    if command == "unlink":
        entry = known_store.unlink(store, args.error_key)
        if entry is None:
            out(f"{args.error_key} 沒有連結任何固定錯誤")
            return 1
        out(f"已取消 {args.error_key} 與 {entry.id} 的連結")
        return 0
    if command == "add":
        if known_store.get_entry(store, args.id) is not None:
            out(f"已有固定錯誤 {args.id},未變更")
            return 1
        try:
            entry = known_store.add_entry(
                store, args.id, args.title, now=clock(), description=args.description,
                source=args.source, created_by="cli", expires=args.expires)
        except ValueError as exc:
            out(str(exc))
            return 1
        out(f"已新增固定錯誤 {entry.id}  {entry.title}")
        return 0
    out(f"不認得的子指令:{command}(可用:{', '.join(SUBCOMMANDS)})")
    return 1
