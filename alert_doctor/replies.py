"""Reply text for the alert channel: Traditional Chinese, Slack mrkdwn."""
from __future__ import annotations

import html
import re
from datetime import datetime, timedelta, timezone

from alert_doctor.hosts import format_hosts
from alert_doctor.redact import for_slack

MAX_CHARS = 3500
TRUNCATION_NOTE = "\n…(內容過長,已截斷)"
SPIKE_FOLLOWUP_REACTION = "chart_with_upwards_trend"
TAIPEI = timezone(timedelta(hours=8))


FENCE = "```"


def _cap(text: str) -> str:
    """At most MAX_CHARS; a cut inside a code block closes the fence, or Slack renders the
    rest of the message as code."""
    if len(text) <= MAX_CHARS:
        return text
    room = MAX_CHARS - len(TRUNCATION_NOTE) - len(FENCE) - 1
    head = text[:room]
    if head.count(FENCE) % 2:
        head += "\n" + FENCE
    return head + TRUNCATION_NOTE


def _lookback_minutes(ev) -> int | None:
    # ElkClient.gather widens the window by 120s after `until`; subtract it to recover lookback.
    try:
        span = datetime.fromisoformat(ev.window_to) - datetime.fromisoformat(ev.window_from)
    except (TypeError, ValueError):
        return None
    return max(round(span.total_seconds() / 60) - 2, 1)


def noise(rule, evidence) -> str:
    text = f"🔇 判定為雜訊:{rule.note}"
    if evidence is not None and evidence.query_ok:
        minutes = _lookback_minutes(evidence)
        window = f"近 {minutes} 分鐘 " if minutes else ""
        text += f"(ELK {window}{evidence.total} 筆、{len(evidence.per_host)} 台、已恢復)"
    return _cap(text)


def known(rule) -> str:
    text = f"🔖 已知問題:{rule.note}"
    if rule.link:
        text += f" {rule.link}"
    return _cap(text)


def duplicate(incident, permalink: str) -> str:
    return _cap(f"🔁 同 incident #{incident.id}(累計 {incident.count} 則)→ {permalink}")


def analyzing(incident, spike: bool) -> str:
    head = "⚠️ 突增" if spike else "🔍 新錯誤"
    return _cap(f"{head},已排入分析(incident #{incident.id})")


def spike_followup(incident, permalink: str) -> str:
    return _cap(f"⚠️ 突增中(累計 {incident.count} 則),分析見 → {permalink}")


def accumulated_followup(incident, permalink: str) -> str:
    return _cap(f"📈 累積異常持續中(累計 {incident.count} 則),分析見 → {permalink}")


def critical(incident, owners, spike: bool) -> str:
    mentions = " ".join(_mention(o) for o in owners)
    head = "🚨 重要告警(突增)" if spike else "🚨 重要告警"
    body = f"{head},incident #{incident.id},已排入分析"
    return _cap(f"{mentions} {body}" if mentions else body)


TRUNCATED_NOTE = "⚠️ 原文超過 Slack 長度上限被截斷,尾段不可得"


def unparsed() -> str:
    return "❔ 無法解析此告警格式,已保留原文,請人工查看。"


def datasource(alert, owners: tuple[str, ...]) -> str:
    """Reply for a check that failed because watchdog could not query ELK."""
    reason = (alert.result_message or alert.raw_text).strip()
    lines = [f"⚠️ *ELK 查詢失敗*:{reason}",
             f"這是 watchdog 查詢 ELK 失敗,不代表系統本身異常;ELK 恢復前,「{alert.check_title}」無法判斷系統狀態。"]
    if owners:
        lines.append(" ".join(owners))
    return _cap("\n".join(lines))


SEVERITY_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
UNKNOWN_SEVERITY_EMOJI = "⚪"
NO_CROSS_SYSTEM = ("", "unknown")
SYSTEM_NAMES = {"cms": "CMS 後台", "pxy": "Pxy 代理", "fastpxy": "FastPxy", "sso": "SSO 會員",
                "oa": "線上開戶", "pe": "官網"}
DEFAULT_TITLE = "分析結果"
# About twice the lengths the prompt asks for: code identifiers make a good answer run a little
# over, and cutting it mid-sentence loses the point. These only stop a runaway field; MAX_CHARS
# still bounds the whole message. FIX_CHARS matches analyzer.FIX_ITEM_HARD_CHARS.
TITLE_CHARS, CAUSE_CHARS, IMPACT_CHARS, FIX_CHARS, REMARK_CHARS, CODE_NOTE_CHARS = \
    120, 240, 120, 120, 120, 60
LOG_LINE_CHARS = 200
ACTION_TARGET_CHARS = 20
MAX_CODE_ITEMS, MAX_FIX_ITEMS, MAX_LOG_LINES = 3, 3, 5
LOW_CONFIDENCE = 0.6
NO_CODE = "無(非程式問題)"
NO_LOGS = "無(ELK 查無相關紀錄)"
FENCE = "```"
SECTION_INDENT = "  "


def _section(label: str, lines: list[str]) -> str:
    """`*label*:` on its own line, each content line below it indented."""
    return "\n".join([f"*{label}*:", *(f"{SECTION_INDENT}{line}" for line in lines)])
_LEADING_ENUMERATOR = re.compile(r"^\d+[.、)]\s*")


def _clip(text, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _mention(owner: str) -> str:
    if owner.startswith("<"):
        return owner
    return f"<!subteam^{owner}>" if owner.startswith("S") else f"<@{owner}>"


ACTION_LABELS = {
    "fix_code": "🛠️ 需修改程式",
    "fix_check": "🔧 調整監控檢查(誤報)",
    "ops": "🧰 需維運處理(主機 / 網路 / DB)",
    "observe": "👀 不用修,待觀察",
    "vendor": "📞 廠商 / 外部問題",
    "investigate": "🔍 需人工調查",
}


def _direction(v: dict) -> str:
    label = ACTION_LABELS.get(v.get("action"))
    if not label:
        return ""
    target = _clip(v.get("action_target"), ACTION_TARGET_CHARS)
    return f"{label}({target})" if target else label


def _fix_items(v: dict) -> list[str]:
    fix = v.get("fix")
    if isinstance(fix, list):
        items = [str(f) for f in fix if str(f).strip()]
    elif isinstance(fix, str) and fix.strip():
        items = [fix]
    else:
        old = _LEADING_ENUMERATOR.sub("", str(v.get("suggested_action") or "").strip())
        items = [old] if old else []
    return [_clip(i, FIX_CHARS) for i in items[:MAX_FIX_ITEMS]]


def _code_items(v: dict) -> list[dict]:
    return [i for i in v.get("evidence") or () if isinstance(i, dict) and i.get("type") == "code"]


def _project(v: dict, source_system: str, project_system: str) -> str:
    """Old verdicts have no `project`: fall back to the first cited repo, then the system."""
    fix = v.get("fix_in_system") or ""
    code = _code_items(v)
    project = (v.get("project") or (code[0].get("repo") if code else "")
               or (fix if fix not in NO_CROSS_SYSTEM else "") or source_system)
    if not project:
        return "未知"
    name = SYSTEM_NAMES.get(project) or SYSTEM_NAMES.get(project_system, project_system)
    return f"{project}({name})" if name and name != project else str(project)


def _code_line(item: dict) -> str:
    line = f"• `{item.get('file')}:{item.get('line')}`"
    if item.get("repo"):
        line += f"({item['repo']})"
    return line + _clip(item.get("note"), CODE_NOTE_CHARS)


_LOG_TIME = re.compile(r"^\s*(\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*")
_JSON_MESSAGE = re.compile(r'"(?:log\.)?message":\s*"((?:[^"\\]|\\.)*)')
_JSON_HOST = re.compile(r'"(?:host|server_hostname|server_ip)":\s*"([^"]+)"')
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_PARTIAL_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{0,3}$|\\$")


def _unescape_json_fragment(text: str) -> str:
    # The elk CLI cuts lines at a fixed width, so the JSON is often truncated mid-string
    # (even mid-escape): decode what is complete instead of json.loads-ing the line.
    text = _PARTIAL_ESCAPE.sub("", text)
    text = _UNICODE_ESCAPE.sub(lambda m: chr(int(m[1], 16)), text)
    return text.replace('\\"', '"').replace("\\n", " ").replace("\\\\", "\\")


def pretty_log(line: str) -> str:
    """`MM/DD HH:MM:SS host message` for the elk CLI's raw-JSON lines, for display only.

    Any other line, or one whose message cannot be decoded into non-empty valid text, is
    returned unchanged.
    """
    m = _JSON_MESSAGE.search(line)
    if not m:
        return line
    message = html.unescape(_unescape_json_fragment(m[1])).strip()
    try:
        message.encode("utf-8")
    except UnicodeEncodeError:
        return line
    if not message:
        return line
    when = _LOG_TIME.match(line)
    host = _JSON_HOST.search(line)
    parts = [when[1] if when else "", host[1] if host else "", message]
    return " ".join(p for p in parts if p)


def _log_lines(v: dict) -> list[str]:
    logs = v.get("logs") if isinstance(v.get("logs"), list) else []
    # A fence inside a log line would close the code block early.
    lines = [for_slack(pretty_log(str(line))).replace(FENCE, "'''").rstrip()
             for line in logs if str(line).strip()]
    return [line[:LOG_LINE_CHARS] for line in lines[:MAX_LOG_LINES]]


def _confidence(v: dict) -> float | None:
    conf = v.get("confidence")
    return float(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool) else None


def verdict(v: dict, reused_from: float | None = None, *, title: str = "",
            source_system: str = "", project_system: str = "", owners=(),
            human_owners=()) -> str:
    """Render a verdict, new format (`cause`/`impact`/`fix`) or old (`summary`/
    `suggested_action`), as sections separated by exactly one blank line.

    `title` is the alert label; `project_system` the system the `project` repo belongs to.
    `owners` / `human_owners` are Slack user IDs or ready-made mention strings: `owners`
    (of the fix system) are only mentioned when the root cause lies in a different system
    than the alert, `human_owners` only when the verdict needs a human.
    """
    emoji = SEVERITY_EMOJI.get(v.get("severity"), UNKNOWN_SEVERITY_EMOJI)
    sections = [f"{emoji} *{_clip(title, TITLE_CHARS) or DEFAULT_TITLE}*",
                _section("錯誤原因", [_clip(v.get("cause") or v.get("summary"), CAUSE_CHARS)])]
    impact = _clip(v.get("impact"), IMPACT_CHARS)
    if impact:
        sections.append(_section("影響功能", [impact]))

    project = _project(v, source_system, project_system)
    fix_system = v.get("fix_in_system") or ""
    if fix_system not in NO_CROSS_SYSTEM and source_system and fix_system != source_system:
        project += f" ↪️ 根因在 {fix_system}"
        if owners:
            project += ",請 " + " ".join(_mention(o) for o in owners) + " 協助確認"
    sections.append(_section("專案", [project]))

    code = _code_items(v)[:MAX_CODE_ITEMS]
    sections.append(_section("錯誤的程式碼", [_code_line(c) for c in code] or [NO_CODE]))

    fixes = [f"{n}. {f}" for n, f in enumerate(_fix_items(v), 1)]
    direction = _direction(v)
    if direction or fixes:
        sections.append(_section("建議修正方法", ([direction] if direction else []) + fixes))

    logs = _log_lines(v)
    # A code block keeps its own layout; indenting it would only shift the fence.
    sections.append(f"*真實Log*:\n{FENCE}\n" + "\n".join(logs) + f"\n{FENCE}" if logs
                    else _section("真實Log", [NO_LOGS]))

    remark = [_clip(v.get("remark"), REMARK_CHARS)] if str(v.get("remark") or "").strip() else []
    conf = _confidence(v)
    if conf is not None and conf < LOW_CONFIDENCE:
        remark.append(f"信心 {conf:.0%}")
    if v.get("needs_human"):
        tag = " ".join(_mention(o) for o in human_owners)
        remark.append(f"需人工確認 {tag}" if tag else "需人工確認")
    if remark:
        sections.append(_section("備註", [" · ".join(remark)]))

    if reused_from is not None:
        sections.append(f"_沿用 {reused_from:g} 小時前的分析_")
    return _cap("\n\n".join(sections))


def over_budget(model: str) -> str:
    return _cap(f"⏸️ 今日 {model} 分析額度已用完,此 incident 暫不自動分析,請人工查看或明日再試。")


def daily_report(
    cov: dict, llm: dict[str, int], backlog: int, day_label: str, failed_analyses: int = 0
) -> str:
    lines = [
        f"📊 *alert-doctor 日報 {day_label}*",
        f"頻道訊息 {cov.get('total', 0)} 則 · 已處理 {cov.get('handled', 0)} · "
        f"失敗 {cov.get('failed', 0)} · 待處理 {cov.get('pending', 0)}",
    ]
    by_category = cov.get("by_category") or {}
    if by_category:
        lines.append("分類:" + "、".join(f"{k} {n}" for k, n in sorted(by_category.items())))
    unhandled = cov.get("unhandled") or []
    if unhandled:
        lines.append("未處理:")
        lines.extend(f"• {title} (ts {ts})" for ts, title in unhandled[:20])
        if len(unhandled) > 20:
            lines.append(f"…另 {len(unhandled) - 20} 則")
    lines.append("LLM 呼叫:" + (" · ".join(f"{m} {n}" for m, n in llm.items()) or "無"))
    lines.append(f"分析積壓:{backlog} · 分析失敗:{failed_analyses}")
    return _cap("\n".join(lines))


def health_alert(problems: list[str]) -> str:
    return _cap("🩺 *alert-doctor 健康檢查異常*\n" + "\n".join(f"{i}. {p}" for i, p in enumerate(problems, 1)))


def _severity_prefix(severity) -> str:
    return f"{SEVERITY_EMOJI[severity]} " if severity in SEVERITY_EMOJI else ""


def host_text(host_counts: dict | None, hosts: int | None) -> str:
    """`host_counts` come from the alerts' quoted samples (one record per alert, so they
    undercount); `hosts` is ELK's distinct-host count for the same error. Both are shown,
    labelled, when ELK saw more hosts than the samples name."""
    if host_counts:
        text = f"主機:{format_hosts(host_counts)}"
        if hosts is not None and hosts > len(host_counts):
            text += f" (ELK 共 {hosts} 台)"
        return text
    return f"主機 {hosts} 台" if hosts is not None else ""


def first_report(*, decision_text: str, summary: dict, mentions: tuple[str, ...]) -> str:
    parts = [f"本分鐘 {summary.get('count', 0)} 則"]
    hosts = host_text(summary.get("host_counts"), summary.get("hosts"))
    if hosts:
        parts.append(hosts)
    if summary.get("window"):
        parts.append(f"{summary['window']} 起")
    lines = []
    if mentions:
        lines.append(" ".join(mentions))
    lines.append(decision_text)
    lines.append(_severity_prefix(summary.get("severity")) + " · ".join(parts))
    return _cap("\n".join(lines))


def minute_update(*, incident_id: int, window_label: str, batch_count: int, total: int,
                  hosts: int | None, changes: list[str], host_counts: dict | None = None) -> str:
    """Never mentions anyone: only an incident's first message tags owners."""
    head = f"📈 {window_label} 這一分鐘 {batch_count} 則(累計 {total} 則)"
    hosts_part = host_text(host_counts, hosts)
    if hosts_part:
        head += f",{hosts_part}"
    return _cap("\n".join([head, *(f"↑ {c}" for c in changes)]))


def backfill_summary(*, count: int, first_ts_label: str, last_ts_label: str) -> str:
    return _cap(f"⏪ 補撈期間共 {count} 則({first_ts_label} – {last_ts_label}),不逐則回覆")


def storm_overview(*, window_label: str, top: list[dict], total_incidents: int,
                   others: list[dict] | None = None, deferred: int = 0) -> str:
    """`top` rows are detailed; `others` (dicts with `incident_id`, `title`, `count`) get one
    line each until the text would pass MAX_CHARS, the rest become a count. `deferred` is the
    number of incidents a caller without `others` left out."""
    lines = [f"🌪️ 告警風暴(已降級){window_label}",
             f"共 {total_incidents} 件 incident,前 {len(top)} 名詳列如下:"]
    for rank, item in enumerate(top, 1):
        row = f"{rank}. {_severity_prefix(item.get('severity'))}#{item['incident_id']} " \
              f"{item.get('title', '')} · {item.get('count', 0)} 則"
        if item.get("hosts") is not None:
            row += f" · {item['hosts']} 台"
        if item.get("link"):
            row += f" → {item['link']}"
        lines.append(row)
    if deferred and not others:
        lines.append(f"另有 {deferred} 件未列出(皆已分類記錄)")
    text = "\n".join(lines)
    if others:
        text += f"\n其餘 {len(others)} 件:"
        reserve = len(f"\n…另 {len(others)} 件")
        for index, item in enumerate(others):
            line = f"\n#{item['incident_id']} {item.get('title', '')} · {item.get('count', 0)} 則"
            if len(text) + len(line) + reserve > MAX_CHARS:
                text += f"\n…另 {len(others) - index} 件"
                break
            text += line
    return _cap(text)


def protection_notice(*, entering: bool, reason: str, mentions: tuple[str, ...],
                      untag_minutes: int = 30) -> str:
    if entering:
        body = (f"🌪️ *進入過載保護*:{reason}\n"
                "已降級:停止逐則 ELK 訊號查詢、跨系統共同錯誤比對與自動規則抽樣"
                "(新 incident 仍會查一次 ELK 證據);非緊急的更新合併成每分鐘一則風暴總覽;"
                "LLM 只分析優先度前 3 名(CRITICAL > 累積量級 > 主機數)。"
                f"進入保護的前 {untag_minutes} 分鐘,非緊急的新 incident 首則不另行 tag。"
                "CRITICAL、never_silence 與 ELK 查詢失敗的告警不會被合併,照常各自回報。")
    else:
        body = f"✅ *已恢復正常模式*:{reason}\n逐則分析與更新恢復運作。"
    return _cap(f"{' '.join(mentions)}\n{body}" if mentions else body)


def occurrence_line(stats: dict | None) -> str:
    """From `Archive.occurrence_stats`; empty when there is nothing to show."""
    if not stats or not stats.get("d30"):
        return ""
    if stats["d30"] == 1:
        return "📊 出現次數:近 30 日首次出現"
    parts = [f"今日 {stats.get('today', 0)} 次", f"近 7 日 {stats.get('d7', 0)} 次",
             f"近 30 日 {stats['d30']} 次"]
    if stats.get("first_epoch") is not None:
        parts.append("首次 " + datetime.fromtimestamp(stats["first_epoch"], TAIPEI).strftime("%m/%d"))
    return "📊 出現次數:" + " · ".join(parts)


def append_section(text: str, section: str) -> str:
    """`text` plus `section` after one blank line; when over MAX_CHARS the body is cut, not
    the section."""
    if not section:
        return text
    tail = f"\n\n{section}"
    if len(text) + len(tail) <= MAX_CHARS:
        return text + tail
    room = MAX_CHARS - len(tail) - len(TRUNCATION_NOTE)
    return text[:room] + TRUNCATION_NOTE + tail


def report_link(permalink: str) -> str:
    return _cap(f"🔗 此 incident 的主要分析串在這 → {permalink}")
