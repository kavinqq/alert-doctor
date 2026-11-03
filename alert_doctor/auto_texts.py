from __future__ import annotations


def auto_noise(rule, sample: bool) -> str:
    base = f"🔇 自動規則 #{rule.id} 判定為雜訊,不另行分析。"
    if sample:
        return base + "\n本則為抽樣複查,仍會送分析以確認規則沒有誤判。"
    return base + "\n如果判斷錯誤,請在此回覆按 ❌ 撤銷規則。"


def sampled(rule, incident) -> str:
    what = "雜訊" if rule.kind == "noise" else "已知問題"
    return (f"🎲 自動規則 #{rule.id}(判定為{what})抽樣複查:本則照常送分析(incident #{incident.id}),"
            "用來確認規則沒有誤判。")


def auto_known(rule, permalink: str) -> str:
    return (f"🔖 自動規則 #{rule.id} 判定為已知問題,先前分析見 {permalink}。\n"
            "如果判斷錯誤,請在此回覆按 ❌ 撤銷規則。")


def accumulated(incident, signal_dict: dict) -> str:
    errors = signal_dict.get("errors")
    parts = [f"錯誤 {errors} 筆"] if errors is not None else []
    rate = signal_dict.get("rate")
    if rate is not None:
        parts.append(f"錯誤率 {rate:.1%}")
    parts.append(f"持續 {signal_dict.get('duration_minutes', 0)} 分鐘")
    parts.append(f"{signal_dict.get('hosts', 0)} 台主機")
    return (f"📈 累積異常:「{incident.check_title}」單則看似雜訊,但近 1 小時量級超出平常水準"
            f"({'、'.join(parts)}),已送分析。")


def revoked_ack(fingerprint_short: str) -> str:
    return (f"❌ 已收到。指紋 {fingerprint_short} 的自動規則已撤銷,"
            "30 天內不會再自動靜音,並已重新送分析。")
