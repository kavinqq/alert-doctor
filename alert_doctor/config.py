from __future__ import annotations

import json
import os
import subprocess
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


def get_secret(service: str, account: str | None = None) -> str:
    """Return a secret from env `ALERT_DOCTOR_<NAME>` or the macOS Keychain.

    NAME is `account` (or `service` when no account), upper-cased with `-` as `_`.
    Raises RuntimeError when neither source has a non-empty value.
    """
    env_name = "ALERT_DOCTOR_" + (account or service).upper().replace("-", "_")
    value = os.environ.get(env_name)
    if value:
        return value
    cmd = ["security", "find-generic-password", "-s", service]
    if account:
        cmd += ["-a", account]
    cmd.append("-w")
    done = subprocess.run(cmd, capture_output=True, text=True)
    value = done.stdout.strip() if done.returncode == 0 else ""
    if not value:
        raise RuntimeError(
            f"找不到機密 service={service} account={account}:"
            f"請設環境變數 {env_name},或寫入 Keychain(security add-generic-password -s {service} ...)"
        )
    return value


@dataclass(frozen=True)
class ChannelSpec:
    id: str
    name: str
    systems: tuple[str, ...]


@dataclass(frozen=True)
class SystemSpec:
    key: str
    repos: tuple[str, ...]
    owners: tuple[str, ...]
    elk_project: str
    error_query: dict


@dataclass(frozen=True)
class RepoSpec:
    id: str
    path: str
    deploy_ref: str = "origin/HEAD"


@dataclass(frozen=True)
class Config:
    workspace_url: str
    channels: tuple[ChannelSpec, ...] = ()
    systems: dict[str, SystemSpec] = field(default_factory=dict)
    repos: dict[str, RepoSpec] = field(default_factory=dict)
    report_channel: str = ""
    # Reports go to this directory when report_channel is empty.
    report_dir: str = "reports"
    keychain_service: str = "alert-doctor"
    elk_url: str = "http://10.0.0.100:9200"
    elk_user: str = "elastic"
    elk_keychain_service: str = "ops-elk"
    elk_timeout: int = 10
    model: str = "sonnet"
    escalation_model: str = "opus"
    daily_limit: int = 80
    daily_limit_escalation: int = 15
    llm_timeout: int = 600
    verdict_reuse_hours: int = 24
    redact_pii: bool = False
    idle_minutes: int = 60
    spike_window_minutes: int = 15
    db_path: str = "data/alert_doctor.db"
    runs_dir: str = "runs"
    rules_path: str = "rules.toml"
    checks_path: str = "checks.toml"
    log_dir: str = "logs"
    mirrors_dir: str = "mirrors"
    topology_path: str = "topology.toml"
    known_path: str = "known.toml"
    shadow_sample_rate: float = 0.1
    auto_rule_ttl_days: int = 7
    default_owners: tuple[str, ...] = ()
    # Slack user IDs allowed to 固定錯誤 / 取消固定; load_config defaults it to default_owners.
    known_editors: tuple[str, ...] = ()
    source_bot_ids: tuple[str, ...] = ()
    purge_green: bool = True
    first_reply_immediate: bool = True
    update_every_minutes_early: int = 1
    update_early_window_minutes: int = 10
    update_every_minutes_late: int = 5
    budget_elk_per_min: int = 30
    budget_elk_reserved_critical: int = 10
    budget_slack_per_min: int = 20
    budget_slack_reserved_critical: int = 4
    budget_slack_reserved_first: int = 4
    budget_llm_per_min: int = 5
    overload_intake_per_min: int = 15
    overload_active_incidents: int = 10
    overload_exit_minutes: int = 5
    overload_untag_minutes: int = 30
    backfill_lag_seconds: int = 120
    fragment_join_seconds: int = 15
    watchdog_snapshot_path: str = "watchdog_snapshot/tasks.json"
    archive_db_path: str = "data/error_archive.db"
    batch_settle_seconds: int = 20
    update_min_interval_minutes: int = 2
    elk_cli_path: str = "/Users/you/.claude/skills/elk-logs/scripts/elk.py"

    @property
    def channel_ids(self) -> frozenset[str]:
        return frozenset(c.id for c in self.channels)

    def channel(self, channel_id: str) -> ChannelSpec | None:
        return next((c for c in self.channels if c.id == channel_id), None)

    def permalink(self, channel: str, ts: str) -> str:
        return f"{self.workspace_url.rstrip('/')}/archives/{channel}/p{ts.replace('.', '')}"


_REQUIRED = ("workspace_url",)
_PATH_KEYS = ("db_path", "runs_dir", "rules_path", "checks_path", "log_dir", "mirrors_dir", "topology_path",
              "watchdog_snapshot_path", "archive_db_path", "known_path", "report_dir")


def _default_error_query(project: str) -> dict:
    return {"bool": {"filter": [
        {"term": {"project": project}}, {"term": {"log.levelname": "ERROR"}}]}}


def _channel(raw: dict) -> ChannelSpec:
    missing = [k for k in ("id", "name", "systems") if k not in raw]
    if missing:
        raise ValueError(f"[[channels]] 缺少欄位:{', '.join(missing)}")
    return ChannelSpec(raw["id"], raw["name"], tuple(raw["systems"]))


def _system(key: str, raw: dict) -> SystemSpec:
    if "elk_project" not in raw:
        raise ValueError(f"[systems.{key}] 缺少欄位:elk_project")
    query = raw.get("error_query")
    return SystemSpec(
        key=key, repos=tuple(raw.get("repos", ())), owners=tuple(raw.get("owners", ())),
        elk_project=raw["elk_project"],
        error_query=json.loads(query) if query else _default_error_query(raw["elk_project"]),
    )


def _repo(key: str, raw: dict) -> RepoSpec:
    if "path" not in raw:
        raise ValueError(f"[repos.{key}] 缺少欄位:path")
    return RepoSpec(key, raw["path"], raw.get("deploy_ref", "origin/HEAD"))


def load_config(path: str) -> Config:
    """Load a TOML file into Config; relative path settings resolve against the file's directory.

    Raises ValueError for missing required keys, unknown keys (a typo must not silently
    fall back to a default such as the daily LLM limit), no channel, or a channel/system
    referencing an undefined system/repo.
    """
    config_file = Path(path).resolve()
    with open(config_file, "rb") as f:
        raw = tomllib.load(f)

    known = {f.name for f in fields(Config)}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ValueError(f"設定檔有不認得的欄位:{', '.join(unknown)}")
    missing = [k for k in _REQUIRED if not raw.get(k)]
    if missing:
        raise ValueError(f"設定檔缺少必填欄位:{', '.join(missing)}")

    channels = tuple(_channel(c) for c in raw.pop("channels", ()))
    systems = {k: _system(k, v) for k, v in raw.pop("systems", {}).items()}
    repos = {k: _repo(k, v) for k, v in raw.pop("repos", {}).items()}
    if not channels:
        raise ValueError("設定檔至少要有一個 [[channels]]")
    for channel in channels:
        for system in channel.systems:
            if system not in systems:
                raise ValueError(f"頻道 {channel.name} 引用了未定義的 system:{system}")
    for system in systems.values():
        for repo in system.repos:
            if repo not in repos:
                raise ValueError(f"system {system.key} 引用了未定義的 repo:{repo}")

    defaults = {f.name: f.default for f in fields(Config) if f.name in _PATH_KEYS}
    for key in _PATH_KEYS:
        value = Path(raw.get(key, defaults[key]))
        raw[key] = str(value if value.is_absolute() else config_file.parent / value)
    raw["default_owners"] = tuple(raw.get("default_owners", ()))
    raw["source_bot_ids"] = tuple(raw.get("source_bot_ids", ()))
    raw["known_editors"] = tuple(raw.get("known_editors", raw["default_owners"]))
    return Config(channels=channels, systems=systems, repos=repos, **raw)


def unknown_check_systems(cfg: Config, checks: dict) -> list[str]:
    """One message per check whose `system` is set but not defined in `[systems]`."""
    return [
        f"checks.toml 的 {key} 引用了未定義的 system:{check.system}"
        for key, check in sorted(checks.items())
        if check.system and check.system not in cfg.systems
    ]
