# alert-doctor

**An on-call assistant that reads every alert in your Slack monitoring channels, decides which ones actually matter, and posts a root-cause analysis for the new ones, with file and line citations that are verified before posting.**

My team's monitoring channels received hundreds of scheduled-check alerts a day. Most were noise, known issues, or repeats of an alert from five minutes earlier, so real incidents got lost. alert-doctor triages each alert with cheap deterministic signals first. It calls an LLM only for alerts that are actually new, and it never lets the LLM post a claim it cannot back up.

- **Python standard library only.** This includes the Slack Socket Mode WebSocket client, which is implemented from scratch.
- Runs on one Mac: SQLite in WAL mode plus a few launchd agents. No inbound port is needed.
- **1379 unit tests.** They make no network calls and never call git, Claude, Slack or ELK.

---

## How it works

```
Slack monitoring channels ─Socket Mode─▶ collector ──▶ SQLite (WAL) ──▶ analyzer ──▶ outbox ──▶ publisher ──▶ one report thread
                       ▲                 │ parse / fingerprint / incident            │                          per incident
       ❌ ✅ 🔇 feedback ┘                 │ ELK volume signal + hourly baseline       ├─ read-only checkout of every repo
                                         │ auto-rules (shadow → active, 10% sampled) ├─ service topology + co-erroring systems
                                         │ every alert is classified                 └─ claude -p, citations verified
tuner (hourly): baselines, propose / promote / expire auto-rules
```

### 1. Collect and triage, cheaply (`collector.py`, `triage.py`)

Every alert message is parsed and **fingerprinted**: UUIDs, IPs, timestamps, long hex strings and numbers are templated away, so "the same error with different values" groups together. Alerts with the same `task_id` across channels merge into one **incident**.

Each alert is then classified without an LLM:

| Category | Meaning |
|---|---|
| `noise` | Matches an active auto-rule or a human rule |
| `known` | Linked to a known issue or maintenance window |
| `duplicate` | Same fingerprint as an incident that is still open |
| `accumulated` | Each alert is small, but ELK volume is far above this hour's healthy baseline |
| `spike` / `critical` | Volume jump, or a check marked `never_silence` |
| `datasource` | The monitoring data source itself is broken (e.g. ELK unreachable) |
| `new` | None of the above, so it is sent to analysis |

### 2. Analyse only what's new (`analyzer.py`)

New incidents go to `claude -p`. The analysis gets read-only checkouts of **every** service repository, a service-topology file, the error volume of other systems in the same time window, and the source of the scheduled check that fired.

The returned verdict (cause, impact, suggested fix, severity) is **validated before anything is posted**:

- every cited `file:line` must exist in the read-only checkout, and every cited ELK key must exist in the evidence the session actually queried. Citations that fail this check are **removed**, not posted.
- the verdict must be internally consistent: category matches action, a human-needed action sets `needs_human`, fix steps are concrete, and the claims are backed by evidence. A verdict that breaks these rules is re-run **once** on a stronger model (`escalation_model`), within a daily budget. If it is still broken, it goes to a retry path instead of to Slack.

### 3. Post calmly, even during an alert storm (`publisher.py`)

- Each incident gets **one report thread per channel**. Owners are tagged only on the first post; later updates go in the same thread without tags.
- Every post goes through a durable SQLite **outbox**. The publisher sends at most one message per second per channel, within the overall Slack rate budget.
- When alert volume explodes, the service enters **overload protection**: it stops tagging, sends only the top incidents to the LLM, and posts one "storm" summary instead of hundreds of replies.

### 4. Learn, but only within limits set by humans (`tuner.py`, `autorules.py`, `feedback.py`)

- **Hourly baselines** come from the last 14 days of healthy periods. They can be rolled back by version.
- **Auto-rules** are proposed from analysis results or a 🔇 reaction. They start in *shadow* mode and are promoted only when they meet the promotion conditions. Even active rules still send 10% of matches to analysis, so silenced alerts keep being re-checked.
- **Humans keep the final say.** These always override auto-rules: `never_silence` checks, owners, and absolute volume floors. An auto-rule is revoked immediately on a volume spike, a ❌ reaction, or a change in the repository SHA.
- Reactions on bot replies give feedback: ❌ means wrong (re-analyse and tag the owners), ✅ means agreed.

### 5. Known issues from Slack (`known.py`, `known_store.py`)

In any alert thread, `@alertdoctor 固定錯誤 <name> [30天]` links the error to a known issue for a limited time (default 14 days, max 90). Matching alerts are then answered directly, without analysis, until the link expires. Volume spikes still go to analysis. `known review` lists links that are about to expire, have gone silent, or fire too often.

---

## Commands

```bash
python3 -m alert_doctor <command> --config config.toml
```

| Command | Purpose |
|---|---|
| `collector` | Long-running: receive, triage, publish, handle feedback |
| `analyzer` | Long-running: LLM root-cause analysis; refreshes repo checkouts every 10 minutes |
| `tuner [--rollback VERSION]` | Recompute baselines and auto-rules (hourly via launchd) |
| `report [--weekly] [--post]` | Daily or weekly report: severity mix, auto-rule changes, feedback accuracy, LLM usage, noisiest fingerprints |
| `health [--post]` | Health check: outbox latency, prolonged overload, stale snapshots. Exits 1 on problems. |
| `replay <file.jsonl>` | Offline replay: prints each classification, then runs the publisher on a simulated clock to show exactly what would be posted |
| `discover --hours 168` | Read-only scan of what each channel contains, to help write `checks.toml` / `rules.toml` |
| `outbox`, `backfill`, `mirrors`, `archive-report`, `known …` | Operations helpers |

---

## Setup

Requires Python 3.11+ (for `tomllib`) and the [Claude Code](https://claude.com/claude-code) CLI on `PATH` for the analyzer.

1. **Create the Slack app** from `deploy/slack-app-manifest.yml`. Socket Mode is already enabled in the manifest. Then generate an app-level token with `connections:write`.
2. **Copy the example configs** and edit them:
   ```bash
   for f in config rules checks topology known; do cp $f.example.toml $f.toml; done
   ```
3. **Provide secrets** through environment variables or the macOS Keychain. They are never stored in config files:
   ```bash
   export ALERT_DOCTOR_BOT_TOKEN=xoxb-...
   export ALERT_DOCTOR_APP_TOKEN=xapp-...     # connections:write, for Socket Mode
   export ALERT_DOCTOR_OPS_ELK=...            # ELK password
   ```
4. **Run it**, either in the foreground (`python3 -m alert_doctor collector` / `analyzer`) or as launchd agents:
   ```bash
   # edit the absolute paths in deploy/launchd/*.plist first
   ./deploy/install.sh
   ```

### Tests

```bash
python3 -m unittest discover -s tests -t .
```

Three tests are skipped in this public copy. They check private local data that is not included: real eval cases, the real `known.toml`, and a snapshot of the scheduler.

---

## Notes

- Slack messages, config comments and most code comments are in Traditional Chinese, because the tool was built for a Taiwanese team.
- Hostnames, IPs, Slack IDs, repository names and vendor names in this repository are placeholders.

## License

[MIT](LICENSE) © 2026 KuanLin
