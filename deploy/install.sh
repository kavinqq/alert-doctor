#!/bin/bash
# 可重複執行:每次先 bootout 再 bootstrap,等同重載。
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
AGENTS="$HOME/Library/LaunchAgents"
UID_NUM="$(id -u)"

if [ ! -f "$REPO/config.toml" ]; then
    echo "找不到 $REPO/config.toml,請先依 README 從 config.example.toml 建立" >&2
    exit 1
fi

mkdir -p "$REPO/logs" "$REPO/data" "$AGENTS"

for plist in "$REPO"/deploy/launchd/*.plist; do
    name="$(basename "$plist" .plist)"
    cp "$plist" "$AGENTS/$name.plist"
    launchctl bootout "gui/$UID_NUM/$name" 2>/dev/null || true
    launchctl bootstrap "gui/$UID_NUM" "$AGENTS/$name.plist"
    echo "已載入 $name"
done

launchctl list | grep alert-doctor || true
