#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

CONFIG_FILE="${CONFIG_FILE:-config-prod.yaml}"
LOG_DIR="${LOG_DIR:-logs}"
RUN_ID="$(date '+%Y%m%d-%H%M%S')"

mkdir -p "$LOG_DIR"

APP_LOG_FILE="${APP_LOG_FILE:-$ROOT_DIR/$LOG_DIR/chimera-$RUN_ID.log}"
CONSOLE_LOG_FILE="${CONSOLE_LOG_FILE:-$ROOT_DIR/$LOG_DIR/chimera-$RUN_ID.console.log}"

# clash-lib currently opens --log-file in append-only mode, so create it first.
touch "$APP_LOG_FILE" "$CONSOLE_LOG_FILE"

echo "config: $CONFIG_FILE"
echo "app log: $APP_LOG_FILE"
echo "console log: $CONSOLE_LOG_FILE"

sudo nix develop --command cargo run -p clash-rs -- \
    -c "$CONFIG_FILE" \
    --log-file "$APP_LOG_FILE" \
    2>&1 | tee -a "$CONSOLE_LOG_FILE"
