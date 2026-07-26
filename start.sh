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

# Keep Cargo's target directory owned by the developer. Only the already-built
# binary needs elevated privileges when TUN setup is enabled.
nix develop --command cargo build -p clash-rs
nix develop --command "$ROOT_DIR/target/debug/clash-rs" -t -c "$CONFIG_FILE"

run_command=(
    "$ROOT_DIR/target/debug/clash-rs"
    -c "$CONFIG_FILE"
    --log-file "$APP_LOG_FILE"
)

if [[ "${RUN_AS_ROOT:-1}" == "1" ]]; then
    nix develop --command sudo -- "${run_command[@]}" \
        2>&1 | tee -a "$CONSOLE_LOG_FILE"
else
    nix develop --command "${run_command[@]}" \
        2>&1 | tee -a "$CONSOLE_LOG_FILE"
fi
