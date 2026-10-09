#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ROOT_DIR/target/release/clash-rs"
LOG_DIR="${LOG_DIR:-$HOME/Library/Logs/Chimera_Client}"

umask 077

if [[ ! -x "$BIN" ]]; then
    echo "Release binary not found or not executable: $BIN" >&2
    exit 1
fi

if ! mkdir -p "$LOG_DIR"; then
    echo "Could not create log directory: $LOG_DIR" >&2
    exit 1
fi

LOG_FILE="${LOG_FILE:-$LOG_DIR/clash-$(date '+%Y%m%d-%H%M%S').log}"

cd "$ROOT_DIR" || exit 1

if ! sudo -v; then
    echo "Could not authenticate with sudo." >&2
    exit 1
fi

echo "Recording clash-rs output to: $LOG_FILE"
sudo -n "$BIN" "$@" 2>&1 | tee "$LOG_FILE"
status=$?

printf '\nclash-rs exited with status %s\n' "$status" | tee -a "$LOG_FILE"
exit "$status"
