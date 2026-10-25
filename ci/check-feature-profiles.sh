#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run() {
  local description="$1"
  shift
  printf '\n==> %s\n' "$description"
  "$@"
}

run "Core minimal (no default features)" \
  cargo check -p clash-lib --no-default-features --locked
run "Core default feature set" \
  cargo check -p clash-lib --locked
run "CLI standard without Dashboard" \
  cargo check -p clash-rs --no-default-features \
    --features standard,aws-lc-rs --locked
run "CLI default with embedded Dashboard" \
  cargo check -p clash-rs --locked
