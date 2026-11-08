#!/usr/bin/env bash
# Reproducible local subset of CI quality gates. Does not change Git refs,
# install system packages, or touch real NIC/TUN settings.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

usage() {
  cat <<'HELP'
Usage: ci/verify-quality-gates.sh [--quick|--full] [--target-dir PATH] [--allow-network]
  --quick          Format, feature forwarding, default-feature all-target Clippy,
                   and library unit tests (default).
  --full           Additionally test no-default-features and CLI, verify/lint/build
                   existing Dashboard dependencies once, run all-feature all-target
                   Clippy + LAN tests.
  --target-dir     Cargo artifact directory. Defaults to CARGO_TARGET_DIR or
                   /Volumes/ChimeraClientVlessTests/Chimera_Client_master_target.
  --reinstall-dashboard  Run pnpm install from the lockfile before Dashboard checks.
  --allow-network  Permit explicitly requested pnpm install to fetch packages;
                   the optional reinstall is offline by default.
The default target lives in an APFS sparsebundle backed by the external
Ventoy USB drive. It MUST be mounted. Builds never silently fall back to
the almost-full system disk. Do not use raw exFAT as a Cargo target directory.
HELP
}
mode=quick
reinstall_dashboard=0
pnpm_network=(--offline)
target_dir="${CARGO_TARGET_DIR:-/Volumes/ChimeraClientVlessTests/Chimera_Client_master_target}"
while (($#)); do
  case "$1" in
    --quick) mode=quick ;;
    --full) mode=full ;;
    --target-dir)
      shift
      if (($# == 0)); then echo "Missing --target-dir argument" >&2; exit 2; fi
      target_dir="$1" ;;
    --allow-network) pnpm_network=() ;;
    --reinstall-dashboard) reinstall_dashboard=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# Do not silently use local target/, even if Cargo's normal default would
# otherwise make the check succeed on one machine and fill another's disk.
if [[ -z "$target_dir" || "$target_dir" != /* ]]; then
  echo "Cargo target directory must be an absolute path: $target_dir" >&2
  exit 2
fi
if [[ "$target_dir" == "$ROOT/target" || "$target_dir" == "$ROOT/target/"* ]]; then
  echo "Refusing internal target directory: $target_dir" >&2
  exit 2
fi
if [[ ! -d "$(dirname "$target_dir")" ]]; then
  echo "External build volume is not mounted: $(dirname "$target_dir")" >&2
  exit 2
fi
mkdir -p "$target_dir"
# An unmounted /Volumes/... directory can still exist on the system disk.
# Compare actual filesystems AFTER resolving any symlink, before compiling.
resolved_target="$(cd "$target_dir" && pwd -P)"
root_device="$(df -P "$ROOT" | awk 'NR == 2 {print $1}')"
target_device="$(df -P "$resolved_target" | awk 'NR == 2 {print $1}')"
if [[ -z "$target_device" || "$target_device" == "$root_device" ]]; then
  echo "Target resolves onto the system disk (external volume missing?): $resolved_target" >&2
  exit 2
fi
export CARGO_TARGET_DIR="$target_dir"

# Keep the pnpm store on the same APFS volume when using the project's known
# external build image. Other callers may supply their own pnpm_config_store_dir.
if [[ -z "${pnpm_config_store_dir:-}" && "$target_dir" == /Volumes/ChimeraClientVlessTests/* ]]; then
  export pnpm_config_store_dir=/Volumes/ChimeraClientVlessTests/pnpm-store
  mkdir -p "$pnpm_config_store_dir"
fi

printf 'Repository: %s\nMode: %s\nCargo target: %s\n' "$ROOT" "$mode" "$CARGO_TARGET_DIR"
printf 'HEAD: '; git rev-parse HEAD
printf 'Dirty worktree (included in checks):\n'; git status --short
printf '\n'
run() {
  printf '\n=== %s ===\n' "$1"
  shift
  "$@"
}
run "Whitespace" git diff --check
run "Rust formatting" cargo fmt --all -- --check
run "CLI -> core feature forwarding" python3 ci/check-feature-forwarding.py
run "Default-feature all-target strict Clippy" cargo clippy -p clash-lib --all-targets --locked -- -D warnings
run "Core library unit tests" cargo test -p clash-lib --lib --locked

if [[ "$mode" == full ]]; then
  # pnpm's frozen install and the Dashboard's lint/build are the same gates
  # used by CI. Rust consumes the generated dist/ files but never invokes pnpm.
  if ((reinstall_dashboard)); then
    run "Dashboard frozen dependency install" pnpm --dir clash-dashboard install --frozen-lockfile "${pnpm_network[@]}"
  else
    [[ -f "$ROOT/clash-dashboard/node_modules/.pnpm/lock.yaml" ]] || {
      echo "Dashboard dependencies absent: run --reinstall-dashboard (optionally --allow-network)" >&2
      exit 2
    }
    run "Dashboard installed dependency validation" pnpm --dir clash-dashboard list --depth=0
  fi
  run "Dashboard lint" pnpm --dir clash-dashboard run lint
  run "Dashboard TypeScript and Vite build" pnpm --dir clash-dashboard run build
  [[ -s "$ROOT/clash-dashboard/dist/index.html" ]] || {
    echo "Dashboard did not produce dist/index.html" >&2; exit 1;
  }
  # The documented Cargo feature profiles cover the minimal/core/CLI variants,
  # including the Dashboard CLI consuming the build produced above.
  run "Supported Cargo feature profiles" ci/check-feature-profiles.sh
  run "All-feature all-target strict Clippy" cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings
  run "LAN proxy integration" cargo test -p clash-lib --test lan_proxy_tests --all-features --locked
fi

printf '\nPASS: all requested local quality gates\n'
