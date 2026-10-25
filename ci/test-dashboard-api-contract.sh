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

run "Dashboard HTTP response shapes, errors, and authentication" \
  cargo test -p clash-lib --test api_smoke_tests --locked
run "Dashboard selector mutation contract" \
  cargo test -p clash-lib --test api_selector_tests --locked
run "Dashboard delay response contract" \
  cargo test -p clash-lib --test api_delay_tests --locked
run "Dashboard proxy provider response contract" \
  cargo test -p clash-lib --test api_provider_tests --locked \
    test_get_provider -- --exact
run "Dashboard provider delay response contract" \
  cargo test -p clash-lib --test api_provider_tests --locked \
    test_provider_proxy_healthcheck -- --exact
run "Dashboard configuration validation and mode contract" \
  cargo test -p clash-lib --test api_tests --locked \
    client_capability_controller_endpoints_expose_validation_and_mode_override \
    -- --exact
run "Dashboard file reload contract" \
  cargo test -p clash-lib --test api_reload_tests --locked \
    put_configs_reloads_runtime_from_file -- --exact
run "Dashboard DNS response wire contract" \
  cargo test -p clash-lib --lib --locked app::api::handlers::
run "Dashboard log WebSocket event field contract" \
  cargo test -p clash-lib --lib --locked \
    app::logging::tests::log_event_serializes_to_dashboard_field_names
run "Dashboard connection and flow response contract" \
  cargo test -p clash-lib --test connection_chain_tests --locked
run "Dashboard WebSocket payload and token contract" \
  cargo test -p clash-lib --features ws \
    --test dashboard_websocket_contract_tests --locked
run "Dashboard log WebSocket route and event contract" \
  cargo test -p clash-lib --features ws \
    --test dashboard_logs_websocket_contract_tests --locked
run "Clash-compatible proxy response contract" \
  cargo test -p clash-lib --test ref_api_compat_tests --locked
