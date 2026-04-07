# Chimera Client (`clash-rs`)

[中文](README.md) | [English](README_en.md)

Chimera Client is a Rust reimplementation of the Clash proxy client stack. It aims to keep the familiar Clash / Mihomo YAML configuration workflow while taking advantage of Rust's type safety, async runtime, observability, and cross-platform maintainability.

The current codebase follows the architecture of upstream [`clash-rs`](https://github.com/Watfaq/clash-rs) and extends it for Chimera-specific needs. It already includes the CLI entrypoint, configuration parsing, runtime assembly, DNS, routing, inbound and outbound management, proxy protocols, TUN support, REST API handlers, and configuration reload flow.

## Goals

- **Clash-compatible configuration**: keep the YAML-based user experience and continue expanding support for proxies, proxy groups, rules, DNS, TUN, profiles, and external controller APIs.
- **Rust-native runtime**: build the networking core on top of `tokio`, structured errors, strong typing, and `tracing`.
- **Modular proxy core**: keep DNS, router, dispatcher, inbound, outbound, profile, and API responsibilities separated so they can evolve and be tested independently.
- **Cross-platform and embeddable design**: reserve integration paths through crates such as `clash-ffi` and `clash-netstack`.

## Current Capabilities

- VLESS + Reality + TCP
- Trojan + TLS + WebSocket
- Hysteria2
- SOCKS5 inbound / outbound
- HTTP / Mixed listening ports
- TUN mode
- DNS resolver, DNS listener, Fake IP, and DNS filtering
- Proxy groups, including Selector, URLTest, and Fallback
- REST API controller
- Configuration file reload
- MMDB, ASN MMDB, and Geosite download / lookup
- TLS crypto provider setup through `aws-lc-rs` or `ring`

Some modules are still evolving. Protocol compatibility, cross-platform behavior, and test coverage are expected to improve over time.

## Repository Layout

```text
.
├── Cargo.toml          # Rust workspace definition
├── rust-toolchain.toml # Rust toolchain configuration
├── clash-bin/          # CLI entrypoint, package name: clash-rs
├── clash-lib/          # Core runtime library
├── clash-dns/          # DNS-related crate
├── clash-netstack/     # TUN / netstack-related crate
├── clash-ffi/          # Reserved for FFI embedding
├── clash-doc/          # Reserved for docs and config reference generation
├── xhttp-h2-phaseb/    # XHTTP / HTTP2 transport experiment
├── docs/               # Design notes, change docs, and project docs
└── ref/                # Reference implementation sources
```

Key crates:

- `clash-bin`: parses CLI arguments, locates or creates config files, validates config, and starts the runtime through `clash-lib`.
- `clash-lib`: the main runtime library. It contains config conversion, logging, DNS, routing, inbound and outbound management, proxy protocols, TUN, API, profile cache, and runtime lifecycle management.
- `clash-dns`: DNS support crate, consumed by `clash-lib` as `chimera-dns`.
- `clash-netstack`: supports TUN and userspace networking.
- `clash-ffi`: reserved for future GUI, mobile, or host application embedding.
- `clash-doc`: reserved for config and API documentation generation.

## Runtime Flow

Start the client with:

```bash
cargo run -p clash-rs -- -c config.yaml
```

Startup flow:

1. `clash-bin` parses CLI arguments with `clap`.
2. If the config file does not exist, the CLI creates a minimal default file with `port: 7890`.
3. If `-t` or `--test-config` is passed, the process only parses the config and returns the validation result.
4. During normal startup, `clash-bin` calls `clash-lib::start_scaffold`.
5. `clash-lib` creates a Tokio runtime, parses YAML config, and converts it into the internal runtime config.
6. The core initializes logging, cache, DNS resolver, outbound manager, router, dispatcher, authenticator, inbound manager, DNS listener, TUN runner, and REST API runner.
7. The runtime listens for Ctrl+C or an internal shutdown token, and it supports config reload through the API.

Common commands:

```bash
cargo run -p clash-rs -- -c config.yaml
cargo run -p clash-rs -- --config config.yaml --directory .
cargo run -p clash-rs -- -t -c config.yaml
cargo run -p clash-rs -- --version
```

During development, you can also use the helper scripts:

```bash
./start.sh
# Windows:
./start.ps1
```

## Core Modules

`clash-lib` is the main runtime crate:

- `app::logging`: `tracing`-based logging and event collection.
- `app::dns`: DNS resolver, Fake IP, DNS server, filters, and system resolver.
- `app::router`: rule routing for domain, keyword, CIDR, GeoIP, Geosite, MATCH, and related rule types.
- `app::dispatcher`: connection dispatcher that sends traffic to the selected outbound handler.
- `app::inbound`: inbound listener and connection management.
- `app::outbound`: outbound manager for plain proxies, proxy groups, and proxy providers.
- `app::api`: external controller API handlers for config, proxies, rules, logs, connections, DNS, traffic, and version.
- `app::profile`: cache files and profile state.
- `proxy`: proxy protocols and transports, including Direct, Reject, Socks5, Trojan, Hysteria2, VLESS, proxy groups, TUN, WebSocket, TLS, Reality, and XHTTP.
- `config`: Clash-style YAML config definitions, parsing, and internal conversion.
- `runner`: shared run, shutdown, and join abstraction for long-lived components.
- `session`: connection session metadata.

## Configuration Pipeline

The project keeps the Clash-style YAML workflow. Config handling is split into two layers:

- `config::def`: raw config structures used for YAML deserialization.
- `config::internal`: runtime-friendly internal config structures.

`clash-lib::Config` supports three input forms:

- `Config::File`: load config from a file path.
- `Config::Str`: parse config from a string.
- `Config::Internal`: pass an internal config structure directly.

The parser uses `serde_yaml` and supports YAML merge behavior through `Value::apply_merge` to stay close to Clash semantics. The converted internal config drives DNS, proxies, rules, listeners, profiles, and API runtime components.

## Feature Design

The project uses Cargo features to control optional functionality:

- `tls`: enable Rustls / Tokio Rustls TLS support.
- `ws`: enable WebSocket transport.
- `trojan`: enable Trojan protocol support.
- `hysteria`: enable Hysteria / Hysteria2 QUIC / H3 support.
- `reality`: enable Reality transport support.
- `tun`: enable TUN, netstack, and system routing support.
- `port`, `http_port`, `mixed_port`: enable HTTP / Mixed listening ports.
- `aws-lc-rs`, `ring`: select the TLS crypto provider.
- `tproxy`, `redir`: transparent proxy related features.

`clash-bin` enables `standard` and `aws-lc-rs` by default. The `standard` feature enables `trojan`, `ws`, `tls`, `hysteria`, `reality`, `port`, and `tun`.

## Development

```bash
cargo check --all
cargo build
cargo run -p clash-rs -- -c config.yaml
cargo fmt
cargo clippy --all-targets --all-features
cargo test --all
```

Run a focused test:

```bash
cargo test -p clash-lib put_configs_reloads_runtime_from_file
```

Run CI-like tests:

```bash
CLASH_RS_CI=true cargo test --all --all-features
```

## Notes

- The project is still evolving. Some protocols, platform behavior, and API behavior still need follow-up work.
- The workspace version in `Cargo.toml` is currently `0.11.1`, and the Rust edition is `2024`.
- Start with `cargo check --all`, then run `cargo fmt`, `cargo clippy --all-targets --all-features`, and `cargo test --all` according to the size and risk of the change.
- When changing config, DNS, routing, proxy behavior, or runtime lifecycle code, prefer adding focused tests to protect reload and controller behavior.
- TUN, Reality, Hysteria2, WebSocket, and TLS depend on features and platform environment. Debugging these areas usually requires checking build features, system permissions, and network setup together.

## Roadmap

1. Improve Clash / Mihomo configuration compatibility.
2. Strengthen VLESS Reality, Trojan, Hysteria2, WebSocket, TLS, and UDP behavior.
3. Improve TUN, DNS hijack, Fake IP, and system route handling across Windows, Linux, and macOS.
4. Expand REST API compatibility with Clash / Mihomo controllers.
5. Add integration tests for config loading, reload, rule matching, DNS, inbound listeners, and outbound dialing.
6. Keep `clash-doc` and `docs/` aligned with runtime and configuration changes.

## Summary

Chimera Client is a Rust proxy client focused on Clash-compatible behavior. `clash-lib` is the core crate, separating config parsing, runtime lifecycle, DNS, routing, inbound and outbound proxying, REST API, and TUN support into clear modules. Cargo features control protocol and platform capabilities. The next stage is to keep improving Clash / Mihomo compatibility, cross-platform stability, and test coverage.
