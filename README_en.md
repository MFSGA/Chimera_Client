# Chimera Client (`clash-rs`)

[中文](README.md) | [English](README_en.md) | [Русский](README_ru.md) | [فارسی](README_fa.md)

Chimera Client is a Rust reimplementation of the Clash proxy client stack. The goal is to stay as compatible as practical with Clash / Mihomo configuration style and operational workflow, while taking advantage of Rust's stronger type safety, async runtime, observability, and cross-platform maintainability.

The current codebase mainly follows the architecture of upstream [`clash-rs`](https://github.com/Watfaq/clash-rs) and continues extending protocols, runtime behavior, and control interfaces for Chimera-specific needs. The project already includes core modules such as the CLI, configuration parsing, runtime assembly, DNS, routing, inbound and outbound management, proxy protocols, TUN, REST API, and hot reload.

## Project Goals

- **Clash-compatible configuration experience**: keep the familiar YAML workflow and continue expanding support for proxies, proxy groups, rules, DNS, TUN, profiles, and external controller APIs.
- **Rust-native runtime**: build on `tokio`, strong typing, structured error handling, and `tracing` to improve reliability and maintainability.
- **Modular proxy core**: keep DNS, router, dispatcher, inbound, outbound, profile, and API responsibilities separated so they can be developed and tested independently.
- **Cross-platform and embeddable design**: reserve integration paths through crates such as `clash-ffi` and `clash-netstack` for GUI, mobile, TUN, and FFI scenarios.

## Current and In-Progress Capabilities

- XHTTP
- VLESS + Reality + TCP
- Trojan + TLS + WebSocket
- Hysteria2
- SOCKS5 inbound / outbound
- HTTP / Mixed listening ports
- TUN mode
- DNS resolver, DNS listener, Fake IP, and DNS filtering
- Proxy groups, including Selector, URLTest, and Fallback
- REST API controller
- Configuration hot reload
- MMDB, ASN MMDB, and Geosite download / lookup
- TLS crypto provider selection through `aws-lc-rs` or `ring`

Some modules are still being completed. Protocol compatibility, cross-platform behavior, and test coverage will continue improving as development progresses.

## Runtime Flow

Start the client with:

```bash
cargo run -p clash-rs -- -c config.yaml
```

Startup flow:

1. `clash-bin` parses CLI arguments with `clap`.
2. If the config file does not exist, the CLI creates a minimal file whose default content is `port: 7890`.
3. If `-t` or `--test-config` is passed, the process only parses the config and returns the validation result.
4. During normal startup, `clash-bin` calls `clash-lib::start_scaffold`.
5. `clash-lib` creates a Tokio runtime, parses the YAML configuration, and converts it into the internal runtime config.
6. The core initializes logging, cache, DNS resolver, outbound manager, router, dispatcher, authenticator, inbound manager, DNS listener, TUN runner, and REST API runner.
7. The runtime listens for Ctrl+C or an internal shutdown token and supports config hot reload through the API.

Common commands:

```bash
cargo run -p clash-rs -- -c config.yaml
cargo run -p clash-rs -- --config config.yaml --directory .
cargo run -p clash-rs -- -t -c config.yaml
cargo run -p clash-rs -- --version
```

## Feature Design

The project uses Cargo features to control optional functionality. Common features include:

- `tls`: enable Rustls / Tokio Rustls TLS support.
- `ws`: enable WebSocket transport.
- `trojan`: enable Trojan protocol support.
- `hysteria`: enable Hysteria / Hysteria2 QUIC / H3 support.
- `reality`: enable Reality transport support.
- `tun`: enable TUN, netstack, and system routing support.
- `port`, `http_port`, `mixed_port`: enable HTTP / Mixed listening ports.
- `aws-lc-rs`, `ring`: choose the underlying crypto provider.
- `tproxy`, `redir`: transparent proxy related features.

`clash-bin` enables `standard` and `aws-lc-rs` by default. The `standard` feature pulls in `trojan`, `ws`, `tls`, `hysteria`, `reality`, `port`, `tun`, and other core capabilities.

## Development Commands

```bash
cargo check --all
cargo build
cargo run -p clash-rs -- -c config.yaml
cargo fmt
cargo clippy --all-targets --all-features
cargo test --all
```

Run a single crate or a focused test:

```bash
cargo test -p clash-lib
cargo test -p clash-lib put_configs_reloads_runtime_from_file
```

Run CI-like tests:

```bash
CLASH_RS_CI=true cargo test --all --all-features
```

## Current Notes

- The project is still evolving quickly. Some protocols, platform behavior, and API behavior still need follow-up work.
- The Rust edition is `2024`.
- During development, it is recommended to run `cargo check --all` first, then `cargo fmt`, `cargo clippy --all-targets --all-features`, and `cargo test --all` according to the scope of the change.
- When changing config, DNS, routing, proxy behavior, or runtime lifecycle code, prefer adding focused tests to protect reload and controller behavior.
- TUN, Reality, Hysteria2, WebSocket, TLS, and similar features depend on Cargo features and platform environment. Debugging them usually requires checking build features, system permissions, and network conditions together.

## Roadmap

1. Organize the project wiki.
2. Continue improving Clash / Mihomo configuration compatibility so common real-world configs can be parsed and converted reliably.
3. Strengthen protocol implementations, especially VLESS Reality, Trojan, Hysteria2, WebSocket, TLS, and UDP behavior.
4. Improve handling of TUN, DNS hijack, Fake IP, and system routing differences across Windows, Linux, and macOS.
5. Improve REST API compatibility with Clash / Mihomo controllers.
6. Expand integration tests to cover config loading, hot reload, rule matching, DNS, inbound listeners, and outbound dialing flows.

## Contributing

#### If you run into usage problems or implementation issues, issues and PRs are welcome.
#### Even if you are completely new to computing, please read the [wiki](https://mfsga.github.io/Proxy_WIKI/) first and then ask targeted questions. I will reply when time allows.
#### One of the major goals of this project is also to attract more developers to participate.

## If this project helps you, a star is welcome 🧡
