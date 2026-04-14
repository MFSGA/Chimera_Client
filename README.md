# Chimera Client (`clash-rs`)

[中文](README.md) | [English](README_en.md) | [Русский](README_ru.md) | [فارسی](README_fa.md)

Chimera Client 是一个使用 Rust 重新实现 Clash 网络代理栈的客户端项目。项目目标是在尽量兼容 Clash / Mihomo 配置与使用习惯的基础上，利用 Rust 生态提供更强的类型安全、异步运行时能力、可观测性和跨平台维护能力。

当前代码主要参考上游 [`clash-rs`](https://github.com/Watfaq/clash-rs) 的架构，并围绕 Chimera 的需求继续补齐协议、运行时和控制接口。项目已经包含 CLI、配置解析、运行时装配、DNS、路由、出入站管理、代理协议、TUN、REST API 和热重载等核心模块。

## 项目目标

- **兼容 Clash 配置体验**：继续支持用户熟悉的 YAML 配置方式，并逐步覆盖代理、代理组、规则、DNS、TUN、Profile 和外部控制接口。
- **Rust 原生运行时**：基于 `tokio` 构建异步网络运行时，使用强类型、结构化错误和 `tracing` 日志提升可靠性与可维护性。
- **模块化代理核心**：将 DNS、路由、Dispatcher、Inbound、Outbound、Profile、API 等能力拆分为独立模块，便于分阶段开发和测试。
- **跨平台与可嵌入能力**：通过 `clash-ffi`、`clash-netstack` 等 crate 预留 GUI、移动端、TUN 和 FFI 集成方向。

## 当前支持与开发中的能力

- XHTTP
- VLESS + Reality + TCP
- Trojan + TLS + WebSocket
- Hysteria2
- SOCKS5 入站 / 出站
- HTTP / Mixed 监听端口
- TUN 模式
- DNS resolver、DNS listener、Fake IP 与 DNS 过滤
- 代理组，包括 Selector、URLTest、Fallback
- REST API 控制接口
- 配置文件热重载
- MMDB、ASN MMDB、Geosite 下载和查询
- 基于 `aws-lc-rs` 或 `ring` 的 TLS crypto provider 配置

部分模块仍在持续补齐中，协议兼容性、跨平台行为和测试覆盖会随着开发继续完善。

## 运行流程

用户通过 `clash-rs` 启动客户端：

```bash
cargo run -p clash-rs -- -c config.yaml
```

启动流程概览：

1. `clash-bin` 使用 `clap` 解析命令行参数。
2. 如果配置文件不存在，会自动生成一个最小配置文件，默认内容为 `port: 7890`。
3. 如果传入 `-t` 或 `--test-config`，程序只解析配置并返回校验结果。
4. 正常启动时，`clash-bin` 调用 `clash-lib::start_scaffold`。
5. `clash-lib` 创建 Tokio runtime，解析 YAML 配置并转换为内部配置结构。
6. 核心库初始化日志、缓存、DNS resolver、出站管理器、路由器、Dispatcher、认证器、入站管理器、DNS listener、TUN runner 和 REST API runner。
7. 运行时监听 Ctrl+C 或内部 shutdown token，并支持通过 API 触发配置热重载。

常用参数：

```bash
cargo run -p clash-rs -- -c config.yaml
cargo run -p clash-rs -- --config config.yaml --directory .
cargo run -p clash-rs -- -t -c config.yaml
cargo run -p clash-rs -- --version
```

## Feature 设计

项目通过 Cargo features 控制可选功能。常见 feature 包括：

- `tls`：启用 Rustls / Tokio Rustls TLS 支持。
- `ws`：启用 WebSocket 传输。
- `trojan`：启用 Trojan 协议。
- `hysteria`：启用 Hysteria / Hysteria2 相关 QUIC / H3 能力。
- `reality`：启用 Reality 传输能力。
- `tun`：启用 TUN、netstack 和系统路由相关能力。
- `port`、`http_port`、`mixed_port`：启用 HTTP / Mixed 监听端口能力。
- `aws-lc-rs`、`ring`：选择底层加密 provider。
- `tproxy`、`redir`：透明代理相关能力。

`clash-bin` 默认启用 `standard` 和 `aws-lc-rs`。其中 `standard` 会打开 `trojan`、`ws`、`tls`、`hysteria`、`reality`、`port`、`tun` 等核心能力。

## 开发命令

```bash
cargo check --all
cargo build
cargo run -p clash-rs -- -c config.yaml
cargo fmt
cargo clippy --all-targets --all-features
cargo test --all
```

运行单个 crate 或特定测试：

```bash
cargo test -p clash-lib
cargo test -p clash-lib put_configs_reloads_runtime_from_file
```

CI 风格测试：

```bash
CLASH_RS_CI=true cargo test --all --all-features
```

## 当前注意事项

- 项目仍在快速演进中，部分协议、平台能力和 API 行为还需要继续补齐。
- Rust edition 为 `2024`。
- 开发时建议先运行 `cargo check --all`，再根据改动范围运行 `cargo fmt`、`cargo clippy --all-targets --all-features` 和 `cargo test --all`。
- 修改配置、DNS、路由、代理或运行时生命周期时，优先补充聚焦测试，避免破坏热重载和控制接口行为。
- TUN、Reality、Hysteria2、WebSocket、TLS 等功能依赖 feature 和平台环境，排查问题时需要同时确认构建 feature、系统权限和网络环境。

## 后续方向

1. 整理 wiki
2. 继续补齐 Clash / Mihomo 配置兼容性，确保常见配置可以稳定解析和转换。
3. 强化代理协议实现，特别是 VLESS Reality、Trojan、Hysteria2、WebSocket、TLS 和 UDP 行为。
4. 完善 TUN、DNS hijack、Fake IP 和系统路由在 Windows、Linux、macOS 上的差异处理。
5. 增强 REST API 与 Clash / Mihomo 控制接口兼容性。
6. 扩展集成测试，覆盖配置加载、热重载、规则匹配、DNS、入站监听和出站拨号链路。

## 贡献

#### 有任何使用上的问题，或者代码实现上的问题，欢迎 Issue 以及 PR
#### 即使你是完全的计算机新手小白，在查阅完 [wiki](https://mfsga.github.io/Proxy_WIKI/) 后，再针对性的提问，我会抽出时间一一回复 
#### 本项目另一大目的也也是为了吸引更多的开发者参与其中。

## 如果觉得有帮助，欢迎点个 star 🧡
