# Mihomo 订阅配置字段兼容性记录（仅结构摘要）

> 记录日期：2026-10-13。以当时提供的 Mihomo 订阅的 **YAML 字段名、数据类型和安全的枚举值** 进行只读分析。
> **不保存**订阅 URL/token、原始 YAML、代理名称、服务器、UUID、密钥、密码、Host/SNI、规则目标或其他隐私内容。
> 本文是字段兼容性台账，**不代表**真实代理服务器握手成功，更不代表未实现功能已完成。

## 结构基线

- 14 个代理：VLESS 10、Hysteria2 2、Trojan 2。
- 6 个组：select 3、url-test 1、fallback 2；组引用/代理名称结构检查未发现缺失目标或同名冲突。
- 538 条规则：DOMAIN 18、DOMAIN-KEYWORD 40、DOMAIN-SUFFIX 444、GEOIP 1、IP-CIDR 30、IP-CIDR6 4、MATCH 1。
- 顶层字段：`allow-lan`、`bind-address`、`dns`、`external-controller`、`log-level`、`mixed-port`、`mode`、`proxies`、`proxy-groups`、`rules`。均有对应结构/解析路径；路由、DNS、健康检查和出口连接仍需实际验收。

## 本批兼容性改动

| 字段及分布 | 当前行为 | 后续工作 |
| --- | --- | --- |
| `vless.client-fingerprint: chrome`（10 个） | Reality 端点维持既有 Chrome 握手支持；**非 Reality TLS** 现仅接收此 Mihomo 字段并明确警告，使用普通 TLS，**不伪装 Chrome**。其他未实现值仍拒绝，Reality `none` 仍拒绝以防降级。 | 为标准 TLS 与各传输实现真实且可测的 ClientHello 指纹；验证证书检查和 ALPN 行为。 |
| `trojan.client-fingerprint: chrome`（2 个）及 `hysteria2.client-fingerprint: chrome`（2 个） | 作为结构化兼容字段接收，给出未实现警告；**不修改 TLS 证书校验、QUIC/TLS 或加密行为**。 | 分别实现/验证 ClientHello 指纹能力，评估 QUIC 兼容性。 |
| `vless.packet-encoding: xudp`（10 个） | 接收 `xudp`，**TCP 保留、UDP 禁用**；不能把原生 UDP 错当成 XUDP。`none` / 空值保持既有逻辑；其它未知编码继续报配置错误。 | 实现 XUDP wire 编解码、端到端 UDP 数据和错误路径测试，再启用 UDP。 |
| `vless.smux.enabled: false`（3 个） | 结构化解析；false 没有实际副作用，true 目前仅警告，不启用多路复用。 | 实现和验证 SMUX（并发、流控、重连与取消）。 |
| `xhttp-opts`（5 个） | 已有 `stream-one` / `stream-up`、基础下载端点和 `reuse-settings` 的配置/运行时路径；一个下载端点显式配置 Reality。**未对本订阅做真实互操作**。 | 覆盖实际 Xray/Mihomo H2/H3、download-settings、复用和安全切换。 |
| `trojan.network: ws`（2 个） | 配置和运行时已有 WebSocket 分支；取决于是否编译 `ws` feature。 | 真实 WebSocket 互操作。 |
| `dns`、`rules`、`proxy-groups` | 字段/规则类型均有相应解析代码；`dns.respect-rules`、`fake-ip`、fallback 和 `proxy-server-nameserver` 有代码路径。**结构能被识别不等于环境依赖和所有规则已验收**。 | 完整配置加载、DNS 启动、GEOIP 数据库及路由行为集成测试。 |

## 保持安全边界

1. 所有 `client-fingerprint` 的无实现兼容都必须**有明确警告**；不得把 Chrome 伪装误报为完成。标准 TLS 仍使用原有证书验证策略；订阅中若显式含 `skip-cert-verify: true`，行为与安全风险原样保留，由用户审查。
2. XUDP 没有真实封包实现时禁止发送普通 VLESS UDP 来假装支持：**禁用受影响节点的 UDP**，避免静默错误；TCP 与其他节点仍可正常配置。
3. `smux`、Trojan/Hysteria2 指纹和 XUDP 均为“兼容接收/待实现”，不是“协议已支持”。
4. 缺少 `hysteria`、`trojan`、`ws`、`reality` 等编译 feature，或下载端点/路由格式本身无效时，核心仍可能拒绝配置；**不允许**靠降级加密、无凭据代理或静默替换节点绕过。
5. 使用虚构节点/测试密钥编写回归用例，不引入真实订阅内容。后续验收需分别测试纯解析、代理创建、网络连通、UDP、跨平台与安全错误分支。

## 相关源码与验证

- 结构：`clash-lib/src/config/internal/proxy.rs`
- 转换：`clash-lib/src/proxy/converters/{vless,trojan,hysteria2}.rs`
- DNS / 规则 / 组：`clash-lib/src/{config/def.rs,app/dns,config/internal/convert}`
- 定向测试：`cargo test -p clash-lib --lib --locked proxy::converters::vless::tests`，及有相应 feature 的 Trojan / Hysteria2 测试。
- ✅ macOS 本地：`cargo fmt --all`、`git diff --check`。
- ✅ `cargo test -p clash-lib --lib --locked proxy::converters::vless::tests -- --test-threads=1`：**92 passed、0 failed**。
- ⚠️ `cargo test -p clash-lib --lib --features 'trojan hysteria ws' --locked proxy::converters:: -- --test-threads=1`：源码已完成编译，但在链接测试二进制时磁盘空间不足（`No space left on device`），**未执行测试，不能视为通过**；未删除用户已有编译缓存。
- ⚠️ 尚未运行原订阅真实端到端握手、Windows/Linux 运行、XUDP/SMUX 实现互操作；这些验证必须明确记作 `not run`，不得写成成功。

## 2026-10-16：VLESS 出站构建与 XUDP 加密组合回归

- **无效 UUID 提前拒绝**：VLESS handler 的 `TryFrom<OutboundVless>` 现在在 outbound 构建阶段验证 UUID，而不是等待第一次建立 TCP/UDP 连接时才由 `VlessStream::new` 报错。错误提示不会回显原始 UUID；仅 YAML 结构解析成功不代表出站能够正常构建。
- **XUDP 不降级**：覆盖 `packet-encoding: xudp`、`smux.enabled: false`、`encryption: mlkem768x25519plus.random.1rtt...` 的虚构配置。handler 可用于 TCP，但 `support_udp()` 仍为 `false`，不会把 XUDP 错当作已支持的原生加密 UDP。
- **验证**：修复前 `vless_rejects_malformed_uuid_before_outbound_runtime` 失败、修复后通过；默认 feature 的 VLESS 转换器测试 **95 passed**；`--no-default-features` 下 UUID 拒绝测试 **1 passed**；`cargo clippy -p clash-lib --lib --locked --offline -- -D warnings` 通过。
- **相关 CI 修复**：此前主线提交 `43679c3` 的 Rust quality CI 因 `encryption_stream.rs` 中 2 个 `collapsible_if` 和 3 个 `chunks_exact_to_as_chunks` 告警失败（Windows Network Regression 已成功）。修复这些告警后，复用了已有 Dashboard 构建产物运行的本地 `cargo clippy -p clash-lib --all-targets --all-features --locked --offline -- -D warnings` 通过；本地**未重新构建 Dashboard**，新提交的远端 CI 仍需单独验收。
- **限制**：没有测试真实节点、XUDP wire 协议、真实订阅，亦未验证完整 Mihomo 订阅在所有平台的运行行为；这些仍需后续独立验收。以上测试只使用虚构 UUID、地址和密钥材料。

## 2026-10-16：XHTTP XMUX 显式零值兼容性

- 使用真实 Mihomo 订阅的**字段取值组合**进行只读分析；未将订阅、节点名称或凭据加入仓库、文档或测试。该订阅有一个 XHTTP 代理同时设置了 `reuse-settings.max-concurrency: "1"` 和 `max-connections: "0"`。
- 旧版 Chimera 在 `ReusePolicy::validate()` 中以两个字段是否都存在为冲突依据；真实启动时因此拒绝该出站，导致代理组引用解析失败。`clash-rs -t` 的基础配置检查未覆盖出站构造，故先前报告通过。
- Xray 上游 `infra/conf/transport_method.go` 的规则按两者范围上界都**大于零**才报冲突；零值不构成正限制。参见 https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_method.go 。Mihomo 文档也描述了两个限制的互斥关系（具体的零值判定以 Xray 源码为依据）：https://wiki.metacubex.one/en/config/proxies/transport/ 。
- 本地修复与测试：只在两个范围上界都为正时拒绝；当正 `max-concurrency` 搭配 `max-connections: "0"` 时，连接池按并发限制复用，避免把零值错误解释成“永不复用”。仍拒绝 `max-concurrency: "1"` + `max-connections: "0-4"`；保留单独 `max-connections: "0"` 的既有行为。
- 本修复只涉及配置有效性及连接池选择语义，不代表节点握手、真实流量或完整订阅运行通过。测试使用虚构数值，不包含真实订阅的任何敏感内容。
