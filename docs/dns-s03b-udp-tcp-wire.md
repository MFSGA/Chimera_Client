# 下一代 DNS S03b：严格 UDP/TCP 真实传输适配（未启用生产规则）

> 上一步：[S03a 严格出口预检](dns-s03-strict-egress-preflight.md)，配置/旧行为基线为 [S00](dns-legacy-golden.md) / [S01](dns-s01-policy-compiler.md) / [S02](dns-s02-query-planner.md)。用户的 v2.0 [实施规范](chimera-nextgen-dns-ai-guide.md) §17.4 仍是开发要求。

## 本次完成范围

新增 `DnsStrictWireTransport`（位于 `clash-lib/src/app/dns/execution.rs`），实现现有的 `DnsStrictTransport` 接口，接收 S03a 固定选择的 `AnyOutboundHandler` 和 `NameServer`，然后复用现有 `DnsClient` / `DnsRuntimeProvider` / Hickory UDP、TCP 协议栈。

- **DNS 出口固定**：必须由 S03a 的 `prepare_dns_execution` 选好 DIRECT 或具体 PROXY 叶节点；传输端使用该 handler，`rule_dispatch: None`，不再调用 Business Router，不调用可能在代理名缺失时自动回退 DIRECT 的 `SharedOutboundHandler`。没有新增对业务流量出口的修改。
- **仅支持 UDP/TCP、IP 字面量上游**：`DnsStrictTransport::validate_server` 在第一包发送前检查 profile 中**所有**服务器。存在尚未接通的 DoT/DoH、含域名的上游或服务器级 `#proxy/#interface` 等，就整体拒绝；绝不将原定加密 DNS 服务器失败当成允许改走明文 UDP 的理由。
- **引导解析防泄漏**：`outbound_resolver` 为只解析 IP 字面量的 `LiteralOnlyResolver`，且不提供可隐式解析上游域名的 `father`。若代理 handler 报告的服务器名不是 IP 字面量，直接拒绝；真实依赖图/代理节点域名引导要待 S04 专门设计。这里的保护是禁止默认系统 DNS **作为这个传输适配层的隐式 DNS fallback**，并未证明任何第三方 handler 的内部实现。
- **短生命周期连接**：每次 DNS 服务器尝试单独构造 `DnsClient`，不共享 legacy cache、不同 profile/egress 的 Hickory 连接；请求结束或内部 5 秒超时后调用 `reset_transport`，中止其后台任务，重置本次连接。清理阶段有 1 秒上界，严格执行器整体 10 秒上界。此处没有新增连接池复用。
- **DNS 报文**：沿用 Hickory 对 TCP wire 事务 ID 的检查，再将返回消息 ID 重写为上层请求 ID，保留 Question/RCODE/Answer/Authority 等内容，以满足 S03a 的请求一致性校验；原有 UDP TC → TCP 升级继续走**相同已固定的 outbound handler**。最终应答仍经 S03a 检查。
- **失败上限**：任何连接、DNS 解析或清理失败只能按 S03a 规则在**同一个显式 profile 且固定出口**内尝试其他服务器，不重新打开 legacy fallback、不切成 DIRECT。如果 profile 任一服务端不受 S03b 支持，则整组先拒绝。

## 离线但真实 socket 的验证

`clash-lib/src/app/dns/execution/tests.rs` 新增 S03b 测试：`127.0.0.1` 上真实 UDP socket / TCP listener 收发 DNS 报文，验证 DIRECT、指定代理 handler、UDP TC→TCP 升级、事务 ID 恢复、严格 bootstrap、拒绝未知 wire 协议及**混合 DoT+UDP 整组拨号前拒绝**。测试专用 `CountingWireProxy` 的 `connect_datagram` / `connect_stream` 会计数并**代理给本机 DIRECT Handler**，只证明实际网络调用确实经过固定的 outbound handler 接口，而**不是**真实 SOCKS5/VLESS/远端出口验证；没有进行真实外网 DNS 泄漏抓包。

验收命令：

```bash
cargo test -p clash-lib --lib --locked s03_
ci/verify-quality-gates.sh --quick
cargo test -p clash-lib --test dns_policy_s02_tests --locked
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
cargo test -p clash-lib --test dns_config_tests --locked
cargo check -p clash-lib --no-default-features --locked
```

## 尚未完成，禁止解除保护

- `clash-lib/src/app/dns/resolver/mod.rs` 仍**拒绝非空 `policy-rules` 启动**，本次没有将传输适配层接入生产 `EnhancedResolver` 或解除此保护。
- 没有实现 DoT/DoH 严格出口、SNI/证书验证、对非 IP DNS 端点的强制 bootstrap、动态代理链路真实 fail-closed 集成、网络接口选择和网络代际转移、Gateway namespace/ECS/cache/连接池实体隔离；这些分别属于 S03 后续及 S04。
- 实际代理节点可能有独立的 DNS/拨号实现；`LiteralOnlyResolver` 只能保证该接口提供的解析器不做系统递归查询。不能把 loopback 代理 wrapper 的计数解释为真实 SOCKS5/VLESS 网络无泄漏证明。
- 即使 UDP/TCP loopback 和旧配置回归通过，也不能宣称 `policy-rules` 在正式运行时可用；先完成严格网络出口集成与 S04 cache/bootstrap 隔离后再考虑撤销运行时拦截。
