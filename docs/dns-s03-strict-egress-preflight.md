# 下一代 DNS S03a：严格出口预检与 Mock 传输边界

> 依据：[v2.0 指南](chimera-nextgen-dns-ai-guide.md) §17.4 和 [S02 计划器](dns-s02-query-planner.md)。本次只完成 S03 **第一步**，未启用生产 DNS `policy-rules`，未发起 DNS 网络连接或系统 TUN 操作。

## 已实现的边界

- `app/dns/execution.rs` 从 S02 `EffectiveDnsPlan` 和编译好的 profile 得到三种结果：原样交给 Legacy 的路径、Fake-IP/hosts `LocalAnswer`，以及严格的 `StrictDnsExecution`。
- 只有明确给出 `resolver`、`egress` 和 `on-failure: fail` 的规则，才允许组成可供 **后续 S03b 接线**的严格执行对象。部分继承的规则继续保留 S02 表示力，但目前明确拒绝准备执行，防止偷偷使用 legacy fallback。
- 显式 `proxy:<name>` 直接读取真实 outbound registry 并使用 `PinnedOutbound::capture` 固定动态组的当前叶节点。**不使用** `SharedOutboundHandler`：其缺少名字时会自动选择 DIRECT，与严格 DNS 出口要求冲突。未找到代理、组循环、组选中 DIRECT 或 REJECT 等，直接错误退出，不降级为 DIRECT。
- 显式 `direct` 单独创建 DIRECT Handler；这只能发生在用户明确选择 DIRECT 时。策略 DSL 中没有改动 Business Rules 顺序或出口。
- 严格查询的 `DnsStrictTransport` 接口一次只获得预检所绑定的 `NameServer`、固定的 handler 和 DNS 请求；同一个已声明的 resolver-profile 内可以继续尝试其他服务器，但不会调用 legacy fallback、普通 Business Router 或另一个出口。上游 DNS SERVFAIL/失败最终导致显式错误。严格执行层设置覆盖该 profile 全部重试的 10 秒总期限，并拒绝事务 ID、Question、消息类型不一致或仍携带 TC 截断位的应答；真实 UDP→TCP 升级须由 S03b transport 自行正确处理。
- 在构造器中再次检查编译 profile 是否仍存在、有效，以及强制 `#proxy`/`#interface` 与显式出口是否冲突，防止未来可变状态绕过 S01 加载期检查。

## 测试与验收边界

`clash-lib/src/app/dns/execution/tests.rs` 使用核心库真正的 `OutboundHandlerRegistry` 和 Mock `OutboundHandler` / Fake `DnsStrictTransport`，验证：真实 registry 查找、Proxy/DIRECT 选择、代理丢失而 registry 仍有 DIRECT 时失败关闭、选中 DIRECT/REJECT 假代理时拒绝、TCP/UDP profile 服务器顺序、同一个代理内失败重试、SERVFAIL、错误 DNS ID / Question / TC、部分配置拒绝、未命中规则原样保留旧路径，以及 Fake-IP 本地回答不出站。

建议命令：

```bash
cargo test -p clash-lib --lib --locked s03_
ci/verify-quality-gates.sh --quick
cargo test -p clash-lib --test dns_policy_s02_tests --locked
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
cargo check -p clash-lib --no-default-features --locked
```

**S03b 进度说明**：现已新增 [S03b UDP/TCP 严格传输适配](dns-s03b-udp-tcp-wire.md)，通过真实本机 UDP/TCP socket 与固定 handler 的离线测试。尚需实现严格 DoT/DoH、TLS SNI/证书、真实代理网络路径、网络代际与连接池隔离、动态代理组失效处理、代理 DNS 自举及递归深度限制。S04 才处理 profile / egress / ECS / namespace / generation 的缓存严格隔离。**未解除生产 `policy-rules` 的启动拦截。**

尤其注意：当前 `resolver/mod.rs` 对所有非空 `policy-rules` 的运行时启动**仍然拒绝**。完成 S03b/S04 必要隔离、真实 DNS 出口回归之前，绝不能放开这一保护。Mock 证明的是模块级调度意图，不是真实数据包已经通过代理。旧 DNS 配置未受影响。
