# 下一代 DNS S03c：受限 DoT/DoH TLS 传输与安全 bootstrap 预检

> 依据：[下一代 DNS v2.0 开发指南](chimera-nextgen-dns-ai-guide.md) §17.4–§17.5；基于 [S03a](dns-s03-strict-egress-preflight.md)、[S03b](dns-s03b-udp-tcp-wire.md)。S03c 是继续开发的**独立传输模块**，并不表示正式 DNS 配置可以启用 `policy-rules`。

## 复用现有 TLS 协议栈，不允许绕过身份校验

- `app/dns/execution.rs` 增加 `DnsStrictPinnedWireTransport`，由调用者显式提供经独立可信途径取得的 `hostname → IpAddr` 固定映射。**当前 YAML 未新增 bootstrap 字段；正式运行时也没有接入该映射。**此结构先用于确认编译期/传输层边界，S04 仍需明确独立配置源、依赖图和轮换策略。
- 使用原 `DnsClient`、Hickory DoT/DoH 和 `DnsRuntimeProvider`。将配置中的原始 DNS 主机名交给 TLS/SNI/证书校验及 DoH Authority，解析出来的连接 IP 则固定为显式 pin；DoH path 和 query string 保持原样。
- 重要源码事实：旧 `dns_client.rs` 对**IP 主机名且连接 IP 相同**的 DoH 使用 `NoHostnameTlsVerifier` 兼容分支。严格加密 DNS **一律拒绝** IP 作为 TLS 主机名，不进入该分支；只能以 DNS 域名为 TLS 身份并使用 pin 绑定目标 IP。没有 pin 则启动前失败，不能调用系统 DNS 或 legacy bootstrap。
- 按现有 `rustls` 根证书信任存储校验 TLS 证书；没有提供 `insecure` / `skip-cert-verification` 开关，也没有在 S03c 为私有 CA 开放额外信任入口。
- 对一个严格 profile，`DnsStrictTransport::validate_profile` 先逐项检查服务器及整组协议类别：**不允许 DoT/DoH 与 UDP/TCP 明文混用**，即使加密服务器失败也不能借 profile 重试直接切成明文；纯 DoT/DoH 组合才可在原定 pinned outbound 内重试。
- S03b 的固定 outbound、只允许字面量代理节点 bootstrap、短生命周期 Hickory 连接、总超时和 `on-failure: fail` 仍然生效。对未设置 pin 的 UDP/TCP 路径保持 IP 字面量上游要求，不改变 S00 legacy 解析行为。

## 验证覆盖与实际证明边界

`clash-lib/src/app/dns/execution/tests.rs` 中 `s03c_` 离线用例验证：
- 不规范的 pin 名称、未设置 pin、IP 形式的 DoH TLS identity、明文/加密混用，均在第一次 outbound dial 之前拒绝。
- 本机生成**不受信任的自签名证书**并监听 TLS 端口，以真实 DoT/DoH 客户端握手验证错误证书不会被接受；使用 `CountingWireProxy` 确认已选择的 outbound 接口被调用，错误后不会改走 UDP/legacy fallback。
- DoH URL 的 `/dns-query?custom=1` path 保持不变；连接目标 IP 从固定 bootstrap pin 获得，而非执行操作系统 DNS 查询。

**限制（必须保留）**：上述测试证明了错误证书**失败关闭**和 TLS 连接走指定 handler；并未证明私有 CA/可信证书场景下能完成完整 DNS over TLS 或 HTTP/2 的成功应答，也不是远端 SOCKS5/VLESS/TUN 抓包测试。成功的可信 DoT/DoH 数据面、TLS SNI/HTTP2 Authority、真实出口 IP 防泄漏，以及 pin 更新/失效后的失败行为需要独立集成测试。尤其不能将本机计数 handler（内部仍代理给本机 DIRECT）当作真实代理网络已隔离的证明。

## 建议验收命令

```bash
cargo test -p clash-lib --lib --locked s03_
ci/verify-quality-gates.sh --quick
cargo test -p clash-lib --test dns_policy_s02_tests --locked
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
cargo test -p clash-lib --test dns_config_tests --locked
cargo check -p clash-lib --no-default-features --locked
```

## 下一阶段与未解除的门禁

S04 必须定义 profile/egress/namespace/ECS/网络代际的缓存及连接复用作用域、明确 hostname pin 的配置/解析/更新来源、可信 bootstrap 依赖图与运行时递归保护，以及真实代理组动态叶节点的隔离行为。随后补齐可信 DoT/DoH 的成功应答、SNI/证书路径及物理网络抓包验证。**当前 `resolver/mod.rs` 对非空 `policy-rules` 的启动拦截继续保留**，本轮没有任何生产 DNS 查询入口启用新规则，也没有改变 Business Rules 的顺序或出口。
