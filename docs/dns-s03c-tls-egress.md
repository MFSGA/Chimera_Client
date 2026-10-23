# 下一代 DNS S03c：受限 DoT/DoH TLS 传输与安全 bootstrap 预检

> 依据：[下一代 DNS v2.0 开发指南](chimera-nextgen-dns-ai-guide.md) §17.4–§17.5；基于 [S03a](dns-s03-strict-egress-preflight.md)、[S03b](dns-s03b-udp-tcp-wire.md)。S03c 是继续开发的**独立传输模块**，并不表示正式 DNS 配置可以启用 `policy-rules`。

## 复用现有 TLS 协议栈，不允许绕过身份校验

- `app/dns/execution.rs` 增加 `DnsStrictPinnedWireTransport`，由调用者显式提供经独立可信途径取得的 `hostname → IpAddr` 固定映射。**当前 YAML 未新增 bootstrap 字段；正式运行时也没有接入该映射。**此结构先用于确认编译期/传输层边界，S04 仍需明确独立配置源、依赖图和轮换策略。
- 使用原 `DnsClient`、Hickory DoT/DoH 和 `DnsRuntimeProvider`。将配置中的原始 DNS 主机名交给 TLS/SNI/证书校验及 DoH Authority，解析出来的连接 IP 则固定为显式 pin；DoH path 和 query string 保持原样。
- 重要源码事实：旧 `dns_client.rs` 对**IP 主机名且连接 IP 相同**的 DoH 使用 `NoHostnameTlsVerifier` 兼容分支。严格加密 DNS **一律拒绝** IP 作为 TLS 主机名，不进入该分支；只能以 DNS 域名为 TLS 身份并使用 pin 绑定目标 IP。没有 pin 则启动前失败，不能调用系统 DNS 或 legacy bootstrap。
- 生产路径按现有 `rustls` 根证书信任存储校验 TLS 证书；没有提供 `insecure` / `skip-cert-verification` 开关，也没有为私有 CA 开放配置入口。单元测试可向一个独立的 `DnsClient` 注入临时根证书存储，以离线验证可信证书成功路径；这个测试钩子不进入非测试构建。
- 对一个严格 profile，`DnsStrictTransport::validate_profile` 先逐项检查服务器及整组协议类别：**不允许 DoT/DoH 与 UDP/TCP 明文混用**，即使加密服务器失败也不能借 profile 重试直接切成明文；纯 DoT/DoH 组合才可在原定 pinned outbound 内重试。
- S03b 的固定 outbound、只允许字面量代理节点 bootstrap、短生命周期 Hickory 连接、总超时和 `on-failure: fail` 仍然生效。对未设置 pin 的 UDP/TCP 路径保持 IP 字面量上游要求，不改变 S00 legacy 解析行为。

## 验证覆盖与实际证明边界

`clash-lib/src/app/dns/execution/tests.rs` 中 `s03c_` 离线用例验证：
- 不规范的 pin 名称、未设置 pin、IP 形式的 DoH TLS identity、明文/加密混用，均在第一次 outbound dial 之前拒绝。
- 本机生成**不受信任的自签名证书**并监听 TLS 端口，以真实 DoT/DoH 客户端握手验证错误证书不会被接受；使用 `CountingWireProxy` 确认已选择的 outbound 接口被调用，错误后不会改走 UDP/legacy fallback。
- `s03c_pinned_dot_accepts_trusted_certificate_and_returns_dns_answer` 将本机自签名证书仅加入测试专用根存储，使用 hostname pin 连接本机 DoT 服务并读取完整 DNS 应答；同时确认请求经过指定 outbound handler、响应 ID 保持正确，且没有 UDP 降级。
- `s03c_pinned_dot_rejects_trusted_certificate_for_wrong_hostname` 信任同一测试证书，但以不匹配的 TLS hostname 连接；验证证书链可信不能绕过主机身份校验，失败后也不会降级到 UDP。
- DoH URL 的 `/dns-query?custom=1` path 保持不变；连接目标 IP 从固定 bootstrap pin 获得，而非执行操作系统 DNS 查询。

**限制（必须保留）**：成功路径仅覆盖本机受信任证书下的 DoT，不覆盖 DoH 的成功 HTTP/2 应答；也不是远端 SOCKS5/VLESS/TUN 抓包测试。真实代理数据面、HTTP/2 Authority、真实出口 IP 防泄漏，以及 pin 更新/失效后的失败行为需要独立集成测试。尤其不能将本机计数 handler（内部仍代理给本机 DIRECT）当作真实代理网络已隔离的证明。

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

## 本轮增量记录：可信 DoT 成功路径

- 基线：本地 `master` 与 `origin/master` 均为 `0f498f6add689196b7623bd5cfe0131477c4d1fe`。本轮未迁移或修改 `ref/`、`ref-mihomo/`、`ref-meow/`。
- 新增只在 `cfg(test)` 下可用的根证书注入点；生产 TLS 根证书与原有 WebPKI 配置一致。离线回归使用本机生成并显式信任的证书，通过 hostname pin 完成 DoT 查询，检查 DNS 应答、事务 ID、固定 outbound 调用和无 UDP 降级。
- 已通过：`cargo fmt --all -- --check`、`git diff --check`、`cargo test -p clash-lib --lib --features aws-lc-rs s03`（25 passed）、`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --lib --tests --features aws-lc-rs -- -D warnings`。构建使用独立 target 目录；仓库默认 Cargo target 所在卷空间不足，未清理其缓存。
- 下一步仍是可信 DoH 成功应答与真实代理数据面验证，然后才评估 S04 生产 pin 来源/runtime 接线；本测试不解除 `policy-rules` 启动 gate。

## 下一阶段与未解除的门禁

S04 必须定义 profile/egress/namespace/ECS/网络代际的缓存及连接复用作用域、明确 hostname pin 的配置/解析/更新来源、可信 bootstrap 依赖图与运行时递归保护，以及真实代理组动态叶节点的隔离行为。随后补齐可信 DoH 成功应答、真实代理数据面和物理网络抓包验证。**当前 `resolver/mod.rs` 对非空 `policy-rules` 的启动拦截继续保留**，本轮没有任何生产 DNS 查询入口启用新规则，也没有改变 Business Rules 的顺序或出口。
