# 下一代 DNS S04a：严格解析缓存隔离与 bootstrap 依赖防护

> 基线：`0d513ec8042cc72afacf9e15ed26269ab8a5a6ad`（S03c 本地提交）。参考 [v2.0 DNS 开发指南](chimera-nextgen-dns-ai-guide.md) §17.5、[S02 计划器](dns-s02-query-planner.md)、[S03c TLS](dns-s03c-tls-egress.md)。
> **状态：S04 的第一项可独立验收切片 S04a，不代表完整 S04 已验收。** 正式 DNS `policy-rules` 启动保护未解除，原有 `EnhancedResolver` 的正缓存、RFC 2308 负缓存和 Fake-IP 映射未修改。

## 改动和边界

- `app/dns/isolation.rs` 新增 `StrictDnsCache`，只可经显式 `exchange_scoped` 调用；现有 `EnhancedResolver::exchange` 不访问此状态。默认不创建缓存、不改变 legacy 缓存行为。严格执行仍使用 S03 原有 `DnsClient` **每服务器尝试独立建连并主动清理**的连接策略，当前没有共享的严格连接池，也没有跨出口复用。
- 严格缓存键包含：规范化 QNAME、QCLASS、QTYPE、`DnsPurpose`、Host/Gateway namespace、查询标志、ECS 描述、resolver-profile、显式 DNS 出口、**固定代理叶节点的 Arc 实体身份**、有序 upstream 完整网络端点/协议/DoH path、transport 的 bootstrap pin 快照 fingerprint，以及网络/配置代际与 bootstrap revision。持有叶节点强引用避免仅凭地址/名称判断时的内存指针复用风险。相同 DNS 服务器经 DIRECT 与 PROXY 不共享状态；代理组切换后即使叶节点名称相同，只要是不同 handler 对象就会隔离。
- 缓存只接纳可逐项证明的普通 IN/A 或 IN/AAAA、无 EDNS/ECS/CD/DO/AD 的递归查询，且只支持对应 QTYPE 的简单正 RRset 或空 Answer 且 SOA 区域/class 正确的 NXDOMAIN/NODATA。**EDNS、ECS、DNSSEC、TSIG 签名请求/响应、非 IN/其他 QTYPE/复杂 CNAME、异常上游应答不缓存**。即使已有相同 Question 的普通缓存条目，TSIG 请求也必须绕过命中并重新查询；带 TSIG 的上游应答不得写入严格缓存。如果传输没有可验证的 bootstrap/config 快照身份，也不缓存。没有实现 serve-stale 或跨 QTYPE NXDOMAIN 复用。
- 正缓存 TTL 取所有答案 RR 的最小 TTL；负缓存 TTL 取 `min(SOA RR TTL, SOA.MINIMUM)`。命中时递减 TTL，并以本次 DNS transaction ID、Question 和请求元数据重写响应；超时后重新执行。可配置内部容量上限，本切片没有向 YAML 暴露缓存调参。
- `advance_epoch(network,config,bootstrap)` 原子清空旧分区。旧代际请求不得查询或存储新分区；当**在途请求**返回时发现 epoch 变动，直接返回错误并丢弃结果，防止旧网络响应覆盖新网络的真实结果。调用方必须在网络/配置/pin 变化时通知该缓存，之后才能使用新代际。
- `DnsStrictTransport::isolation_fingerprint` 由 S03b 普通严格传输提供固定 ID，由 S03c 显式 pin 传输提供**排序后的 hostname→IP 快照**。这只表明传输选项的身份，**不是实际 OS 出口 IP 检测**。身份未知则安全绕过缓存。
- `BootstrapGraph` 维护解析 Profile/Upstream/Proxy 的显式依赖 DAG，检查间接循环与最大深度；`BootstrapTrace` 是**每请求不可变链条**，阻止运行时递归或过深的依赖，不使用可能误伤其他并发请求的全局递归栈。这些工具目前没有从配置/动态 selector 自动生成图，也没有自动注入所有 DNS 调用路径。

## 证据和测试

```bash
cargo test -p clash-lib --lib --locked s04_
ci/verify-quality-gates.sh --quick
cargo check -p clash-lib --no-default-features --locked
cargo test -p clash-lib --test dns_policy_s02_tests --locked
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
cargo test -p clash-lib --test dns_config_tests --locked
```

新增离线测试验证：同域名不同出口/profile/代理叶节点/上游地址绝不串用；Host/Gateway tenant/purpose/网络代际分桶；transport pin 快照不同与 revision 更新不串用；无 transport fingerprint 不缓存；ECS/EDNS/DNSSEC 保守绕过；RFC 2308 SOA 负缓存保留 RCODE 并递减 SOA TTL；正缓存过期、容量约束；多层依赖 DAG 循环和深度上限；每请求 trace 并发互不干扰；网络切换时**在途旧应答不回传或污染缓存**。以上均为离线逻辑验证，没有用真实系统 DNS、真实 SOCKS5/VLESS 远端、Gateway 分设备抓包。

## S04b/S04c 待完成的严格准入

1. **真实执行接线与身份来源**：由可靠配置/网络变化信号驱动网络代际、配置代际、bootstrap revision，而不能假定 S02 context 默认值 `0` 代表稳定网络。缓存入口的各维度须由真实调用方提供，并监测动态代理叶节点变化；旧 legacy 路径继续完全独立。
2. **引导依赖图完整性**：构建代理组/动态 provider/代理节点自身域名和 DoT/DoH upstream 的真实依赖关系，验证先有稳定可信 bootstrap 再开始拨号，加入运行时强制深度 guard。当前仅显式 pin 传输和工具层拒绝，不接受未审查的隐式系统 DNS。
3. **严格连接/缓存作用域**：若未来为了性能引入连接池，须以与本缓存同样的实际代理叶节点、profile、source-scope、network/config/pin generation 进行独立池化和释放验证。本轮维持**不共享连接池**以保证安全。
4. **扩充 DNS 复杂应答和 ECS/DNSSEC**：在可以正确识别 EDNS 选项及作用域、CNAME、多 Question、CD/DO 与签名相关字段前继续保守不缓存；正负缓存策略不替代已有 legacy RFC 2308 语义。
5. **真实数据面**：可信证书下 DoT/DoH 成功路径、真实远端代理 fail-closed、DNS 出口实际抓包和网络切换/并发压测，依然是撤销 `policy-rules` 运行时 gate 的硬前置条件；独立审查与维护者批准也尚未完成。

**行为承诺**：本阶段没有更改 Business Rules 顺序、业务最终出口、旧 DNS fallback、Fake-IP 处理、旧缓存或默认加密 DNS 行为；不能把 S04a 内部隔离能力写成正式用户可用的下一代 DNS。
