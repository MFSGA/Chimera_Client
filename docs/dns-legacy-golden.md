# Chimera DNS 旧行为金标准与 S00 验收索引

> 本页是 **S00 的版本化测试入口和观测契约**，不是下一代 DNS 规则已经实现的声明。
> 指南：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md) §14、§15、§17、§19。产品字段取舍见 [`dns-compat-matrix.md`](dns-compat-matrix.md)。

## 1. 固定基线

| 项目 | 精确值及说明 |
|---|---|
| 指南原参考 commit | `71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`（公开仓库基线，非当前实现） |
| S00 开工 HEAD | `275ac992808acac4dd51783f5fc295c157218f8e`（本地 `master`） |
| 本地较指南新增 | `eff9164ed57615330b4bb69f212413876ddb656a`（缓存完整性/并发否定应答）；`275ac992808acac4dd51783f5fc295c157218f8e`（RFC 2308 负缓存及 policy 防泄漏） |
| 原参考 | `ref/` `39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`；Mihomo 参考 `ref-mihomo/` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`（本地快照，未宣称最新） |
| 本次测试改动范围 | 新增 `clash-lib/tests/dns_legacy_golden_tests.rs`；补充 `clash-lib/src/app/dns/server/handler.rs` 的 SRV 旧行为测试；没有修改生产 DNS 行为 |
| 用户本地工作区 | 既存 VLESS `datagram.rs` 未提交差异须保留；其他未跟踪文件与 submodule 均不属于 S00 |

**行为版本差异**：指南依据的 `71ddfd6` 之后，`eff9164` 对缓存完整性、EDNS/不安全缓存、上游否定响应竞争做了修复；`275ac99` 增加带 SOA 的 RFC 2308 NXDOMAIN/NODATA 缓存、网络重置失效、正答覆盖负缓存及策略隔离测试。S01 不得基于旧版“所有 NXDOMAIN 不缓存”的假设重复实现。完整证据见 `docs/dns-error-diagnostics.md`。

## 2. 旧配置 Golden — 独立集成测试

执行：`cargo test -p clash-lib --test dns_legacy_golden_tests --locked`。

| 用例（全部前缀 `s00_`） | 固定的可观察行为 |
|---|---|
| `dns_disabled_remains_disabled_without_upstream` | 没有 DNS 上游且 DNS 禁用的状态仍被接受，不擅自启用 resolver |
| `legacy_normal_nameserver_order_protocol_port_and_listeners` | UDP/TCP server 顺序、端口与 listener 解析保持一致 |
| `ipv6_requires_global_and_dns_flags` | 全局与 DNS 层 IPv6 必须同时允许（只是旧兼容性事实，不代表 Fake IPv6 功能已完整） |
| `fake_ip_filter_and_range_remain_legacy_values` | Fake-IP 模式/IPv4 CIDR/filter 原样传递 |
| `nameserver_policy_single_string_keeps_original_server` | 旧 string 值仍解析为单一指定 DNS server，保留 host/协议/端口 |
| `fallback_filter_keeps_geoip_cidr_and_domain_values` | fallback、GeoIP country code 规范化、IP CIDR 与 domain filter |
| `proxy_and_direct_nameservers_remain_distinct` | 特定代理节点 DNS 与 direct DNS 不被默认 nameserver 合并 |
| `respect_rules_and_legacy_proxy_modifier_are_preserved` | `respect-rules` 与地址级 `#proxy=...` 解析不丢失 |
| `legacy_invalid_values_remain_explicit_errors` | 缺 nameserver、只给 system、启用 redir-host、默认 DNS 域名等必须明确报错 |
| `old_nameserver_policy_does_not_accept_new_array_syntax` | 旧字段的值目前是 string，不能把新拟议数组当作已实现 |
| `business_rule_order_and_no_resolve_options_are_preserved` | GEOIP、DOMAIN-SUFFIX、MATCH 原顺序和 `no-resolve` 不经 DNS 变更被重排 |

## 3. 旧数据面 / DNS wire Golden — 现有测试索引

仅列源码/测试实际已包含的入口；**“已有用例”不等于 S00 本轮已运行所有组合**。

| 旧行为/观测指标 | 源码中现成的测试 / 新增保护 |
|---|---|
| Fake-IP A 不查真实 DNS；SRV 隔离与过滤放行 | `app/dns/server/handler.rs::a_query_returns_fake_ip_without_forwarding_to_upstream`、`s00_legacy_srv_is_preserved_only_for_fake_ip_excluded_domains`、`filtered_domain_non_address_queries_reach_upstream` |
| SRV 的 Target / Priority / Weight / Port 不被旧链路改写 | `s00_legacy_srv_is_preserved_only_for_fake_ip_excluded_domains`，固定原始 RDATA 与 TTL（离线 Mock） |
| Fake-IP IPv4 PTR 反查 | `app/dns/server/handler.rs::allocated_fake_ipv4_ptr_returns_local_hostname_without_upstream` |
| 非 A 记录防泄漏与多 Question | `non_a_queries_are_not_forwarded_for_fake_ip_domains`、`shared_dns_entry_rejects_multiple_questions_without_resolver_access` |
| Fake-IP 实际 TUN UDP/TCP DNS 报文封装 | `proxy/tun/datagram.rs::ipv4_tun_udp_*`、`proxy/tun/stream.rs::ipv4_tun_tcp_*`（netstack/offline，无系统设备） |
| Policy 指定上游优先、故障不越权 fallback | `resolver/enhanced.rs::policy_negative_cache_does_not_leak_to_main_or_fallback`、`policy_upstream_failure_fails_closed_without_public_fallback` |
| Proxy server DNS 优先于 policy/main | `proxy_server_nameserver_precedes_nameserver_policy_without_leaking`、`test_proxy_server_domain_resolved_via_proxy_nameserver` |
| DIRECT DNS 与旧 fallback 语义 | `direct_resolver_prefers_direct_nameserver_without_fallback_query`、`direct_resolver_falls_back_when_direct_nameserver_has_no_ip` |
| DNS 上游全失效、SERVFAIL、主+fallback 双失败 | `all_failed_upstreams_preserve_each_upstream_reason`、`main_and_fallback_errors_are_both_reported`、`all_servfail_upstreams_are_reported_as_failures` |
| NXDOMAIN/NODATA 与正答竞争 | `fast_nxdomain_must_not_mask_later_positive_address`、`fast_nodata_must_not_mask_later_positive_address` |
| 正/负缓存 RCODE、Authority、TTL 与失效 | `cached_response_preserves_authority_additional_and_metadata`、`soa_based_nxdomain_is_cached_with_code_and_transaction_id`、`soa_based_nodata_is_cached_per_question_type`、`expired_negative_cache_does_not_hide_upstream_failure` |
| respect-rules 出站无法获取 router 时失败关闭 | `app/dns/runtime.rs::respect_rules_fails_closed_before_router_is_ready` |
| 业务 `no-resolve` 配置合法性及顺序 | `config/internal/rule.rs::no_resolve_preserves_valid_rules_and_explicit_interface`、`no_resolve_is_only_valid_for_ip_and_geo_rules`，新 `s00_business_rule_order_and_no_resolve_options_are_preserved` |

采用以上断言而不是原样快照日志字符串：每项固定 RCODE、RecordType、SOA TTL、地址/端口、上游调用次数/ID、失败与回退；只有实际影响语义的内容进入 Golden。

## 4. 旧路径与下一代规则的 A/B 验证合同

S00 **没有**实现新路径，也不能凭单测声称已有可执行的“legacy / nextgen”双实现。为 S01/S02 固定对照流程：

1. 输入固定 YAML + 查询 fixture，取当前 legacy 的解析配置结果或模拟 upstream 的 DNS Message。
2. 不配置任何新增字段时必须调用当前 `exchange_with_resolver` / `EnhancedResolver` 路径；未来 shadow 计划不能改变拨号或 DNS 输出。
3. 记录 `(QNAME,QTYPE,QCLASS)`、客户端 Fake-IP/真实答复、RCODE、TTL、受查询的 upstream ID、fallback 调用次数、业务规则 ordinal/最终出口。
4. S01 的规则编译单元测试不允许实际拨号；S02 的计划器必须在“无新增规则”和“不命中新规则”条件下与第 2 步一致。
5. 新增规则改变 DNS upstream 但不能自动改变 Business Router 原始顺序、GEOIP/no-resolve 语义及最终 DIRECT/PROXY。

## 5. S00 尚需在后续阶段完成的风险验证

- 本轮配置 Golden 锁定*解析产物*而不是系统 DNS 出口；实际代理 DNS 的每个 wire 协议、路由接口绑定、真实 OS TUN/网关多租户泄漏尚无强保证。
- `respect-rules` 已有 router 未就绪时 fail-closed 用例；动态代理组叶节点、多个网络代际切换后的真实连接池隔离属于 S03/S04。
- IPv6 Fake-IP 的配置输入虽然存在，真实假 IPv6 数据面尚不满足“已验证”，不纳入本轮功能实现。
- 官方 Mihomo 的实际行为尚未在固定 `ref-mihomo` 执行互操作对照；只以指南中的 A/B/C 建议作为待确认取舍。
- 文档中的 T01–T28 为整个下一代 DNS 的最终验收矩阵，**S00 不是声称 28 项全部通过**；S00 主要为 T01、T05、T07/T08、T10/T11 建立既有行为证据。其余应在相应后续切片逐项验收。
- 尚未实现 `dns.resolver-profiles`、`dns.policy-rules`；旧对象对未知字段可能静默忽略，这是 S01 的严格新对象解析必须消除的风险，不能在文档里写成已支持。
- S01/S02 对 RuleEngine 规则顺序的保证目前是**配置/解析级 Golden**，不是端到端路由选择的新的实际网络执行测试。

## S06a：可选安全 SRV 转发

`dns.service-discovery-mode: safe` 是新加的 opt-in 设置，仅改变 Fake-IP 范围内的 SRV 查询：保留上游返回的 SRV answer（包括 target、priority、weight 和 port），移除 Additional section 中的 A/AAAA 地址。请求要求 DNSSEC、携带签名，或响应带认证/签名标志且需要移除地址时返回 SERVFAIL，避免修改已签名数据。HTTPS/SVCB 等其他非 A/AAAA 查询继续沿用原有过滤行为。

默认值 `legacy` 保留 S00 行为：Fake-IP 范围内的非 A/AAAA 查询返回空答复，Fake-IP filter 排除的域名仍走原上游路径。`safe` 模式对标准 SRV QNAME `_service._protocol.domain` 使用 `domain` 匹配 Fake-IP filter，使 `*.lan` 这类规则能正确应用于服务发现；`legacy` 仍按完整 QNAME 匹配，以保留旧行为。此切片只处理 SRV response 的附加地址泄漏；它不启用 `policy-rules`，也不做 SRV/GeoDNS 自动选择。回归用例位于 `app/dns/server/handler.rs` 与 `tests/dns_config_tests.rs`。

本轮验证记录（2026-10-23）：

| 命令 | 结果 |
|---|---|
| `cargo fmt --all -- --check`、`git diff --check` | 通过 |
| `CARGO_TARGET_DIR=/tmp/chimera-dns-review-target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test -p clash-lib --lib --no-default-features --locked --offline app::dns::server::handler::tests` | 25 passed |
| `CARGO_TARGET_DIR=/tmp/chimera-dns-review-target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test -p clash-lib --no-default-features --features ring,port --test dns_config_tests --locked --offline` | 17 passed |
| `CARGO_TARGET_DIR=/tmp/chimera-dns-review-target CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test -p clash-lib --no-default-features --features ring,port --test dns_legacy_golden_tests --locked --offline` | 11 passed |

默认 feature 的 handler 单测重跑在 `rustc` 连续数分钟无 CPU 活动、占用约 3.4 GB 后中断；no-default 首次尝试使用共享 `target` 时遇到旧 `displaydoc` 元数据与 Rust 1.99 不兼容及卷空间耗尽，未清理共享构建缓存。改用 `/tmp` 临时 target 后，handler 定向测试通过。`dns_config_tests` 不带 TLS provider 的 no-default 组合有 4 项依赖加密 provider 的既有测试失败；改用 `ring,port` 后 17 项通过。

DNSSEC 回归用例覆盖 DO/CD/AD 与 TSIG 请求，以及 AD、RRSIG 和 TSIG 响应在需要清理附加地址时返回 SERVFAIL。若上游签名响应没有需要清理的 A/AAAA 附加地址，则保持响应不变透传。通用 DNS 错误应答目前没有 TSIG 密钥，因此需要清理时返回的 SERVFAIL 不带 TSIG；TSIG 客户端可能无法认证该错误答复，但带地址的签名响应仍会被阻止。配置兼容测试确认 YAML 缺省为 `legacy`、显式 `safe` 可解析。外部 Rust 调用方若直接构造公开 `app::dns::Config` 结构体，需要为新增字段补值；YAML 用户配置保持兼容。该增量不表示下一代 DNS 已完成：`dns.policy-rules` 仍未接入生产执行路径，S01–S06 的剩余验收项保持待办。

S00 原则：不改变任何 DNS 运行时决策，不删除/重命名旧字段；保护用户未提交文件。提交、审查和 CI 状态必须根据实际执行结果记录，而不是预先标成 pass。
