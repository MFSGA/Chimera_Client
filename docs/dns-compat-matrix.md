# DNS 兼容契约矩阵（S00 / 开发基线）

> 状态：**S00 实测/源码基线，不是 S01–S08 的功能承诺或弃用批准**。
> 指南：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md)，主要依据 §2、§3、§14、§17。
> 本地基线：`275ac992808acac4dd51783f5fc295c157218f8e`；指南公开基线：`71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`。远端 `origin/master` 当时为 `71ddfd6`。
> **A = Core/Keep、B = Legacy/Review、C = Skip/Reject** 是指南的*产品取舍建议*，与“当前实现状态”是两个不同的判断轴。除非有 Decision 及维护者批准，表中的建议**不构成删除旧字段的授权**。

## 1. 已有配置及行为

| 字段或机制 | 当前输入/真实行为（含边界） | 现状 | 建议 A/B/C | 会破坏现有使用吗？ / 迁移示例 | 实证/金标准 |
|---|---|---|---|---|---|
| `dns.enable` | `bool`；禁用则使用系统 DNS，启用需要至少一个可用 `nameserver` | implemented | A | 删除会破坏；保留 `enable: true` | `config/def.rs:398`、`dns/config.rs:367`；S00 `dns_disabled`、`invalid_values` |
| `dns.listen` | 既有 UDP/TCP/DoT/DoH/DoH3 对应配置入口；TLS listener 必须配置证书与密钥，不等于端到端互操作已测 | implemented/partial validation | A | 保留 `listen: {udp: '127.0.0.1:0'}` | `dns/config.rs`，`dns_config_tests.rs::encrypted_dns_listeners_require_certificate_pairs`；S00 `legacy_normal` |
| `dns.ipv6` | 需要顶层 `ipv6` 和 DNS 层 `ipv6` 同时启用；关闭时 DNS listener 对 AAAA 空答 | implemented | A | 保留现有两个开关 | `dns/config.rs:474`；S00 `ipv6_requires_global_and_dns_flags` |
| `dns.nameserver` | `Vec<String>`；支持 UDP/TCP/DoT/DoH/DHCP 入口（按编译特性），省略 scheme 时默认 UDP；`system` 被跳过，全部跳过时报错 | implemented | A | 不得默认改成新 profile；旧配置 `nameserver: [1.1.1.1]` 继续可用 | `dns/config.rs:81`；S00 `legacy_normal`、`invalid_values` |
| `dns.nameserver-policy` | `HashMap<String,String>`；domain trie 匹配、每个值**单个** DNS upstream，不能直接接受 Mihomo 数组 | implemented subset | A（子集） | 改成只接受数组会破坏；`example.com: 1.1.1.1` 必须继续可读 | `config/def.rs:419`、`dns/config.rs:214`、`resolver/enhanced.rs::match_policy`；S00 `nameserver_policy_single_string`、`old_nameserver_policy_does_not_accept_new_array_syntax` |
| `dns.default-nameserver` | `Vec<String>`；必须非空且解析为 IP literal，可用来 bootstrap 上游域名 | implemented | A | 旧 `default-nameserver: [223.5.5.5]` 保留 | `dns/config.rs:385–411`；`dns_config_tests.rs::default_nameserver_must_be_ip_address` |
| `dns.proxy-server-nameserver` | `Vec<String>`；非空时用于代理节点域名的特定解析；同名普通 DNS 不应越权替代 | implemented | A | 保留独立字段；`proxy-server-nameserver: [9.9.9.9]` | `dns/config.rs:414`、`resolver/enhanced.rs::ip_exchange`；S00 `proxy_and_direct_nameservers`；`proxy_server_nameserver_precedes_nameserver_policy_without_leaking` |
| `dns.direct-nameserver` | `Vec<String>`；非空时单独构造 direct resolver（有现存 fallback 语义） | implemented | A | 保留 `direct-nameserver: [192.0.2.53]` | `dns/config.rs:426`、`resolver/enhanced.rs::direct_resolver`；S00 `proxy_and_direct_nameservers`；`direct_resolver_prefers_direct_nameserver_without_fallback_query` |
| `dns.fallback` | `Vec<String>`；现有主/后备竞争、筛选及失败行为不是“所有错误必定回退”；已具备特定场景双失败诊断 | implemented | B（保留待评审） | 删除会破坏；保持 `fallback: [9.9.9.9]` | `dns/config.rs:374`、`resolver/enhanced.rs::ip_exchange`；S00 `fallback_filter_keeps_*`、`main_and_fallback_errors_are_both_reported` |
| `dns.fallback-filter` | 保留 `geoip`、`geoip-code`（规范化大写）、`ipcidr` 和 `domain`；依赖现有域名/IP 条件 | implemented | B（保留待评审） | 如迁移至 profile 需单独 Decision；旧 `fallback-filter: {geoip: true}` 继续 | `dns/config.rs:444–460`；S00 `fallback_filter_keeps_*`、`dns_config_tests.rs::invalid_fallback_cidr_is_rejected` |
| `dns.enhanced-mode: fake-ip` | IPv4 Fake-IP A 合成、PTR 反向映射、非 A 保守空答，已建立离线劫持测试 | implemented (IPv4) | A | 不改变默认合成规则；新增复杂记录能力必须 opt-in | `dns/server/handler.rs`、`dns/fakeip/`、`proxy/tun/`；S00 `fake_ip_filter_and_range_*`，已有 Fake-IP/TUN 回归 |
| `dns.fake-ip-range` | IPv4 CIDR，地址池错误（过小/耗尽）明确报错；映射当前没有安全 LRU 回收策略 | implemented (IPv4) | A | 保留 `fake-ip-range: 198.18.0.0/16`；不可随意复用活跃 IP | `dns/fakeip/mod.rs`；S00 `fake_ip_filter_and_range_*`、`invalid_fake_ip_ranges_fail_runtime_startup` |
| `dns.fake-ip-filter` | `Vec<String>`；匹配的域名不使用 Fake-IP，非 A 类型按现有策略转上游；其他非 A 仍保守空答 | implemented subset | A | `fake-ip-filter: ['*.lan']` 保留语义 | `dns/resolver/enhanced.rs::should_fake_ip`、`dns/server/handler.rs`；S00 `fake_ip_filter_and_range_*`、`fake_ip_filter_lets_excluded_domains_use_real_ipv4_dns` |
| `dns.fake-ip-range6` | 可解析 IPv6 子网；**没有证明实际 Fake-IPv6 分配/应答全链路可用** | partial | B（待评审） | 不得因 YAML 能读就宣称可用；暂保留旧输入形式 | `dns/config.rs:522`、`dns/resolver/enhanced.rs::resolve_v6`；`full_dns_fixture`、`fake_ip_range6_rejects_ipv4_prefix` |
| `dns.enhanced-mode: redir-host` | enum 可反序列化；**DNS 启用时明确以未实现拒绝** | unsupported at runtime | B（待评审） | 如弃用需决定 KEEP/REJECT，并给迁移：改用 `normal`（非语义等价）或 `fake-ip`（行为不同） | `config/def.rs:348`、`dns/config.rs:401`；S00 `legacy_invalid_values`、`enabled_redir_host_mode_is_rejected_as_unimplemented` |
| `dns.respect-rules` | `bool`；仅按现有 DNS dialer 与 Business Router 交互；未验证所有上游协议/代理池路径一致 | implemented, incomplete egress E2E | B | 保留 `respect-rules: true`，不替换为新 `egress` 默认 | `dns/runtime.rs::pick_outbound`、`dns/config.rs:551`；S00 `respect_rules_and_legacy_proxy_modifier_*` |
| DNS 地址修饰符 `#proxy`、`#interface` | 解析器接受修饰字段，`#RULES` 等值的运行时语义按现有 dialer 决定；未知 interface 可报错 | implemented subset | B | 新 `egress` 冲突须显式诊断；旧 `udp://1.1.1.1#proxy=PROXY` 必须保留 | `dns/config.rs::parse_outbound_proxy`、`parse_outbound_interface`；S00 `respect_rules_and_legacy_proxy_modifier_*` |
| `dns.edns-client-subnet` | IPv4/IPv6 CIDR 可解析，至少提供一个地址族；不默认添加 ECS | implemented parsing; wire not independently asserted here | B（需审计使用方） | 保留现有显式设置格式 | `dns/config.rs::parse_edns_client_subnet`、`dns_config_tests.rs::edns_client_subnet_requires_at_least_one_family` |
| `dns.use-hosts` | 显式开关（默认 true），DNS hosts 与 localhost 保留，非法地址直接报错 | implemented | A（S00 补充建议，待维护者确认） | 保留默认值；不擅自关掉 hosts | `config/def.rs`、`dns/config.rs:465`；`invalid_hosts_entry_is_rejected` |

## 2. 拟议新增字段/与 Mihomo 的取舍

| 字段/机制 | 当前实现事实 | 建议 A/B/C | 不兼容/迁移说明 | 证据/判定 |
|---|---|---|---|---|
| `dns.resolver-profiles` | **S01 已新增编译期输入与严格服务器列表校验**，但尚无实际查询执行；可选，不配置时旧行为不变 | implemented (parse/compile only)，执行尚未接线 | 后续 S02/S03 实现实际 resolver/egress；目前只声明 profile 不会改变 DNS 查询 | 指南 §6、§17；`config/def.rs`、`app/dns/policy.rs`、`dns_policy_s01_tests.rs` |
| `dns.policy-rules` | **S01 已实现 QNAME+QTYPE 有序编译/纯匹配及加载校验**；运行时对非空规则显式拒绝启动（执行器尚未实现），不能宣称 DNS 出口已生效 | implemented (parse/compile only)，runtime gated | S02/S03 完成 DNS query planning/egress 后再开放运行，不静默忽略 `on-failure: fail` | 指南 §6、§17；`app/dns/policy.rs`、`resolver/mod.rs`、`dns_policy_s01_tests.rs` |
| `fake-ip-filter-mode: rule/whitelist` | 未见实现（未在本轮测试 Mihomo 输入） | C（条件成立） | 不将 Mihomo 原字段偷偷映射成新行为；未来确需支持则另立决策 | 指南 §2.2、§2.4 |
| `proxy-server-nameserver-policy`、`direct-nameserver-follow-policy` | 未见声明/执行 | C（条件成立） | 老配置未支持时必须给未来明确错误/警告，而不是以为生效 | 指南 §2.2 |
| `cache-algorithm`、`prefer-h3`、`fallback-lazy-query` | 未见原生承诺；不能因此把现存缓存和 fallback 功能标为缺失 | C（条件成立） | 保留实际已有缓存；不要求照搬 Mihomo 的调参名称 | 指南 §2.2 |

**尚未审定的事实**：Mihomo 端具体字段和行为尚未在固定 `ref-mihomo` 对照运行；本矩阵的 Mihomo 语义仅引用上传的 v2.0 设计稿所列候选，**不是经 Mihomo 运行验证的兼容认证**。`#RULES`、跨 Host/Gateway、多网卡真实 DNS 出口、IPv6 Fake-IP 仍需要专门实验，不能以配置解析成功代替运行时验证。

## 3. 变更管理与 S01 准入

当前决定是 **保留已实现旧配置行为**，不存在本轮批准的 REMOVE/DEPRECATE。对每个未来不兼容行为使用指南 §2.3 的 `DNS-COMPAT-XXXX` 决策模板；没有具体旧行为、影响、迁移、回滚、测试和维护者批准，不允许落地。

S01 准入必须满足：金标准用例在目标 HEAD 实际运行；未知新配置不会被误称为可用；即使新规则生效，也严格保持业务规则顺序，不能将 `dns.egress` 当作业务流量出口。有关真实 DNS 出口与网络泄漏的完整证明在后续 S03/S04 隔离验证执行，S00 仅建立基线。
