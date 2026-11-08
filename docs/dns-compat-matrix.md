# DNS 兼容契约矩阵（S00 / 开发基线）

> 状态：**S00 实测/源码基线，不是 S01–S08 的功能承诺或弃用批准**。
> 指南：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md)，主要依据 §2、§3、§14、§17。
> 本地基线：`275ac992808acac4dd51783f5fc295c157218f8e`；指南公开基线：`71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`。远端 `origin/master` 当时为 `71ddfd6`。
> **A = Core/Keep、B = Legacy/Review、C = Skip/Reject** 是指南的*产品取舍建议*，与“当前实现状态”是两个不同的判断轴。除非有 Decision 及维护者批准，表中的建议**不构成删除旧字段的授权**。

## 2026-11-07 运行时隔离补充（P0）

- 固定 Mihomo 只读参考：`ref-mihomo` gitlink / 工作树 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；`config/config.go::parseDNS` 中解析独立 `proxy-server-nameserver`，并在配置 `proxy-server-nameserver-policy` 时要求其非空。这里的运行时零客户端失效关闭是 Chimera 的隐私安全强化，**不是已证明 Mihomo 具有相同错误路径**。
- Chimera 基线 `e42dabe74282c77245da1023de0b828830928216`：`resolver/enhanced.rs::new_with_network_path_source` 对已配置但运行时零客户端的 `proxy-server-nameserver` 发出警告并回退默认 DNS；即使解析层通常会拒绝全跳过配置，内部配置和运行时构造仍可能出现此状态。
- 先写否定测试 `configured_proxy_nameserver_with_no_runtime_clients_fails_closed`，修复前实测 0 passed / 1 failed；修复后该状态直接返回 `InvalidConfig`，不会构造回退到默认 DNS 的代理节点解析器。测试不触碰系统 DNS、路由或 TUN；仍需故障注入验证实际已构造客户端超时、provider 更新和物理 NIC/utun 抓包。

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

## 2026-11-08 — 代理节点专用 DNS 失败隔离回归（本地候选，L2 审查待办）

- 最新隔离整合分支 `codex/dns-master-integration-20261108-v3` 基于 `origin/master` `840c5a2b8f6a6be3e783dea026cc1bf3b5143f2f`，单独移植空客户端失效关闭修复及 A/AAAA 故障注入测试；不包含远端已经撤回的合并历史。原工作树、用户未提交更改不变。固定 Mihomo 参考为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，仅只读核查配置/解析器；尚无二进制互操作对照。
- `proxy_bootstrap_failure_never_queries_policy_main_or_fallback` 对 A 和 AAAA 注入专用 DNS 错误，断言专用上游共调用两次，policy/main/fallback 均未收到查询，两种请求均返回错误。此为内存客户端隔离断言，不证明物理 NIC 或 utun 上没有 DNS 泄漏。
- 定向 `configured_proxy_nameserver_with_no_runtime_clients_fails_closed` 不仅要求失败，还断言返回明确的 `InvalidConfig` 和静态诊断消息，避免将其他初始化错误误认为成功执行了隐私失效关闭。A/AAAA 故障测试分别在专用上游模拟失败，拒绝 policy/main/fallback 降级。TUN+Ring（无默认 feature）核心回归、DNS 配置及 S01/S02 策略测试用于验证未破坏旧配置；macOS DNS ownership、DNS Proxy 激活、抓包及 L2 独立审查仍未完成。
- `origin/master` 在 2026-11-08 先从 `a96c21d` 回到 `54b95ff`，又因提交重签从 `54b95ff` 变为 `840c5a2`；后两个基线 Git tree 相同但 Git 祖先不同。当前本地 `master` 仍有未提交修改，整合内容先保留于隔离候选分支。不得把测试成功或本地签名当成独立 L2 审查、GitHub Verified、required CI 或系统级隐私验收。

## 2026-11-08 — nameserver-policy 复合选择器失效关闭（新增候选，L2 审查待办）

- 固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy` 将逗号分隔域名、`geosite:` 和 `rule-set:` 视为有运行含义的策略选择器。Chimera 的 `parse_nameserver_policy` 原来只调用宽松的域名分割器，导致这些键及带空白的复合选择器被当作无法匹配的单个 trie 字面键，配置成功但没有预期 DNS 策略。
- 先新增 `nameserver_policy_rejects_unimplemented_compound_selectors` 否定测试，修复前因 `example.com other.test` 被错误接受而失败；再在 `clash-lib/src/app/dns/config.rs` 的转换层显式拒绝空白、逗号复合、`geosite:` 和 `rule-set:` 键。诊断不包含域名/上游地址；普通域名及现有 `*.`/`+.` 通配符继续成功。该切片是失效关闭，并**未实现** Mihomo 的高级规则执行语义。
- `clash-lib/tests/dns_config_tests.rs::nameserver_policy_compound_selectors_fail_closed_at_yaml_conversion` 对启用和禁用 DNS 的 YAML 都验证上述四类输入被拒绝，避免仅通过底层解析单测冒充 YAML 转换兼容。尚未执行 Mihomo 二进制差异运行、macOS 系统 resolver 或物理 NIC/utun 抓包。

## 2026-11-08 06:00 PST — fake-ip-ttl 未实现字段拒绝（独立本地 P0 候选）

- 只读参考固定 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：`config/config.go:240` 明确接受 `dns.fake-ip-ttl`；默认值 `1` 见第 513 行，配置值被赋给运行时 DNS 配置的 `FakeIPTTL`（第 1539 行）。Chimera 当前没有相应的 TTL 运行时字段或行为，故不能以 Serde 成功解析代替语义兼容。
- 在 `clash-lib/tests/dns_config_tests.rs` 先新增负例：`fake-ip-ttl` 与下划线误拼 `fake_ip_ttl`，分别在 `dns.enable=true/false` 时必须拒绝；还验证错误不泄露配置值、旧版 `fake-ip-range` 仍被接受。修复前定向测试 **0/1**，配置被静默接受；修复后 **1/1**。
- `clash-lib/src/config/def.rs` 在 YAML merge 后、Serde 反序列化前明确拒绝这两个键。该改动是安全 fail-closed 保护，**不声称实现 Mihomo 的 TTL 语义**，也不影响未显式设置 TTL 的旧配置。
- macOS 上 `--no-default-features --features tun,ring`：Cargo fmt、严格 Clippy（all-targets）、lib 832/832（另 11 ignored）、DNS config 20/20、S01 17/17、S02 14/14 全通过；默认 features 严格 Clippy 也通过。DNS listener 端口冲突日志为预期负例。未做真实 DNS/TUN/NIC 抓包、Mihomo 二进制对照或系统设置修改。
- 独立 L2 Reviewer/维护者批准仍缺失；本地候选不得自动并入 PR #107 或 master。下一切片应核对固定 Mihomo `proxy-server-nameserver-policy` 解析和运行时隔离，并做失效关闭故障注入。

## 2026-11-08 — 未实现的 Mihomo DNS 隐私字段严格拒绝（本地 P0 候选，L2 待审）

- 固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go` 定义 `fake-ip-filter-mode`、`proxy-server-nameserver-policy`、`direct-nameserver-follow-policy`、`use-system-hosts` 和 `fallback-lazy-query`，分别控制 Fake-IP 过滤、代理节点 DNS 策略、direct 查询策略、系统 hosts 使用及 fallback 查询时机。Chimera 仍没有相同运行语义，因此不将 YAML 反序列化成功视为兼容。
- `clash-lib/src/config/def.rs` 在 YAML merge 完成后、Serde 忽略未知字段前，拒绝这五个完整字段及相应下划线误拼；错误仅包含字段名，不回显配置值。无关 vendor 扩展与既有 DNS 配置继续可解析。其他隐私相关未知字段、仅部分近似拼写和平台特有限制仍待逐项审计。
- 新增 `clash-lib/tests/dns_config_tests.rs::unimplemented_mihomo_dns_privacy_controls_must_fail_closed`：启用/禁用 DNS、YAML merge、下划线误拼、错误保密以及无关 vendor 扩展回归。首次 canonical 用例修复前 0/1、证明被静默接受；新增 typo 用例及系统 hosts/fallback 字段用例均先失败再修复。修复后定向测试 1/1 通过。
- 在 macOS、`--no-default-features --features tun,ring` 下，核心单测 832 通过/0 失败/11 忽略；DNS 配置 19/19、S01 17/17、S02 14/14。关闭 TUN、启用 ring 的核心配置相关定向测试 7/7。Cargo fmt 和严格 Clippy（TUN+Ring all-targets；无 TUN、Ring lib）通过。尚未宣称 Mihomo 二进制行为等价或 NIC/utun 无泄漏。
- 该切片保留于独立本地分支，基线为 `840c5a2b8f6a6be3e783dea026cc1bf3b5143f2f`，原主工作区未提交修改、固定参考及系统 DNS/路由/TUN 未改变。独立 L2 审查、维护者批准、GitHub Verified 和候选 SHA 的 required CI 仍缺失，不合入本地/远端 master。

## 2026-11-08 05:17 PST — v0.29.0 新基线隔离整合（L2 待审）

- `origin/master` 在本轮新增 `ffda1a7c894e2b6cf14609fa2639630d91052d91`，修改 Cargo 版本及锁文件；旧的 `840c5a2` 候选现为历史快照。已在隔离分支 `codex/macos-dns-privacy-v029-integration-20261108` 上从 `ffda1a7` 重新签名 cherry-pick 六项 DNS 修复/否定测试；未覆盖原有候选和主工作树。
- v0.29.0、macOS：TUN+Ring、无默认 feature 核心单测 832 通过、0 失败、11 忽略；DNS 配置 19/19；S01 17/17；S02 14/14；默认 feature 核心单测 1024 通过、0 失败、11 忽略；DNS 配置 19/19。Cargo fmt、严格 Clippy（TUN+Ring 与默认 feature、all-targets）通过。测试中的 DNS 端口占用错误日志属于预期的负例，断言最终通过。
- 保持固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 只读；无 Mihomo 二进制实时对照、macOS NIC/utun 抓包或系统 DNS ownership 验收。候选仅本地签名、GitHub Verified 与候选 required CI 不可确认；L2 独立 Reviewer 及维护者批准仍缺失，禁止据此更新 master 或推送。

## 2026-11-08 06:01 PST — Fake-IP TTL 显式字段失效关闭（仅本地后续切片）

- 固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go` 声明 `dns.fake-ip-ttl`，并将值传给运行时 `FakeIPTTL`；Chimera 当前不支持同等响应 TTL 语义。接受该字段但不改变运行时结果会误导配置者。
- 从公开 PR #107 的固定 HEAD `8b3faa49c55906402e99bcb05a467afca62eee92` 本地派生 `codex/dns-fake-ip-ttl-strict-guard-20261108`，先添加 `fake_ip_ttl_not_implemented_must_not_be_silently_ignored`：`fake-ip-ttl` 和 `fake_ip_ttl`、DNS 开关两态必须明确报错且不回显用户值；原有 `fake-ip-range` 继续接受。修复前目标测试 0/1，证明静默接受；修复后 1/1。
- `clash-lib/src/config/def.rs` 仅在既有 merge 后严格字段检查中添加这两个键，没有实现、也没有声称实现 Mihomo TTL 语义；修改有潜在旧配置行为改变，因此仍为 L2。
- macOS v0.29.0、TUN + Ring、无默认 feature：核心单测 832 通过/0 失败/11 忽略、DNS 配置 20/20、S01 17/17、S02 14/14；默认 feature：核心单测 1024 通过/0 失败/11 忽略、DNS 配置 20/20；两组严格 Clippy（all-targets）、Cargo fmt 与 Git diff check 均通过。未运行实时 Mihomo 二进制对照与真实 NIC/utun 抓包。
- 该后续切片**仅在本地分支**；没有修改或推送 PR #107，也没有更改其待审 HEAD，新的本地提交尚未取得 GitHub Verified / 独立 Reviewer / required CI。PR #107 正在运行的 CI 和此前审查要求不得继承为本切片的批准。

## 2026-11-08 06:25 PST — PR #107 合并后基线重锚定

- PR #107 在 2026-11-08 06:20:34 PST 已合并为 `master` `befdcdb9360c5b88aa1920c75ef83861fba2ffeb`。该提交与原 PR HEAD `8b3faa49c55906402e99bcb05a467afca62eee92` 的 Git tree 相同，虽提交历史 SHA 不同，但七项 DNS 变更的最终源码已进入远端 `master`。
- 此 TTL 切片原本地提交 `7b9b2bb4649fa14836e21e4528756dadf7ef5510` 保留；已在独立分支 `codex/dns-fake-ip-ttl-post-merge-20261108` 上以新 `master` 为直接父提交单独签名移植（最终 SHA 以该分支 HEAD 为准），不重放 PR #107 已合并的七项提交。
- 此后续提交与 PR #107 是不同审查对象，不能继承后者的 GitHub Verified、CI、Reviewer 或维护者决定；必须独立核验最终 SHA、运行相关测试并获得 L2 审查/批准。未授权修改本机 DNS、路由、TUN 或进行物理 NIC/utun 抓包。
