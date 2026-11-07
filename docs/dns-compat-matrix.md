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
| `dns.nameserver-policy` | `HashMap<String,String>`，每个值仍只接受**单个** DNS upstream；本地迭代已按 Mihomo 拆分逗号域名键，统一域名大小写，拒绝未实现的 `geosite:` / `rule-set:` 选择器以及重复键，内部热更新也无法绕过。尚不支持 Mihomo 数组/GeoSite/RuleSet 完整语义 | implemented subset (安全拒绝未实现) | A（子集） | 不破坏原有单字符串格式；`example.com: 1.1.1.1` 继续可读。真正引入多上游数组需要独立 L2 兼容决策并审查旧金标准 | `app/dns/config.rs::parse_nameserver_policy`、`config/internal/config.rs`、`resolver/enhanced.rs::match_policy`；S00 单值金标准和新增逗号/高级选择器拒绝测试 |
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
| `fake-ip-filter-mode: whitelist` | **本地迭代分支已实现** Mihomo IPv4 Fake-IP 白名单语义：仅匹配的域名使用 Fake-IP，其他域名会使用真实 DNS；模式名称大小写不敏感。完整高级域名匹配及 Fake-IPv6 未实机验证 | A（有意 opt-in） | 严格隐私配置仍推荐 `blacklist` + 空过滤列表；`whitelist` 会让未列出的代理域名使用真实解析 | 本地 `ref-mihomo` 63bd52e `component/fakeip/skipper.go`、`constant/dns.go`；新增 FakeDns/resolver/配置测试 |
| `fake-ip-filter-mode: rule` | 尚未实现，解析时明确拒绝。`fake-ip-filter` 中的 `rule-set:`、`geosite:`、Mihomo 规则表达式也显式拒绝，防止字面匹配导致隐私意外降级 | C（条件成立） | 不允许静默映射到 blacklist / whitelist；需要先完成有序规则及 RuleSet/GeoSite 运行语义 | `config/def.rs`、`app/dns/config.rs`、`dns_legacy_golden_tests.rs` |
| `proxy-server-nameserver-policy` | **本地迭代分支已实现普通域名子集的运行时选择**：有序匹配、大小写不敏感、标量/多个上游、逗号分隔规则；未命中节点使用独立 `proxy-server-nameserver`，策略失败不降级至主 DNS。`geosite:`、`rule-set:`、`system`、`#proxy` 暂拒绝；未进行真实 macOS DNS 出口抓包或完整 Mihomo 互操作 | A（部分支持，L2 待审） | 仅此字段从 P0 拒绝列表移除；仍要求独立节点 nameserver | 固定 Mihomo `config/config.go::parseNameServerPolicy`、`dns/resolver.go`；`app/dns/config.rs`、`resolver/enhanced.rs`、`dns_config_tests.rs` |
| `direct-nameserver-follow-policy` | **本地分支实现运行时语义**：默认 false 保持旧 DIRECT 解析行为；设为 true 且配置 `direct-nameserver` 时，在独立 DIRECT 解析器上共享 `nameserver-policy` 的同一批上游/域名匹配器。匹配规则时优先策略且失败不回退；未命中时走 `direct-nameserver`，该上游失败也不降级为普通 DNS（Mihomo 独立 DirectResolver 语义）；没有 `direct-nameserver` 则和 Mihomo 一样不会生成专用解析器。域名匹配显式转为小写，防止大小写绕过策略 | A（部分等价，L2 待审） | 只有显式 true 更严格；false 下 Chimera 原有 DIRECT→主 DNS fallback 保留以维护既有兼容。尚无真实 macOS NIC/TUN 出口抓包 | 固定 Mihomo `config/config.go::parseDNS`、`dns/resolver.go::ReCreateServer`；`app/dns/config.rs`、`resolver/enhanced.rs`、新增 config/runtime 负例测试 |
| `dns.fake-ip-ttl` | **本地迭代分支实现**：Mihomo 默认/最小 TTL 为 1 秒，0 和负值规范化到 1；设置正整数时只改变合成 Fake-IP A/AAAA DNS 记录的 TTL，不改变被 `fake-ip-filter` 排除域名的真实 DNS 响应及 TTL。超过 `u32` 的值拒绝。相比原 Chimera 合成 A/AAAA 默认 60 秒，默认值变为 1 秒是有意兼容行为变更，需维护者 L2 审查 | A（合成应答运行时支持；L2 待审） | 不改真实上游 TTL；旧配置如果依赖缓存 60 秒需显式指定 `fake-ip-ttl: 60`；PTR 当前仍使用独立固定 TTL | 固定 Mihomo `config/config.go`、`dns/enhancer.go`、`dns/middleware.go::withFakeIP`；`app/dns/server/handler.rs`、配置/运行时/模拟上游测试 |
| `cache-algorithm`、`prefer-h3`、`fallback-lazy-query` | 未见原生承诺；不能因此把现存缓存和 fallback 功能标为缺失 | C（条件成立） | 保留实际已有缓存；不要求照搬 Mihomo 的调参名称 | 指南 §2.2 |

**尚未审定的事实**：Mihomo 端具体字段和行为尚未在固定 `ref-mihomo` 对照运行；本矩阵的 Mihomo 语义仅引用上传的 v2.0 设计稿所列候选，**不是经 Mihomo 运行验证的兼容认证**。`#RULES`、跨 Host/Gateway、多网卡真实 DNS 出口、IPv6 Fake-IP 仍需要专门实验，不能以配置解析成功代替运行时验证。

## 2026-11-06 macOS DNS 配置拒绝与节点引导失效关闭（L2 待审）

- 基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy`，开发前 HEAD `78b1d0cda8d231ece2748db44bbdade7c8de0128`；本地 `master=e42dabe74282c77245da1023de0b828830928216`，`origin/master=902c5e7702960ab4f978a014d7079c79d17079fd`；固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。同一项目另一隔离分支已有 `2c7fd3469989` 的类似字段拒绝提交；本轮不重置、不 cherry-pick、不改该分支。
- 参考：固定 Mihomo `config/config.go::RawDNS`、`RawTun`、`parseDNS` 和 `docs/config.yaml`。Mihomo 的节点 DNS 和 fallback 选择语义不能以 Chimera YAML 反序列化成功替代；不支持的敏感选项应当报错。这里只建立 fail-closed 边界，**未实现对应运行时字段语义**。
- 本轮在 YAML merge 后、反序列化前拒绝 12 项未实现的隐私相关输入：`tun.dns-mode`、`tun.auto-detect-interface`、`tun.include-interface`、`tun.exclude-interface`、`tun.stack`、`tun.route-address`、`dns.proxy-server-nameserver-policy`、`dns.direct-nameserver-follow-policy`、`dns.fake-ip-ttl`、`dns.use-system-hosts`、`dns.fallback-lazy-query`、`dns.fallback-filter.geosite`。保留不相关 vendor 字段兼容；诊断只输出字段名，不输出 DNS policy 值。以上 12 项仍为 unsupported，绝非 implemented。
- 内部解析器 `EnhancedResolver::new` 的 `proxy_server_nameserver=Some(vec![])` 原先会降级为默认解析器；现在直接拒绝，防止在配置转换之外（内部配置或未来热重载路径）悄然回退。没有配置（`None`）仍保留旧行为。普通 YAML 的空列表在配置转换层已提前拒绝。定向负例先证明旧实现错误地接受 `Some(empty)`，修复后通过。
- 仍存在的风险：`default-nameserver` 可能为系统/物理出口 DNS，当前系统 service-scoped DNS ownership 与物理 NIC 隔离尚未验证；macOS 真实网络与 TUN 抓包、跨平台测试及 L2 独立 Reviewer/维护者批准均未完成。没有修改系统 DNS、TUN、路由、权限、子模块或远端 Git。
- 当时计划的下一步是 `proxy-server-nameserver-policy`；它已在随后独立提交中实现普通域名子集，见下文。上述 12 项拒绝列表记录的是 P0 历史提交 `27d943b`，不能将它理解为本地 P1 HEAD 仍拒绝全部字段。

### 2026-11-06 节点 DNS 策略部分 Mihomo 兼容（L2 待审）

- 基线 `e8e9fcce761d8e6cb233c45cd1cf91dd77fd212f`；Mihomo 固定 gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，参考 `config/config.go::parseNameServerPolicy`、`dns/resolver.go` 的专用 ProxyResolver。参考子模块保持只读。
- `dns.proxy-server-nameserver-policy` 已支持按 YAML 顺序的普通域名选择器、既有 trie 的星号/加号域名匹配、逗号拆分域名、字符串或上游列表、大小写不敏感；仅代理节点域名应用，未命中走独立默认节点 DNS，匹配的策略失败则直接失败而不回退普通 DNS 或 fallback。网络路径重置包含其专属 DNS 客户端，内部配置也强制要求独立节点 nameserver。
- 运行时还将这套有序策略挂到 DNS 传输层的独立 `outbound_resolver` 上（并非只影响普通 DNS listener），新增该入口下选中专用策略或回退**专用默认节点 DNS**的模拟测试。内部配置绕过 YAML 注入不支持的 GeoSite 等规则也会被拒绝。
- 不支持且会明确报错：`geosite:`、`rule-set:`、策略值的 `system` 上游及 `#proxy` 指定出站。其它 Mihomo DNS 高级策略、真实 DNS 出口接口选择、系统 service-scoped resolver、TUN/NIC 抓包和跨平台运行仍未验证；不能宣称全部兼容或全系统零泄漏。
- 对应测试涵盖 YAML→运行时、客户端构造、多个上游、匹配顺序、未知节点默认专用解析器、策略失败无公共 DNS 回退、大小写、网络切换重置及内部热更新校验；既有 `dns_legacy_golden_tests::s00_respect_rules_and_legacy_proxy_modifier_are_preserved` 的前序冲突仍单列，不改旧测试掩盖失败。

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

## 2026-11-09：最新 v0.29.1 主线上的独立 DNS 安全候选批次 1（L2 待审）

- 基线：`origin/master` `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定只读 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。本地 `master` 有未提交修改且与远端分叉，因此仅在隔离集成分支 `codex/dns-master-batch1-20261109` 提交，不改写或移动 `master`。
- 第一项：独立移植 `staged_cache_keeps_legacy_symlink_replacement_semantics`，验证 Provider 原子缓存覆盖符号链接路径而不修改其目标文件（源分支 `8cdec18`）；只移植兼容性回归，不复制不相关历史文档。
- 第二项：内部配置将 `dns.proxy-server-nameserver` 设为显式空列表时，验证阶段直接 `InvalidConfig`，未配置 `None` 则维持旧行为。源分支 `54b80b2` 的独立 P0 修复已适配最新主线；否定测试 `explicit_empty_proxy_node_bootstrap_fails_internal_reload` 先失败（0/1），再实施修复。
- macOS 本地验证：Rust 1.99.0（由于项目锁定的 1.99.1 安装不完整，需补跑锁定工具链），TUN+Ring、无默认 feature 核心库 834 通过、0 失败、11 忽略；`dns_config_tests` 20/20；严格 all-target Clippy（`-D warnings`）、Cargo fmt 和 Git diff 检查通过。端口占用日志是 DNS listener 失败路径的预期注入。
- 局限：未进行 macOS 物理 NIC/utun 抓包、Mihomo 二进制互操作、独立 L2 Reviewer 或远端 required CI。不得把本地候选标成已合并至 `master` 或已通过发布审查；未修改系统 DNS、路由、TUN、Network Extension、权限或远端分支。

## 2026-11-09 — 批次 2：内部 default-nameserver 引导安全校验（L2 待审）

- 以最新 `origin/master` `f304da17` 及第一批隔离提交为基线，借鉴原始 `088f487`，只移植可独立应用的 `default-nameserver` 内部配置校验及对应测试；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读。
- 内部配置和热重载拒绝空、非 IP 字面量、`#proxy` 或 `dhcp://` 上游，保留 IP 字面量 DoH 的旧配置；这并非系统级 macOS DNS 零泄漏验收。
- 独立 L2 审查、Rust 1.99.1 锁定工具链核验、Mihomo 二进制互操作和 NIC/utun 抓包仍待完成；未更新本地 `master` 或远端分支。

## 2026-11-09 — 批次 3：DNS 监听与 TLS 身份字段拼写失效关闭（L2 待审）

- 基于最新 `origin/master` `f304da17` 与前两批本地候选，独立适配原始候选 `377085f` 的 DNS 监听/TLS 隐私字段诊断，不引入其依赖的较大范围配置校验重构。
- 先写 `dns_listener_typo_must_not_silently_disable_listener`：旧行为会接受 `dns.listen.tpc`（否定测试 0/1）；新增合并后 YAML 校验，拒绝 DNS 监听协议和 DoH/DoT/DoH3 的证书、主机名、地址相关拼写错误，同时保持普通 `vendor-extension` 字段兼容。
- `dns_tls_certificate_typo_must_not_silently_disable_identity` 断言诊断不会打印 `secret.example`。两个定向测试通过；TUN+Ring 无默认 feature 核心库 837 通过/0 失败/11 忽略，DNS 配置 21/21，严格 all-target Clippy、fmt 和 diff 检查通过（Rust 1.99.0，锁定 1.99.1 安装状态待修复）。
- 固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读；未实际运行 Mihomo 二进制、macOS NIC/utun 抓包、远端 CI 或独立 L2 Review。此批仅保存在隔离集成分支，不将测试结果当成主线发布批准。

## 2026-11-09 — 批次 4：DNS/TUN 隐私配置字段拼写失效关闭（L2 待审）

- 基线为已推送的第 3 批 HEAD `24435eacc6d79abc4e794698db270f07785edca4`，上游 `origin/master` 为 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读。
- 独立移植旧 DNS 隐私分支 `0f3ef23` 中可审查的顶层 DNS/TUN 及 `fallback-filter` 字段诊断，并复用已验证的一编辑/相邻交换拼写比较函数。先写负向测试，旧配置会默默接受 `dns.nameserver-polcy`（0/1）；修复后明确拒绝安全敏感的近似拼写、YAML merge 后的错拼、TUN `strict-route`/`strcit-route`（尚无有效运行语义）、未实现的 `dns.fallback-filter.geosite`，同时保留普通 `vendor-extension` 兼容。
- 验证：Rust 1.99.0、macOS；无默认 feature + TUN/Ring 核心库 **842 通过 / 0 失败 / 11 忽略**，默认 feature + TUN/Ring 核心库 **1034 通过 / 0 失败 / 11 忽略**；两组 DNS 配置集成各 21/21。严格 all-target Clippy（两组）、Cargo fmt 与 Git diff --check 均通过。
- 此批次为仅本地签名候选，不包含在第 3 批远端推送的 SHA 内；独立 L2 审查、GitHub required CI、锁定 Rust 1.99.1 修复与复测、Mihomo 二进制互操作及 macOS NIC/utun 抓包仍待完成。未修改 `master`、系统 DNS/TUN/路由或其他工作树的未提交内容。

## 2026-11-09 — 批次 5：nameserver-policy 普通域名逗号选择器（L2 待审）

- 基于隔离分支 `codex/dns-master-batch4-20261109` 的 `efa18a1a2d1162e967396c9d8d4f05196b9c5f07`，上游 `origin/master` 快照 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定 Mihomo 只读 gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy` 对普通域名键以逗号拆分并共用指定 nameservers。此批仅移植 **普通域名选择器展开**，不宣称多 DNS 上游数组、GeoSite、RuleSet 或 Mihomo orderedmap 冲突优先级等价。
- `clash-lib/src/app/dns/config.rs::parse_nameserver_policy` 将 `example.com,other.test` 展开为两条规范化小写的可匹配键；`resolver/enhanced.rs::match_policy` 将查询域名规范化后查 trie。保持原有单域名/`*.`/`+.` 语法；拒绝空 token、选择器空白、重复及大小写折叠后的冲突、`geosite:` 和 `rule-set:`，不再将普通多域名逗号键拒绝或默默当字面串。
- 先写 `nameserver_policy_expands_comma_selectors_into_runtime_domains`，原代码确定性失败（0/1），修复后通过；另加 `nameserver_policy_rejects_ambiguous_or_unsupported_comma_keys`、YAML→内部配置集成测试，以及 `comma_delimited_nameserver_policy_uses_dedicated_upstream`，用 mock DNS 证明两个域名命中策略上游、未匹配域名仍走主上游。
- 本地验证：macOS，Rust 1.99.0；`--no-default-features --features tun,ring` 核心库 **845 pass/0 fail/11 ignored**，默认 features + `tun,ring` 核心库 **1037 pass/0 fail/11 ignored**；两组 `dns_config_tests` **22/22**，严格 `clippy --all-targets -D warnings`、`cargo fmt --check` 和 `git diff --check` 均通过。
- 未覆盖：policy value 多上游数组（当前 `HashMap<String,String>`）、Mihomo 有序 selector 冲突覆盖语义、实际 Mihomo 二进制互操作、macOS 物理 NIC/utun 抓包、Rust 1.99.1 锁定工具链（本机安装缺少 manifest）、远端 required CI、独立 L2 审查。本批只本地签名提交；不自动推送/合并主线，不修改系统网络。

### 2026-11-06：代理节点 DNS policy 选择器边界

- 固定 `ref-mihomo` gitlink：`63bd52ec794b7051569b76ede2f6cdbf4c091fda`；只读核对 `config/config.go` 的 `ProxyServerNameserverPolicy` 与 `parseNameServerPolicy` 调用，未执行 Mihomo 二进制对照测试。
- 内部配置（含热重载）和 YAML 解析均拒绝带空白字符的 `proxy-server-nameserver-policy` 域名选择器。此前内部配置会接受 `node.example `，但无法匹配实际查询，造成策略静默失效；新增先失败后通过的否定测试。
- 独立节点解析器增加混合大小写回归断言（既有实现已通过），保持节点 DNS 选择不区分 QNAME 大小写。
- 验证：`cargo test -p clash-lib --lib internal_node_dns_policy_rejects_whitespace_selector --features tun,ring`、`cargo test -p clash-lib --test dns_config_tests --features tun,ring -- --test-threads=1`（30/30）、`cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring -- -D warnings`、`cargo fmt --all`。未进行 macOS 网络变更或抓包；Mihomo 的完整规则选择语义仍待运行时对照。

### 2026-11-06：TUN + Fake-IP 节点 DNS 引导路由隔离（L2 待审）

- 开发基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy` 的 `b9e90c0b95a2ca5a4aed752f249f6150a5e0ea61`；固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。参考 `config/config.go::parseDNS` 使用 `parseNameServer(cfg.ProxyServerNameserver, false, ...)`，节点 DNS 不应依赖业务代理规则；Chimera 对特定 DNS 上游允许旧式 `#proxy`，并不自动继承 Mihomo 的引导安全保证。
- 在 `tun.enable && dns.enable && enhanced-mode: fake-ip` 下，`dns.proxy-server-nameserver` 明确拒绝 `#proxy` 代理路由（防止节点解析依赖自身）与 `dhcp://` 系统网络服务 DNS 发现（可能绕过 utun DNS 劫持）；`dns.proxy-server-nameserver-policy` 的选中上游也拒绝 `dhcp://`。在内部配置/热重载的 `Config::validate` 执行相同门禁。普通非 TUN 配置的旧 `#proxy` 语法仍保留。该切片不改变 `dns.nameserver` 的旧业务出口配置。
- 先写 `dns_config_tests::fake_ip_tun_proxy_bootstrap_rejects_proxy_routing_and_dhcp` 否定测试，修复前实际失败；随后实现并加入 `internal_tun_fake_ip_rejects_proxy_bootstrap_dialer_and_dhcp`、策略 DHCP 否定测试和非 TUN 兼容测试。
- **边界**：本切片阻断两种已知的危险引导方式，但未证明其他 DNS 上游的物理 NIC 出口均受控；`default-nameserver`、DNS policy 上游的 bootstrap、macOS service-scoped resolver、真实 NIC/utun 抓包和 Mihomo 二进制互操作仍需后续验证。没有改动宿主机 DNS、路由、TUN、Network Extension 或提升权限。

## 2026-11-06 P0: internal default DNS bootstrap validation (local isolated branch)

- Baseline: `codex/macos-tun-fakeip-dns-privacy` at `db728d5`; fixed read-only Mihomo submodule gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, compared with `config/config.go::parseDNS` (default nameserver must be IP-based).
- `Config::validate` now enforces nonempty, IP-literal `dns.default-nameserver` without `#proxy` or DHCP even for internal configuration and reload, closing a path that bypassed YAML conversion checks. IP-literal DoH remains accepted. This is stricter than accepting system resolver discovery and is deliberate for bootstrap isolation.
- Regression: `internal_default_nameserver_bootstrap_rejects_non_ip_and_proxy_dialers` first failed to compile with the missing validator, then passed after implementation. DNS config integration and strict Clippy pass. This is configuration-level fail-closed, **not** proof of no macOS system DNS leakage; physical NIC/utun capture and L2 review remain required.

## 2026-11-07 P0: DNS policy selector fail-closed validation

- Pinned read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Source comparison: `config/config.go::parseNameServerPolicy` splits comma-delimited keys and validates each raw token through `component/trie/domain.go::ValidAndSplitDomain`. It rejects leading/trailing whitespace and malformed wildcard placement. The Mihomo validator does not itself reject embedded whitespace; Chimera explicitly rejects that extra case because it would create a trie key that silently misses the intended DNS name. This is a conservative privacy divergence, not a claim of byte-for-byte Mihomo equivalence.
- Root cause: both Chimera `dns.nameserver-policy` and `dns.proxy-server-nameserver-policy` stripped whitespace before validating tokens. The permissive Rust trie validator also accepted partial/misplaced wildcards. These accepted keys could bypass intended per-domain/per-node DNS routing. An internal `Config` could bypass YAML expansion and put a comma-delimited node policy key directly into the runtime trie.
- Negative tests were added before production changes. `nameserver_policy_rejects_selector_ambiguity_before_runtime_trie` failed on a leading-space key rewritten to `example.com`; `proxy_nameserver_policy_rejects_selector_ambiguity_before_node_dns` failed on rewritten `node.example`; `internal_proxy_server_policy_rejects_malformed_domain_selectors` failed on a comma-delimited internal key. All three passed after the shared selector validator and internal config guard were fixed. Existing valid keys (`example.com`, `*.example.com`, `.example.com`) remain supported, and comma lists without whitespace still expand.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: 1046 passed, 0 failed, 11 ignored; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1`: 35 passed, 0 failed; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, `cargo fmt --all -- --check` and `git diff --check` passed. The unrelated pre-existing legacy golden `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` still failed (12 passed, 1 failed) because `respect-rules` now requires dedicated node DNS bootstrap; this change did not touch that rule.
- No host DNS, routing, TUN or Network Extension changes, no elevated operations and no real physical NIC/utun packet capture. L2 independent review, maintainer decision and real Mihomo runtime parity remain outstanding. Non-TUN/other-platform checks must be reported separately.

## 2026-11-07 P0: selective unknown DNS/TUN privacy fields

- In a `serde(default)` configuration, unknown YAML keys silently disappear. That can disable requested DNS policy, Fake-IP filtering, DNS hijack or TUN strict route semantics. The pinned read-only Mihomo gitlink remains `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. This guard is a Chimera privacy hardening policy, not a demonstrated equivalent to every Mihomo unknown-key parser behavior.
- Added negative tests before production edits. `unknown_privacy_shaped_dns_field_names_fail_closed` failed initially on `dns.nameserver-polcy`; `unknown_privacy_shaped_tun_field_names_fail_closed` failed initially on `tun.dns-hijak`; `fallback_filter_unknown_privacy_fields_fail_closed` failed initially on `dns.fallback-filter.geoiip`. All pass after repair. Also tested merged YAML anchors and `Config::Str(...).try_parse()` for actual runtime-entry rejection.
- The raw YAML guard (after `apply_merge`, before serde deserialization) rejects privacy-shaped unknown fields and one-edit near-misses in `dns`, `tun` and nested `dns.fallback-filter`. Error messages identify the bad key, not DNS values. Existing supported keys and aliases, plus unrelated vendor keys, stay accepted. This guard is intentionally selective, not a universal ban on all unknown keys. It also does not claim coverage for arbitrary spellings far from known controls.
- Current-source tests: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> 1050 passed, 0 failed, 11 ignored; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> 36 passed, 0 failed; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` and Cargo fmt/diff checks passed. With TUN disabled and ring enabled, `config::def::tests::` -> 18 passed, 0 failed. DNS S01 and S02 integration groups -> 17/17 and 14/14 passed.
- The pre-existing `dns_legacy_golden_tests` failure remains: 12 passed, 1 failed (`s00_respect_rules_and_legacy_proxy_modifier_are_preserved`) because `dns.respect-rules` requires dedicated `proxy-server-nameserver`; this slice does not modify that constraint. Optional Linux cross-check was attempted but stopped in `cc-rs` because `x86_64-linux-gnu-gcc` is not installed; it is an environment block, not proven source failure. No real NIC/utun capture or host network changes; L2 independent review, maintainer decision and Mihomo runtime interoperability remain pending.

## 2026-11-07 P0: macOS TUN Fake-IP DHCP egress fail-closed

- Fixed read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Mihomo `config/config.go::parseNameServer` accepts `dhcp://` for DNS service discovery. Chimera's `clash-lib/src/app/dns/dhcp.rs::probe_dns_server` opens DHCP UDP sockets on the physical interface, then makes clients for the discovered DNS IPs without a proved TUN-isolated egress path. Since scoped macOS DNS ownership and physical-NIC egress cannot be verified without permission and a real packet capture, this slice deliberately **rejects** DHCP in macOS TUN + Fake-IP high-privacy mode instead of claiming Mihomo runtime equivalence.
- Prior to production changes, `macos_fake_ip_tun_rejects_dhcp_in_all_dns_egress_pools` failed because `Config::Str(...).try_parse()` accepted `dns.nameserver: [dhcp://en0]`; `internal_macos_fake_ip_tun_rejects_service_scoped_dhcp_dns_egress` separately failed through direct internal config mutation/re-validation. Both red tests became green after macOS-only `Config::validate` rejected DHCP in four DNS egress scopes: `dns.nameserver`, `dns.fallback`, `dns.direct-nameserver`, and `dns.nameserver-policy`. The existing dedicated node DNS and per-node policy DHCP blocks remain in place.
- Compatibility controls: under macOS non-TUN configuration, DHCP remains parseable in all four pools. TUN with `enhanced-mode: normal` also retains the previous DHCP behavior. No DHCP probe, TUN, system DNS, network route, Network Extension, or elevation was used; these are pure configuration tests.
- Final validation from current source: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1051 passed, 0 failed, 11 ignored**; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> **39 passed, 0 failed**; DNS S01/S02 integration tests -> **17/17 and 14/14 passed**; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` and Cargo fmt/diff checks passed. No-feature `ring` build: `internal_macos_dhcp_cannot_mask_missing_tun_feature` ran red-before-green and now passes; an unsupported TUN configuration reports the missing `tun` feature first, before any DHCP-specific check. The TUN-dependent tests are feature-gated so this non-TUN matrix does not spuriously fail. These checks cannot establish real host DNS leak freedom.
- Risk / next step: refusing intentionally configured DHCP is a documented high-privacy compatibility divergence from Mihomo, required until macOS service-scoped resolver traffic is measured under an explicitly authorized physical NIC/utun test. Consider replacing the refusal with a genuinely managed transport only after packet captures, rollback and L2 review establish its egress behavior.

## 2026-11-07 P0: explicit DNS interface override fail-closed on macOS

- Pinned read-only Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`: `config/config.go::parseNameServer` retains URL fragment parameters, including `#interface`; Chimera's `Config::parse_nameserver` materializes `#interface` into `NameServer.interface`, which `app/dns/helper.rs::make_clients` passes to `DnsClient::new_client` as a forced socket interface. A physical NIC override can bypass network-path-managed DNS egress. The new explicit refusal is a *macOS TUN + Fake-IP security divergence*, not a claim that all Mihomo fragment semantics are equivalent.
- First added offline negative test `internal_macos_fake_ip_tun_rejects_physical_dns_interface_overrides`, using a **synthetic** `OutboundInterface` with no actual interface lookup, socket creation or host network mutation. It failed on `dns.nameserver` before the change. Then extended the existing macOS-only high-privacy validation to refuse `#interface` for all seven pools: `dns.nameserver`, `dns.default-nameserver`, `dns.fallback`, `dns.direct-nameserver`, `dns.nameserver-policy`, `dns.proxy-server-nameserver`, and `dns.proxy-server-nameserver-policy`. The test passed afterwards for every case. Existing bootstrap/DHCP isolation checks remain in place.
- Compatibility: synthetic interface-bound `dns.nameserver` and `dns.default-nameserver` remain valid with TUN off; also valid with TUN on but `enhanced-mode: normal`. These control tests pass. The non-TUN `ring` feature combination passes the non-TUN control; TUN-dependent tests are feature-gated.
- Current-source validation: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1054 passed, 0 failed, 11 ignored**; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> **39 passed, 0 failed**; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, fmt and diff checks passed. The older legacy golden failure `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` is tracked above and not resolved by this slice; other-platform compilation and live system DNS capture remain outstanding.
- This only blocks explicit upstream `#interface` overrides under the named macOS privacy configuration. It **does not guarantee** that an unspecified DNS socket cannot use a physical NIC, that macOS service resolver ownership is correct, or that all host DNS packets enter TUN. Before allowing `#interface` again, a managed egress mechanism, authorized physical NIC/utun packet capture, L2 independent review and maintainer approval are necessary. No host DNS, route, TUN, Network Extension or permissions were changed here.

## 2026-11-07 P0: macOS TUN Fake-IP DNS #interface egress override

- Pinned read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; inspected `config/config.go::parseNameServer` (`u.Fragment` params) and Chimera `app/dns/helper.rs::make_clients` (`NameServer.interface` forwarded as `Opts.iface`), `app/net/mod.rs::OutboundInterface`. An explicit DNS `#interface` can bind sockets to a physical network service and bypass the verified managed DNS path. This is a **deliberate high-privacy restriction** rather than a claim of exact Mihomo compatibility.
- Added `internal_macos_fake_ip_tun_rejects_physical_dns_interface_overrides` using a synthetic `OutboundInterface` and all seven DNS upstream scopes (`nameserver`, `default-nameserver`, `fallback`, `direct-nameserver`, `nameserver-policy`, `proxy-server-nameserver`, `proxy-server-nameserver-policy`). It failed first because internal `Config::validate` accepted `dns.nameserver` with a physical interface, then passed after fail-closed validation. No real NIC or socket was accessed by this test.
- Compatibility: `non_tun_dns_interface_override_keeps_legacy_compatibility` passes both TUN-enabled and no-TUN builds, and `tun_normal_mode_dns_interface_override_keeps_legacy_compatibility` passes. Existing DNS fields without explicit interface bindings remain unaffected.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1054 passed, 0 failed, 11 ignored**; DNS config integration -> **39 passed, 0 failed**; strict Clippy TUN+Ring `--all-targets -D warnings` passed; strict no-TUN Ring `--lib -D warnings` passed. S01/S02 integration tests rerun on this source -> **17/17 and 14/14 passed**. This is config-level isolation only; independent L2 review and physical NIC/utun capture under separate authorization remain required.

## 2026-11-07 P0: adjacent-transposition privacy field diagnostics

- Fixed read-only Mihomo reference gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; Mihomo's `config/config.go::parseNameServer` and DNS policy handling were checked read-only. This is a Chimera configuration safety gate, **not** evidence of Mihomo runtime equivalence.
- YAML's permissive legacy field handling previously ignored a transposed `tun.strcit-route`, potentially disabling an intended strict-routing guarantee. Added it to the existing negative test **before** implementation: `unknown_privacy_shaped_tun_field_names_fail_closed` failed with `strcit-route was ignored` (1 passed, 1 failed). `dns.edns-clinet-subnet` is a control for the existing prefix-based guard.
- `clash-lib/src/config/def.rs::within_one_edit` now also detects a single adjacent-character swap when comparing known DNS/TUN security keys; unknown unrelated vendor keys remain accepted. Errors identify the field, not its value. No host DNS, routes, NIC, TUN or permissions were touched.
- `cargo test -p clash-lib --lib --features 'tun ring' unknown_privacy_shaped` -> 2 passed, 0 failed; full `--lib` -> 1054 passed, 0 failed, 11 ignored; `dns_config_tests` -> 39 passed, 0 failed; `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` passed. Physical NIC/utun capture and L2 independent review remain outstanding.
- Next: test and close DNS bootstrap socket egress bypasses with offline resolver/path tests; separately validate scoped macOS resolver ownership under explicit host-network authorization.

## 2026-11-07 11:13 PST: node DNS transport resolver isolation on protected branch

- Read-only pinned Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, comparison `config/config.go::parseDNS` and `parseNameServer`: dedicated `proxy-server-nameserver` / per-node policy transports are distinct from general DNS and must not be silently delegated to libc/system DNS. Also reviewed the previously isolated signed local implementation `ff737ef70ed48dfa3365ef405fff8f9974708b65` on `codex/macos-node-dns-rebuild-guard-20261106`; only the minimal transport wiring and invariant were reimplemented here, not its independent lifecycle/reset changes.
- Test-first **red**: `app::dns::helper::tests::node_dns_group_fails_closed_without_explicit_transport_resolver` accepted a literal-IP node DNS upstream with missing outbound resolver (even when a separate bootstrap resolver is provided), which can cause the `dns_stream_builder` transport to choose `SystemResolver` when opening or rebuilding its stream. This is a DNS-egress isolation flaw even though the upstream IP itself needs no initial lookup.
- Production change: `helper.rs::make_clients` now requires a nonempty dedicated `proxy_server` group to have an explicit outbound transport resolver. `resolver/enhanced.rs::new` passes its managed `default_resolver` into both dedicated `proxy_server_nameserver` and `proxy_server_nameserver_policy` client groups rather than `None`. Empty node DNS groups remain a legacy no-op; an IP-literal upstream with a managed transport continues to initialize. **Green**: both dedicated group tests passed (2/2), including under `--no-default-features --features ring`.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: **1056 passed, 0 failed, 11 ignored**. `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1`: **39 passed, 0 failed**. DNS S01 and S02 suites: **17/17 and 14/14 passed**. Strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` passed; `cargo fmt --all -- --check` and `git diff --check` passed.
- Scope: configuration and offline client construction, not a physical NIC or utun packet-capture proof and not a complete Mihomo runtime parity claim. A parent node bootstrap resolver is **not** used as a substitute for a transport resolver. Pending separately: bounded network-path reset/cancellation, host system DNS ownership, L2 independent review, maintainer decision and authorized physical NIC/utun capture.
