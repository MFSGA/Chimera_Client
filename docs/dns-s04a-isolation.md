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

## S04b-a：运行时代际与动态出口预检（仅内部可调用，未启用生产规则）

- `StrictDnsCache::exchange_observed` 从现有共享 `RuntimeStatus::decision_versions()` 读取**真实 config/network generation**，不用 S02 请求上下文里尚未接线的默认 `0`。当前运行时没有有效网络观测（含成功配置重载后观测被清空）、网络代际或配置版本为零时直接拒绝；调用方需明确提供单调递增的 `bootstrap_revision`。在锁内禁止把 cache epoch 回滚；发生代际切换时清除旧条目，并在上游返回后复核 RuntimeStatus，改变则丢弃应答和旧缓存。
- `StrictDnsCache::exchange_planned_observed` 是**未接入生产解析器的 opt-in 内部入口**，每次先核对真实 DNS Question 与已编译计划，再调用 S03 的 `prepare_dns_execution` 从真实 registry **重新捕获当前 selector/provider 叶节点**。实际叶节点以 Arc 身份分桶，而非只按组名复用；显式 DIRECT 使用同一个严格缓存专属的 DIRECT handler 身份，并仍受 config/network/pin 分区约束。未命中策略、本地 Fake-IP/hosts、缺失代理和不完整的严格动作不借此入口偷偷回退；由 legacy 解析器保持现有行为。
- 对代理叶节点服务器域名尚无独立可信 bootstrap 来源，内部入口在缓存命中前仍明确拒绝该路径，不允许靠系统 DNS 补洞。**这不是完整的 bootstrap DAG 或实际动态 Provider 递归保护**，也没有自动订阅网络状态、pin 轮换或在变更中重新捕获正在使用的动态选择器；现有每查询身份分桶不等于中途切换的真实数据面证明。
- S04b-a 离线验证命令：`cargo test -p clash-lib --lib s04b_ --locked`，包括无网络快照失败、真实 network/config 变更、pin 回滚拒绝、动态叶节点分桶、在途结果丢弃、错误 Question/缺失代理 fail-closed 和显式 DIRECT 缓存复用。本次严格 `policy-rules` 运行时拦截仍保留；未修改生产 `EnhancedResolver`、Fake-IP、legacy 缓存和连接池。

## S04b-b：显式 bootstrap pin 快照与版本轮换（仍为内部实验入口）

- 新增 `app/dns/bootstrap.rs` 的 `StrictBootstrapPinStore`：只有在当前 `RuntimeStatus` 已有网络观测时才能通过 `install_explicit` 安装一套**由调用者在外部验证后提供**的 hostname→IP 映射。相同代际和相同映射不增加 revision；pin 变化、网络代际或配置代际变化时 revision 单调递增；重载后观测未恢复，或新网络还没有重新安装映射时，严格失败关闭。pin store 还固定其首次安装的 `RuntimeStatus` 实例身份，拒绝其他运行时即使代际数字碰巧相同的快照。空映射可以撤销现有的主机名 pin，不会自动读取系统 DNS 或旧缓存。
- 内部 `StrictDnsCache::exchange_planned_pinned` 使用当前 pin 快照构建真正的 S03c `DnsStrictPinnedWireTransport`，保留 DoT/DoH 的 TLS 主机名/SNI 校验和 `prepare_dns_execution` 选择的固定出口。发送前、请求完成后比较 pin 快照；在途轮换会丢弃结果并清除旧 cache epoch，且不会以旧 pin 继续缓存。无 pin 的加密 DNS 在拨号之前拒绝。
- 此接口**不证明 pin 来源已可信**。项目仍没有从独立可信解析器/签名配置加载 pin、也没有自动订阅 provider/网络事件、更没有对代理节点域名的独立 bootstrap；这些输入仍需未来的受审查生产绑定来提供。`BootstrapGraph`/`BootstrapTrace` 仍未接入真实代理依赖，因此本切片不能解除 `policy-rules` 拦截。新增 `s04bb_` 离线测试检验轮换、撤销、过期代际、配置重载、查询中途 pin 更改及缺少加密服务器 pin 的失败关闭。

## S04b-c：已选择代理叶节点的依赖环与递归防护（内部入口）

- 严格查询每次经 `prepare_dns_execution` 捕获当前动态 selector/provider 的实际叶节点后，根据其**实际 server_name、出口类型及选定 profile 的全部 upstream** 构建 `BootstrapGraph`：`Profile → Upstream → Proxy`；若代理节点自身必须解析的域名与该 upstream 的主机名相同，再加入 `Proxy → Upstream`，在**读取缓存或拨号前**拒绝强制循环。代理组叶节点切换后重新构图，不使用旧的组名作依赖证明；无法证明独立 bootstrap 的其他代理节点域名仍严格拒绝，不会隐式使用系统 DNS。
- 新增 `exchange_planned_pinned_traced` 内部入口：调用者可显式携带每请求不可变的 `BootstrapTrace` 父级路径，按 profile / 上游 / 选定叶节点检查重复节点和深度上限 16；并发请求没有共享的全局递归栈。原 `exchange_planned_pinned` 只在顶层查询使用空轨迹，仍以同一 pin 快照和网络/配置代际完成调用。`s04bc_` 离线测试覆盖动态选中叶节点导致的依赖环、无独立 pin 的代理节点失败关闭、递归入口和超过深度预算的拨号前拒绝。
- **范围限制：** 这是基于已准备好的单次严格执行计划的图，不是完整的配置期 provider 全节点遍历，也没有自动追踪代理节点经哪个独立 bootstrap resolver 解析、没有将父级轨迹注入所有真实 Dialer 调用链。不存在可信代理域名引导来源时，即使 upstream 主机名已有 pin，代理节点域名仍不允许通过此切片自动解析。完整静态依赖图、真实 bootstrap 解析源、生产接线和数据面测试继续属于后续准入前置条件。

## S04b-d：配置级静态候选依赖预检（内部、失败关闭）

- 新增 `app/dns/bootstrap_topology.rs` 的 `validate_configured_strict_egress`：从原始配置读取静态 `proxy-groups` / `proxies`、所有组成员、节点的 `dialer-proxy` / `connect-via` 链以及所用 resolver profile 的 upstream 主机名。以深度上限 16 的遍历验证依赖，拒绝循环、缺失成员、歧义名称、DIRECT/REJECT 候选以及代理节点必须通过自身 upstream 解析的情况。只要任一静态候选需要尚不存在的独立可信域名 bootstrap，就保守拒绝整组。
- 包含 `use:` Provider 的组不能把动态候选当成空集合或隐式批准：在缺少经过认证的 Provider 候选快照时明确失败关闭。现有 `StrictDnsCache::exchange_planned_pinned_configured` 是**可选的内部配置级预检入口**，先校验配置，再使用 S04b-c 的单请求递归轨迹和 S04b-b 的 pin 快照；它尚未接入生产 resolver。`s04bd_` 离线测试覆盖嵌套静态组、`dialer-proxy` 环、组环、Provider、缺失节点、同名节点和拨号前拦截。
- **限制：** 尚未获得可信的外部 pin 解析来源，也没有为 Provider 定义经过认证且与运行时代际绑定的候选快照。本轮只完成静态候选拓扑边界，不能证明所有配置端点（尤其动态 Provider）可运行；没有把配置期 graph 自动注入真实代理 Dialer，也不解除 `policy-rules` 启动保护。现有旧 DNS/Fake-IP 缓存与 Business Rules 不受影响。

## S04b-e：动态 Provider 原子候选快照与内容版本（暂不授权真实出口）

- `ProxyProvider::strict_content_snapshot` 新增可选 API：返回**在同一内部锁下读取**的候选 handler 对象及单调 content revision。可更新的 `ProxySetProvider` 在成功替换代理列表时递增版本，初次加载前返回 `None`；失败的更新保持最后一次完整列表和版本，不伪造成功。`PlainProvider` 的候选不可变，固定使用版本 `1`；其他未实现该接口的 Provider 返回 `None`，严格 DNS 观察入口拒绝其使用。
- 新增内部 `StrictProviderObservation::capture/ensure_current`：由调用者提供命名 Provider 句柄表，并将候选对象、内容版本、Provider 实例、共享 `RuntimeStatus` 实例、实际 network/config generation 绑定为一个短期观察结果。第一次捕获及未来每次复核均核对运行时代际、候选 Arc 对象身份和 Provider content revision；检测查询间版本轮换、相同名字但不同 handler 的替换、配置/网络变化、未知或未初始化 Provider，并拒绝跨运行时使用。拒绝空候选及重复节点名。新增真实 `ProxySetProvider` 离线更新测试验证有效更新、失败保留、过期观察和版本号。
- **关键安全限制：** 本快照只保证运行时内容版本可比较，**不认证下载/配置的来源或供应链**。命名 Provider 表由未来调用方传入，尚未与实时 Group/Provider 注册表、静态拓扑证明、pin 可信来源、全部 Dialer 链和选中叶节点的最终身份原子绑定。因此 S04b-d 对动态 Provider 的**失败关闭仍有效**：此版本未让动态 Provider 越过生产或内部严格拨号保护；查询开始/结束处的快照复核也尚待显式接线。S04b-e 为后续建立可信 Provider 候选拓扑证明提供版本基础，不能解除 `policy-rules` 运行时 gate。

## S04b/S04c 待完成的严格准入

1. **真实执行接线与身份来源**：S04b-a 提供共享 RuntimeStatus 读取接口，但**尚未由生产 DNS runtime 自动接入或订阅**；需有可信的 bootstrap pin revision/变更事件来源，而不是由未受验证的调用者提供任意数值。仍需真实数据面验证动态代理在查询中途切换时的失效与回滚；旧 legacy 路径继续完全独立。
2. **引导依赖图完整性**：构建代理组/动态 provider/代理节点自身域名和 DoT/DoH upstream 的真实依赖关系，验证先有稳定可信 bootstrap 再开始拨号，加入运行时强制深度 guard。当前仅显式 pin 传输和工具层拒绝，不接受未审查的隐式系统 DNS。
3. **严格连接/缓存作用域**：若未来为了性能引入连接池，须以与本缓存同样的实际代理叶节点、profile、source-scope、network/config/pin generation 进行独立池化和释放验证。本轮维持**不共享连接池**以保证安全。
4. **扩充 DNS 复杂应答和 ECS/DNSSEC**：在可以正确识别 EDNS 选项及作用域、CNAME、多 Question、CD/DO 与签名相关字段前继续保守不缓存；正负缓存策略不替代已有 legacy RFC 2308 语义。
5. **真实数据面**：可信证书下 DoT/DoH 成功路径、真实远端代理 fail-closed、DNS 出口实际抓包和网络切换/并发压测，依然是撤销 `policy-rules` 运行时 gate 的硬前置条件；独立审查与维护者批准也尚未完成。

**行为承诺**：本阶段没有更改 Business Rules 顺序、业务最终出口、旧 DNS fallback、Fake-IP 处理、旧缓存或默认加密 DNS 行为；不能把 S04a 内部隔离能力写成正式用户可用的下一代 DNS。
