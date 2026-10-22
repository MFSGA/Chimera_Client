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

## S04b-f：Provider 注册表身份与实际选定叶节点检查（不授权 DNS 拨号）

- `StrictProviderObservation::capture_registered` 绑定**命名 Provider 注册表的 Arc 实例及其中每一个 Provider 句柄**，除上一阶段的 network/config generation、单个 Provider 内容修订与候选 Arc 身份外，在检查前后还对比注册表名称集合和每个句柄身份；同名 Provider 被另一个对象替换会令旧观察失效。它仍不能检测读取窗口外的瞬时 A→B→A 注册表变更：尚无注册表级单调版本号与原子拨号承诺。
- 新增 `validate_observed_selected_provider` 和 `StrictDnsCache::inspect_observed_provider_selection` **内部检查接口**：调用 S03 既有的 `prepare_dns_execution` 重新选择当前 egress 叶节点，沿原配置的嵌套组/`use:` 候选追踪可达 Provider，要求实际选中 handler 与 Provider 观察中的 Arc 身份相同；随后复核版本。未知成员、循环/超过 16 层、未观察 Provider、同名但已替换的叶节点、注册表重绑均失败关闭。它不会进行 DNS 查询、不读写严格答案缓存、不调用 DNS transport 拨号，也不会取代此前完整静态拓扑对未认证 Provider 的**拒绝**。**注意：** S03 在捕获动态组选择时可能触发原有 Provider `touch`，因此检查过程不保证完全无副作用或无其他网络行为。
- `StrictProviderObservation::validate_during` 增加**只读/无共享缓存副作用**操作的查询前与结束后版本复核辅助，离线测试使用可暂停的操作，在其运行时轮换候选列表并确认旧结果不返回；不得把此辅助当成共享缓存 invalidation 或生产网络拨号隔离。S04b-f 仍缺 Provider 来源认证、所有 `dialer-proxy` 链端点证明、完整 selector/provider 快照与实际拨号的事务性绑定，故生产 `policy-rules` 保持禁用，动态 Provider 的严格执行入口继续失败关闭。

## S04b-g：严格观察专用 Provider 注册表修订号（阻断短暂 A→B→A）

- 将仅供内部严格 DNS 观察使用的 `StrictProviderRegistry` 从可直接写入的 `RwLock<HashMap<...>>` 改为 `StrictProviderRegistryStore`，以**同一个写锁**维护 Provider 句柄表和单调 revision；任何 `replace`（包括相同 Arc 的重置）均推进版本，版本溢出时失败且保持原状态。观察创建时原子捕获版本和对象表，在观察前后的完整性复核里同时检查版本、对象身份和 Provider 内容修订。即使调用方在两次复核间将注册表从 A→B→A 恢复为相同对象，旧观察仍然失败关闭；增加隔离测试同时覆盖一次普通 ABA 和暂停中的只读操作 ABA 轮换。
- **边界：** 新注册表仅用于 opt-in 严格观察，不取代现有实际 ProxyManager/Group 注册表，也不保证未来真实拨号过程的原子选择及身份约束。要将它接入实际数据面仍需可靠的 Provider 内容来源认证、全部路由/拨号链验证和事务性 epoch 承诺。生产 `policy-rules` 启动拒绝仍保持不变。

## S04b-h：真实 OutboundManager 身份绑定（只读检查，无生产接线）

- `StrictProviderObservation::capture_manager` 直接从已经完成初始化的真实 `OutboundManager::get_proxy_providers()` 读取实际 Provider 句柄，并保留所属 `Arc<OutboundManager>`。`ensure_current_manager` 要求同一 Manager 对象、同一 Provider 句柄集合、当前 network/config 代际及各 Provider 的内容版本仍有效。即使重载后的 Manager 复用相同名称和相同 Provider Arc，旧观察也不能交由新 Manager 使用。
- 新增 `OutboundManager::owns_outbound_registry` 和 `StrictDnsCache::inspect_manager_provider_selection`：选定叶节点的 **registry Arc 必须与被观察的 Manager 所有的 registry 相同**；否则即使其中装有完全相同的 handler 对象也拒绝。通过这项检查后才使用已有 S04b-f 的选定叶节点和 Provider 可达性核对，并再次确认 Manager 观察没有变化。离线 `s04bh_` 测试覆盖正确绑定、伪造的另一份 registry、另一 Manager 实例和网络代际变化。
- **限制：** `OutboundManager` 在构造后不再修改其 Provider 句柄映射，真实 Provider 的内容更新仍使用上一阶段的单 Provider revision 检测。该方法只是内部只读检查；实际 selector `touch` 仍可能有附带行为。尚未把完整 provider 来源认证、选定叶节点→最终 dialer 链、真实网络拨号和答案缓存的事务性一致性联结起来；`policy-rules` 生产启动保护保持不变。

## S04b-i：每上游尝试前后的固定叶节点复核（内部无缓存执行边界）

- `StrictDnsExecution::exchange_guarded` 为 S03 既有严格执行增加可选 `DnsStrictAttemptGuard`：在每个 upstream 的**首次拨号前及网络调用返回后**（包括失败、成功和超时）检查当前绑定的 outbound。任一检查失败立即以错误终止，不再尝试 profile 中的第二个上游、DIRECT 或 legacy resolver；在检查持续有效时，仍允许使用**同一固定叶节点**按原 profile 顺序重试。原有 `exchange` 语义保留。此接口本身**不读写严格缓存**，也没有生产调用点。
- `StrictDnsManagerLeafGuard::bind` 绑定此前观测的真实 `OutboundManager`、其 outbound registry、Provider 所属名称以及**选中的 handler Arc**。每次执行边界复核都会拒绝不同 handler 对象（即使同名）、不同 registry/Manager、Provider 版本轮换及网络/配置代际变更；复用既有 S04b-h 观察，不偷偷重新选择另一片叶节点。离线 `s04bi_` 测试验证拨号前阻断、请求进行中变化时即使首个 upstream 成功/失败也不触发第二次拨号，以及版本稳定时正常的同叶节点重试。新增真实 Manager guard 的身份/网络变更回归断言。
- **限制：** 这是可离线测试的**检查前/后**模型，不能禁止两次检查之间已经产生的网络副作用；也尚未在实际 Connector 内部的 `dialer-proxy` 每个递归跳点做事务性保护。Provider 下载/配置内容仍无可信来源认证，不存在受认可的动态 Provider 完整拓扑证明或安全的真实 strict DNS 调用链。**不得将此接口视为生产拨号授权，也不把它接入 DNS 答案缓存或 `policy-rules` 运行时**；必须保留 S04b-d 的动态 Provider 失败关闭以及独立数据面验证和 L2 门禁。

## S04b-j：实际命名 `dialer-proxy` 单跳身份预检（内部实验入口）

- 新增 `app/dns/bootstrap_dialer.rs` 的 `StrictDnsConnectorChain`：沿已固定的出站叶节点 `support_dialer()` 读取真实 `OutboundManager` 的命名 handler，严格要求共享同一 outbound registry Arc、节点确实为固定非 DIRECT/REJECT/动态组代理、两端服务器均为 IP 字面量。保存实际引用的 handler Arc，每次严格执行 guard 复核其身份；若单跳 handler 被同名新对象替换，即使服务器地址相同也立即失败关闭。自依赖、缺失 hop、缺少独立 bootstrap 的域名和动态组全部拒绝。
- 当前 `OutboundManager::init_handler_connectors` 为 `dialer-proxy` 注册的是 `ProxyConnector(named_proxy, DirectConnector)`，并未安装任意递归多跳连接器。因此 S04b-j **主动拒绝第二级 `dialer-proxy`**，不能把配置中写出的链误认作受到逐跳保护。`StrictDnsManagerLeafGuard::bind/ensure_current` 在既有 Provider、Manager、网络代际检查的前后增加此单跳关系复核，不使用共享 DNS 缓存、不解除生产保护。新增 `s04bj_` 离线测试覆盖同名 hop 替换、缺失/循环/不可信端点/多跳/动态组以及 guard 执行边界。
- **限制：** 身份检查仅在 I/O 前后发生，不可撤销两次检查之间的网络副作用；真实 Connector 内部仍未绑定原子代际承诺及防 ABA 的注册表版本，也没有对正在使用的连接池进行端到端认证。Provider 下载内容与代理端点 bootstrap 来源尚未认证，完整动态拓扑证明、实际数据面抓包、独立 L2 审查及维护者批准仍为前置条件。`policy-rules` 生产 gate 继续保持关闭。

## S04b-k：真实 outbound registry 作用域租约（仅内部无缓存严格执行）

- 对当前真实 `OutboundHandlerRegistry = Arc<RwLock<...>>` 新增 `StrictDnsConnectorChain::lease_for_exchange`：获取**持有所有权的 RwLock 只读租约**，在同一锁内验证 S04b-j 捕获的命名 hop 与选中叶节点。新增 `StrictDnsManagerLeafGuard::exchange_with_leased_connector`，将该租约保持至 `StrictDnsExecution::exchange_guarded` 全部上游尝试结束，期间任何 registry 写锁替换都必须等待；不会发生请求进行中的可见 A→B→A 命名 hop 更新。每个上游 I/O 前后复核 Provider 内容、Manager 身份、network/config 代际及固定叶节点。租约内的复核不重入获取 registry 的 RwLock，以防等待中的写者导致读者死锁。
- `s04bk_` 离线回归：正在执行假 DNS I/O 时启动同名 hop 的 A→B→A writer，验证写者被阻塞；独立地更改网络代际后，DNS 旧应答失败关闭，租约释放后 writer 才完成。另覆盖开始租约前 hop 已被同名替换时必须拒绝。仅触及内部 `bootstrap_dialer.rs`、`bootstrap_provider.rs` 和测试，原有生产代理流量/业务 registry 使用方式不变。
- **关键限制：** 只读租约阻塞真实 registry 的写者直至内部请求结束（包括失败和超时）；会产生潜在写锁延迟，不可未经性能、取消与死锁审查接入生产。它**不是全局单调 registry revision**，对捕获快照之前发生且已恢复的 A→B→A、Provider 内部自身变化、Connector 构造时持有的私有 handler、socket 打开期间的系统级流量副作用，均不能单凭这个锁给出证明。真实 socket path generation / Connector 内部逐跳事务验证及经过认证的 Provider/pin 来源仍未完成；`policy-rules` 生产 gate 继续关闭，不能视为用户可用功能。

## S04b-l：租约超时/取消释放与 socket 路径规划代际一致性（仅内部）

- `StrictDnsManagerLeafGuard::exchange_with_leased_connector` 新增**整个内部操作 11 秒总时限**（含等待实际 registry 读租约、每次上游请求及其前后身份校验）；超时取消作用域中的 future，利用 owned 读租约的 RAII `Drop` 释放锁，避免由于不可达或停滞的上游长期阻塞 registry 写者。`exchange_with_lease_budget` 仅作为共享实现和定向测试的小预算入口；生产尚无调用方。主动取消该 future 也会释放同一租约，未继续重试或返回旧应答。
- 新增 `OutboundManager::strict_dns_path_generation`，从实际 Manager 的 `NetworkPathSource::snapshot` 核对**所绑定的 SharedNetworkStatus Arc 与严格 DNS 所见为同一运行时**，且 socket **路径规划网络代际** 与当前严格 DNS 观察的 network generation 一致。租约内每次网络 I/O 前后都会复核；缺失 path 观察、已换绑 RuntimeStatus 或代际不符均失败关闭。`s04bl_` 四项离线测试覆盖请求进行中的超时释放、任务 abort 释放、尚未拿到读租约时超时（不得触发网络或遗留等待者），以及切换 socket path source 后的拨号前拒绝。旧 `s04bk_` 同时验证共享真实观测对象时在途网络切换仍拒绝。
- **边界：** 这是**路径规划代际的身份复核**，不是网络 socket 返回的已验证 `NetworkPathId` 或 NIC/源地址证明，也不持有操作系统网络路由锁。检查后到实际打开 socket 之间的网络变化、Connector 私有连接池、当前读租约的写入延迟和性能风险仍有待真实数据面、抓包及取消压测确认；不能凭此开放动态 Provider / 真实严格 DNS 运行入口。可信 pin 来源、完整递归拨号/缓存隔离、L2 独立审查与维护者批准均未完成。**生产 `policy-rules` gate 仍保持关闭。**

## S04b-m：显式 socket 路径证据校验（内部非生产传输）

- 新增 `app/dns/bootstrap_socket.rs`：`StrictDnsSocketPathEvidence` 仅由实际 `BoxedChainedStream` / `BoxedChainedDatagram` 提供的 `network_path_ids()` 捕获物理本地 socket 路径。空集合、过多路径、无效接口/源地址或重复项失败关闭；使用 `OutboundManager` 的相同 `NetworkPathSource`/`SharedNetworkStatus` 复核**当前网络代际**，并逐一比对被观察的 `BindingStatus::Verified` 本地接口、地址族与源 IP。既验证路径来源与请求所属的 Manager 一致，也拒绝不属于当前候选的“貌似有效”路径。此检查不验证代理的远端转发链，也不是操作系统内核的出口证明。
- `DnsStrictSocketPathTransport` 是**显式 opt-in** 的内部传输能力，返回 DNS 应答及同一物理连接产生的证据。`StrictDnsManagerLeafGuard::exchange_with_socket_evidence` 复用前述 registry 租约、选中叶节点/Provider 版本、网络和配置代际 guard；适配器对任何传输或证据错误**终止本次严格查询**，不可转用第二个 DNS 上游或 legacy/DIRECT fallback。**S04b-m 当时**的 `DnsStrictWireTransport` / `DnsStrictPinnedWireTransport` 没有此能力；S04b-n 后已为严格 TCP/UDP 补充从实际连接对象回传路径的能力，仍不能从路由规划或服务器配置凭空生成。S04b-m 离线测试使用带路径 ID 的假 chained stream 验证正确报告、缺失、过期、接口或源地址不匹配及网络在途切换；测试中的假链路并不证明真实 OS socket 绑定。
- **S04b-m 当时未完成：** DNS client/transport 尚未回传 TCP/UDP 的物理 socket 路径 ID（已在 S04b-n 补充 opt-in 路径），Connector 与 TLS/DoH 连接池的端到端身份证明、取消压力测试、真实数据面与抓包验证，以及可信 Provider/pin 来源与独立 L2 审查均未完成。生产 `policy-rules` gate 继续关闭；这一切片不得被用作放开生产严格 DNS 的理由。

## S04b-n：真实 DNS TCP/UDP 客户端的连接路径回传（内部，未启用生产）

- `DnsRuntimeProvider` 在 TCP `connect_tcp` 及 UDP `bind_udp` 建立连接后，从返回的 `BoxedChainedStream` / `BoxedChainedDatagram` 读取 `network_path_ids()`，在 `DnsPathUse.socket_paths` **独立保存实际连接器报告的路径 ID**。它与原用于运行时诊断的 `selected_path.path_id` 明确分离：无法从连接对象证明的路径不会由规划候选填充。包含 DIRECT 选择和指定代理路径；网络/配置代际检查及 legacy DNS 诊断不变。
- `DnsClient` 增加可选 `exchange_with_socket_paths` 接口：仅新建的真实 `DnsClient` 能提供本次连接的 socket ID，其余 DNS client 默认失败关闭。正常 `exchange` 不改变；DNS UDP 如果因截断回退到 TCP，返回**最终 TCP 连接**的路径而不是先前 UDP 的路径。S03 严格传输为每次请求创建新 client，在读取 ID 后仍按既有流程按时清理客户端，防止继承其他请求的连接池路径。
- `DnsStrictWireTransport` 与 `DnsStrictPinnedWireTransport` 实现 S04b-m 的 `DnsStrictSocketPathTransport`，**仅 TCP/UDP 可走证据接口**；DoT/DoH 仍不支持这份证据接口，不能降级到明文或虚构路径。缺少实际 socket ID、来源不完整或最终验证不通过时失败关闭并停止上游重试；普通严格交换逻辑和生产 `policy-rules` gate 仍保持原样。S04b-n 离线测试验证 TCP/UDP runtime 只使用连接报告的 ID，以及一条经过 Hickory DNS TCP 编解码的内存连接可将 ID 传至严格传输，缺少 ID 时拒绝。
- **仍未完成：** 本地 `ChainedStream` 报告的 ID 是连接器侧软件元数据，并非 OS 级 NIC/源地址的最终证明；没有端到端验证实际 proxy connector/UDP socket 绑定、DoT/DoH/连接池行为、真实远端代理和抓包；可信 Provider/bootstrap pin 来源与完整递归依赖图以及独立 L2 审查/维护者批准仍未完成。S04b-n 是内部条件能力，**不可用来解除生产 `policy-rules` 启动保护**。

## S04b-o：ProxyConnector 完成路径来源约束与 UDP→TCP 最终连接归属

- 修复 `ProxyConnector::connect_stream_with_pool_context` 和 `connect_datagram_with_pool_context` 的**规划路径残留风险**：过去只有在内层代理报告非空 `network_path_ids` 时才更新 `NetworkPoolContext.path_id`；如果下层连接实际上未报告物理路径，旧的拨号前规划 ID/网络代际会残留，并可能经由上层 wrapper 误当作完成连接证据。现在两个协议统一调用 `record_connected_paths`，使用最终完成链条的首个报告 ID 和其网络代际**覆盖**上下文；若连接链没有物理路径报告，清空这两个字段，不使用规划候选或上一次连接的信息补足。候选集合仍保留供既有池化资格逻辑检查，业务 DNS 和动态 Provider 生产门禁没有变动。
- `s04bo_proxy_connector_context_uses_completed_tcp_udp_paths_only` 离线回归让真实 `ProxyConnector` 驱动模拟内层出站，分别测试 TCP/UDP 无连接证据与有不同于原计划的实际证据，确认两者都不会泄漏事前候选。`s04bo_udp_truncation_uses_final_tcp_socket_path_not_udp_path` 通过完整的 DNS UDP 截断应答和随后 Hickory TCP DNS 编解码、分别返回不同的连接路径 ID，验证最终应答仅绑定 TCP 连接路径，而非第一阶段 UDP 路径；不打开外网或更改系统路由。
- **限制：** 这些是可离线复现的路径元数据来源/归属测试，并非真实 OS NIC/源 IP 抓包、套接字最终出口证明、动态代理递归拨号证明或并发复用压测。尚需真实 Connector/本地 UDP/TCP 与加密 DNS 池的网络切换压力测试、可信 bootstrap Provider/pin 来源及独立 L2 审查。**生产 `policy-rules` 继续禁用。**

## S04b-p：连接池出借后的网络代际复核与默认连接器证据污染隔离

- `NetworkPoolContext::permits` 增加路径 ID 内部 `network_generation` 与连接所声称代际的一致性要求；新增 `verify_reused_path`，对出借后的连接路径使用**当时重新读取**的可用候选集合及网络代际再次验证。VLESS `try_reuse_transport_stream` 在任何池化 transport 的 `try_reuse_stream_with_pool_metadata` 异步操作返回之后，立即重新询问实际 connector 的 `connection_pool_context`；代际切换、路径不一致、路径已不在可用集合或缺乏所需路径证据时返回 `Interrupted`，不向 DNS/上层交付旧逻辑流，也不偷偷转向其他出口。没有网络观察来源时，仍保留旧的 generation-only 兼容行为；这不是原子性的数据面网络路径承诺。
- 收紧两个通用默认边界：未实现物理路径报告的 `RemoteConnector` 在默认 TCP/UDP `connect_*_with_pool_context` 中抹去 caller 传来的**规划 `path_id`**（代际记录用于已有兼容逻辑），防止上层把它当成拨号后证据；未覆盖 `Transport::connect_stream_with_connector_and_path_ids` 的自建连接传输返回空的物理路径 ID，而不是从连接器调用前的规划上下文复制一份。实现自己的路径证明的 XHTTP 等专用实现仍可覆盖此默认行为。严格 DNS 需要物理证据的接口遇到空集合仍然失败关闭，不开放 `policy-rules`。
- 新增 4 项 `s04bp_` 离线测试：TCP/UDP VLESS 池化流异步取出期间 generation 从 7→8 时拒绝、未变化时允许；不一致的物理路径代际失败关闭；旧式未观测 Connector 的 TCP/UDP 默认方法拒绝规划路径冒充已完成连接；自建连接传输默认报告空 ID，不能从已规划路径生成假的物理证据。另验证既有 VLESS reuse 8 项、gRPC 13 项与 XHTTP 52 项全通过；当前 feature 下 Hysteria2 筛选未命中用例，不能视为完成 Hysteria2 压测。
- **限制：** 重读网络上下文是在归还逻辑流之前进行的复核，不是 socket 建立与物理使用期间的不可中断锁或 OS 级出口证明；旧流建立过程的网络副作用不能撤销。gRPC/XHTTP/Hysteria2 等其他连接池的建立、重用、取消并发仍需独立压力测试，真实网卡/源 IP 抓包、可信 Provider/bootstrap pin、完整逐跳证明、独立 L2 审查和维护者批准仍未完成；生产 `policy-rules` 继续禁用。

## S04b-q：Hysteria2 QUIC 池化复用与建立完成后的代际复核（Feature 显式测试）

- 确认 `proxy::hysteria2` 受 `hysteria` Feature 控制，旧的默认 Feature 测试过滤条件未真正执行其用例。新 `pool_context_is_current` 不再对 `cached.path_id=None` 无条件退化成 generation-only：若当前网络明确提供候选物理路径集合，无报告路径的旧 QUIC 池连接必须拒绝；没有候选集合的遗留连接器仍允许同代际复用。
- 在 Hysteria2 单例 QUIC 池锁取得之后才采集当前网络上下文，避免排队等待期间先前的观测被误用于池内对象；取出旧连接前确认取消令牌未触发。新连接完成认证后、发布到池之前重新采集当前 connector 的路径上下文，并与实际完成连接记录的 `NetworkPoolContext` 及取消令牌复核。若网络已变化，关闭新建的 QUIC 连接并中止 driver task，返回 `Interrupted`，不缓存旧身份。检查不能撤销已发生的握手/网络包，也不是系统级网卡/源地址证明。
- `s04bq_` Feature 专属离线测试覆盖未报告路径而候选集合明确时的失败关闭、连接期间 generation 更新/取消、重复 32 轮在途取消与 future 释放；保留 Hysteria2 既有取消回归。gRPC/XHTTP 在当前切片只做既有回归，不声称已完成其所有网络切换压测。生产 `policy-rules` gate 继续关闭；可信 Provider/pin 来源、实际出口抓包、端到端递归拨号证明以及独立 L2 审查与维护者批准仍待完成。

## S04b-r：gRPC/XHTTP 逻辑流交付边界的取消复核（内部连接池）

- gRPC 的 `proxy_stream_with_pool_context` 与 `try_reuse_stream_with_pool_metadata`、XHTTP 的 `connect_stream_with_connector_and_path_ids`（含启用 H3 时的自建连接分支）、`proxy_stream_with_pool_context`、`try_reuse_stream_with_pool_metadata` 都已有 biased `select!` 监听连接池网络重置的 cancellation token。S04b-r 增加共享的 `finish_pool_delivery`：**在异步 `select!` 返回之后、把逻辑流交给调用者之前** 再检查同一 token。避免流刚好构造完成、同一 poll 内取消已触发时走完成分支而交付过期连接。已取消则返回 `ConnectionAborted`、丢弃成功结果；未取消则保留成功值或真实上游错误，不改重试路径与业务配置。
- 新增 `s04br_` 四项离线测试：刻意在异步成功分支内触发取消，验证最后交付检查拒绝并 `Drop` 成功结果；未取消时成功/错误原样传递；gRPC、XHTTP 各自把池借用者停在恢复读锁前，模拟并发 reset，验证旧令牌取消后借用失败，池重置完成并提供未取消的新令牌。仍使用各自已有 recovery_gate 与 pool reset 机制，无需改变实际网络连接方式。
- **范围限制：** 检查保证的是软件层面交付边界，不能撤销已发出的 HTTP/2/HTTP/3 请求、已建立的底层 TCP/QUIC socket，也不能原子证明最终 NIC/源地址；`tokio::select!` 取消/任务释放与活跃计数仍需大负载下的真实数据面观测。不得据此放开动态 Provider 或生产严格 DNS。可信 Provider/bootstrap pin 来源、完整多跳拨号、真实出口抓包以及独立 L2 审查与维护者批准依然待完成。生产 `policy-rules` gate 保持关闭。

## S04b-s：gRPC/XHTTP 活跃流计数与异步取消释放（内部连接池）

- gRPC 以前仅在 downlink 后台任务完成时减少 `ReusableGrpc.active`；若应用已丢弃逻辑流但服务端一直不返回，计数可能长期占用。新 `GrpcActiveStream` 将活跃名额绑定到**调用者实际持有的逻辑流生命周期**，`Drop` 恰好递减一次，并触发 cancellation token 使 uplink/downlink 后台任务主动退出；不再把递减责任交给可能无限等待的下行任务。gRPC 请求构造失败的分支继续自行归还名额，外层复用错误分支不再重复递减，避免 `AtomicU64` 下溢。注意 Drop 只取消软件任务，不能收回已经发往网络的请求。
- 新增 `PoolActiveReservation` 作用域守卫：XHTTP H2/H3 复用路径在异步构建逻辑流前就已增加活跃计数，若任务在 `await` 期间被 reset/abort，普通的 `Err` 分支不会执行。现在守卫在取消、失败与 future Drop 时自动回退计数；只有成功封装为既有 `ReuseLeaseStream` 后才转交名额所有权。覆盖 XHTTP H2 `try_reuse_stream_with_pool_metadata` 与 H3 `try_reuse_h3_stream`；H3 上传/下载自建连接分支的全部取消所有权仍需后续单独审查。
- `s04bs_` 离线测试覆盖 64 次异步取消时守卫不泄漏计数、gRPC 服务端不回应时丢弃应用流并重复复用、gRPC 非法请求与多次失败复用不发生双减、XHTTP H2 在复用请求已发出且服务端挂起期间取消任务并释放预留名额。保留原有 `s04br_` 网络重置时交付拒绝机制，原有生产 `policy-rules` gate 不变。
- **仍未完成：** gRPC/XHTTP 真正网络连接后台任务与计数的持续高负载压力测试、XHTTP H3 自建 QUIC 链及上传/下载双端全生命周期、系统级物理出口证明、可信 Provider/bootstrap pin、完整 dialer 递归保护、独立 L2 审查与维护者批准。以上不能视作生产严格 DNS 已可开放。

## S04b-t：XHTTP HTTP/3 上传/下载 sender 租约与 QUIC 建立期间取消

- HTTP/3 以前从 QUIC 池取出上传或独立下载 sender 时，会增加 `active`，但仅把 `Option<Arc<AtomicU64>>` 随 sender 返回。若在随后获取另一端 QUIC 连接、等待 H3 请求/响应或逻辑流交付前取消 future，普通错误分支和成功转交路径未必运行，导致活跃名额泄漏。现将 `H3UploadSender.active` 和 `H3DownlinkSender.active` 改为已有的 **RAII `H3ActiveLease`**：任意 await/取消/错误导致其所有权 Drop 时恰好释放一次，成功交付后通过 `into_stream` 转交给实际应用持有的 `ReuseLeaseStream`。同时把 StreamUp/PacketUp 的独立下载活跃计数从可能无限等待的后台下行任务转交给应用流，应用流 Drop 即释放，防止把后台等待时长误当作应用活跃并发。
- `connect_h3_stream` 的上传预留名额在下载端连接或协议建立失败时由租约释放；H3 下载复用和 H3 上传复用都不会因两端分别创建/取消而双减。仅当显式成功封装成应用逻辑流时才转移租约；原有池退休、网络代际与 S04b-r/s 的交付取消检查保持不变。QUIC UDP socket 和 h3 driver 的**真实异步生命周期还需单独证明**：复用池持有的物理 socket 允许在用户逻辑流 Drop 后按池策略继续存活，不能声称此改动立即释放所有网络句柄。
- 新增 `s04bt_` 离线本地 QUIC 端到端测试：实际建立上传和独立下载两个 H3 sender 后，在逻辑流交付前 abort，检查两端 `active` 都归零并可以退休池；实际建立上传后刻意使下载端使用不支持的 TLS 模式而失败，确认上传名额归还。既有本地 HTTP/3 StreamUp 测试加断言：上传/下载池在应用释放逻辑流后均立即归零，不依赖服务端结束后台等待。同时显式以 `--features xhttp-h3` 单独编译和测试，调整仅供 Hysteria2 使用的共享 UDP socket reexport Feature 门禁，避免 XHTTP/3 单独启用触发未使用警告。
- **仍未完成：** QUIC 连接/driver 关闭时机及 OS socket 占用的长期压力、所有 H3 建立阶段的系统级取消路径、物理出口抓包、可信 Provider/bootstrap pin、完整递归 dialer 保护和独立 L2 审查。生产 `policy-rules` 继续严格禁用，不能以这些测试作为上线许可。

## S04b-u：HTTP/3 QUIC 握手到 driver 交接的资源所有权（内部、未启用生产严格 DNS）

- XHTTP H3 `connect_h3_sender` 在 QUIC 握手成功后增加 **`PendingH3Socket` 作用域租约**。租约同时拥有本地 `Endpoint` 和已建立的 `quinn::Connection`，覆盖后续异步读取 Connector 当前网络上下文、验证路由资格及 `h3::client::builder().build` 的全过程。若 future 在任一 await 被取消，或者 HTTP/3 初始化错误，`Drop` 会**主动关闭 QUIC connection 和 Endpoint**；直到 H3 driver 成功建立时才以 `handoff()` 明确转移所有权给现有后台 driver 任务。已完成 driver 交付的健康流及连接池仍按旧生命周期运行，不在普通 pool reset 时强制切断。
- 收紧握手后的网络变化判断：从 `current_context.permits(connected_context.network_generation, connected_context.path_id.as_ref())` 统一验证完成连接代际及当前候选物理路径。即使连接未返回物理路径 ID，在运行时有明确候选路径限制时也不得仅凭同一 network generation 放行；失败时直接返回 `Interrupted`，不改换备用地址重新拨号，租约自动清理该连接。
- `s04bu_` 两项离线本地 QUIC 测试：使用本地 QUIC 服务端和真实 TLS/ALPN 握手，模拟握手后、driver 交付前取消任务，要求远端实际观察到 QUIC 连接关闭；另外验证当前有明确候选集合时，无物理路径报告的 H3 链路不能通过认证。保持独立 `xhttp-h3` Feature 的可构建性，补跑现有 HTTP/3 双端和正常回声测试。
- **限制：** 当前保护覆盖**握手已建立但尚未交接 driver 的资源**。已交付 sender/活跃流后，QUIC driver 的自然退出、连接池退休、可能悬挂的上传/下载后台任务及 OS UDP socket 关闭仍未得到全生命周期压力或抓包证明；关闭连接亦不能撤销此前的 UDP 发包。真实 NIC/源 IP 验证、可信 Provider/bootstrap pin、完整递归 dialer、独立 L2 审查与维护者批准仍待完成。生产 `policy-rules` gate 继续关闭。

## S04b-v：池化 HTTP/3 退休、在途流与 QUIC driver 退出（内部非生产）

- XHTTP HTTP/3 池化连接新增 `H3PooledSocket` 共享生命周期：记录 QUIC `Connection`/`Endpoint`、活跃应用逻辑流计数、退休状态和 driver 完成状态。`ReusableH3` 从池中移除（显式 `reset_connection_pool`、失效的网络路径、时间/重用限额）时标记为 `retired`，不允许再次作为新流的复用来源。若 `active == 0`，立即对 QUIC 连接及 Endpoint 发出关闭；若还有应用流，则允许它继续工作，等**最后一个 `H3ActiveLease` 或 `ReuseLeaseStream` Drop** 后再关闭。后台 driver 同时等待 HTTP/3 空闲和底层 QUIC 关闭，结束时记录状态，防止已退出 driver 的旧 entry 再被复用。注意此实现不能撤回已经开始的请求或系统网络包。
- 新增 `H3PoolRegistration` 作用域守卫，覆盖 driver 已创建、但新上传/下载 sender **正在等待复用池互斥锁登记** 的取消窗口。登记前发生 future Drop 时，自动退休尚未发布的连接；只有实际插入 pool 后才撤销守卫。首次增加 `active` 计数也延迟到持有池锁时，防止因等待锁而留下虚假的活跃计数；不入池的旧式直连行为保持不变。
- `s04bv_` 两项**真实本地 QUIC/TLS+HTTP/3** 离线测试验证：(1) 先退休池后释放活跃逻辑流，以及先释放后退休，均在最后一次 Drop 后使远端观察到 QUIC 关闭并确认 driver 任务完成；活跃逻辑流在池退休后仍可正常读写。(2) 成功创建 driver 后停在新池登记锁，abort 等待者，确认无池 entry、无活跃名额、远端 QUIC 已关闭且 driver 完成。既有 H3 上传/下载、并发限额及网络切换回归继续运行。
- **边界：** 本轮证明有明确池生命周期的 H3 QUIC 连接会在**退休且最后一个逻辑流释放后**关闭并结束后台 driver；不是对任意未池化 H3 socket、操作系统 UDP 文件描述符何时实际回收、强制取消网络副作用、真实 NIC/源 IP 或高负载/系统重连压力的端到端证明。未纳入池的 H3 sender 自有生命周期仍待审查。可信 Provider/bootstrap pin 来源、递归 dialer 全链路及独立 L2 审查与维护者批准尚未完成。**生产 `policy-rules` gate 不变且继续禁用。**

## S04b-w：未池化 HTTP/3 sender 与 Quinn UDP pump 的资源回收（内部、未启用生产 DNS）

- 之前只有进入连接池的 H3 sender 具有 `H3ActiveLease` 和连接所属 `H3PooledSocket`；不配置复用策略或明确禁止建池时使用 `H3ActiveLease::none()`，会在取消请求、单独下载初始化失败、以及应用流释放后丢失唯一应用侧 socket 生命周期信号。现在未池化 sender 持有 `H3ActiveLease::unpooled(socket)`：建立请求期间被取消/失败时，租约 `Drop` 立即退休 QUIC `Connection`/`Endpoint`；正常构建成功则将连接所有权转交应用流，应用流最后一次 `Drop` 触发退休。独立上传与独立下载 sender 各自持有租约并分别关闭，池化连接则保持原有 active 计数、池退休后等待最后一个应用流的行为。复用参数必须按既有语义解释：`max-connections=0` 与正数 `max-concurrency` 并存代表由并发数管理连接池，**不是**禁用池。
- `ConnectorUdpSocket` 以前把拆分的 UDP datagram 收发两半放在两个独立 `tokio::spawn` pump 中，而接收任务可以无限等待 `recv` 并继续持有原 OS UDP socket。现在适配器直接拥有 `send_pump` / `recv_pump` 两个 `JoinHandle`，`Drop` 时明确 abort 两者，使分离的 `Sink`/`Stream` 被释放，不再留下悬挂接收任务和底层 UDP 端口占用。
- `s04bw_` 新增五项本地离线测试：未池化的无复用策略和明确禁止连接池两种 StreamOne 应用流 `Drop` 后远端观察 QUIC 关闭；单独上传、下载两条 QUIC 连接均在流释放后关闭；上传已建立而下载 TLS 配置不支持时失败并关闭上传；取得未池化 sender 后在交付前 `abort`，检查 driver 完成、远端关闭；用真实绑定的 OS UDP socket 验证适配器存活时端口无法重复绑定、销毁后短时内可重新绑定。继续验证现有 QUIC 数据收发及池化 H3 退休测试。
- **限制：** 重绑定是本地 UDP 描述符生命周期的实证测试，非多系统、多接口、真实代理链或长期高并发资源压力验证；关闭已建立的连接不能撤销已发送的数据包，也不能推导真实 NIC/源 IP 是否符合 strict DNS 的宣称。可信 Provider/bootstrap pin 来源、完整逐跳拨号证明、网络切换抓包、独立 L2 审查与维护者批准仍未完成。生产 `policy-rules` 启动门禁原样关闭。

## S04b-x：UDP 真实 socket 的网卡和源地址双重绑定（本机可验证切片）

- 修复 `new_udp_socket` 的原有 `match (src, iface)` 互斥分支：以前非 loopback 目标同时提供指定源 IP 与网卡时，只执行 `must_bind_socket_on_interface`，**漏掉 `socket.bind(src)`**；由此可能让规划的源 IP 与真实 UDP socket 来源不一致，甚至让严格路径选择在 `local_addr` 检查前因未绑定而失败。现在非 Android 路径依次执行所要求的 NIC 绑定与独立的显式源地址绑定，两项操作任何一个失败都传播错误；保留 loopback 目的地跳过**物理网卡**限制、Android 保护处理和 Windows 在没有 `src` 时按接口/通配地址绑定的既有兼容逻辑。没有从路由规划补写物理路径 ID，也未改变 DNS `policy-rules` gate。
- 3 项 `s04bx_` 本地离线测试验证：(1) 使用真实 loopback NIC 让 UDP 建立函数同时执行网卡和 `127.0.0.1` 源地址绑定，32 次独立创建、收发和释放，核对 socket 的 `local_addr` 与接收端真实看到的 UDP 来源完全一致；family hint 指向测试专用非 loopback 地址，仅用于触发平台网卡绑定，**实际数据报只发给 localhost**；(2) 指定本机不存在的测试用源 IP 时，即使 NIC 绑定成功也必须失败，不能悄悄采用系统默认来源；(3) macOS 动态查找当前已配置的非 loopback IPv4 网卡及其实际地址，确认 socket 同时接受该网卡索引与选定源 IP，并检查 `local_addr`，**不对外网发包**。Linux 若 `SO_BINDTODEVICE` 无权限或运行环境没有对应网卡，相关测试有明确条件跳过。
- **仍未完成：** 没有在两个真实物理网卡之间修改路由、进行网络切换或外网抓包，因此本轮不能证明任意远端代理的实际出接口、数据面源地址长期不变或系统内核出口路由。连接器报告的 `NetworkPathId` 仍是软件元数据，真实路径抓包、NetworkPathSource 中途换代及安全故障恢复、可信 Provider/bootstrap pin、完整逐跳拨号图、独立 L2 审查与维护者批准均为生产门禁前置事项。**生产 `policy-rules` 继续拒绝启用。**

## S04b/S04c 待完成的严格准入

1. **真实执行接线与身份来源**：S04b-a 提供共享 RuntimeStatus 读取接口，但**尚未由生产 DNS runtime 自动接入或订阅**；需有可信的 bootstrap pin revision/变更事件来源，而不是由未受验证的调用者提供任意数值。仍需真实数据面验证动态代理在查询中途切换时的失效与回滚；旧 legacy 路径继续完全独立。
2. **引导依赖图完整性**：构建代理组/动态 provider/代理节点自身域名和 DoT/DoH upstream 的真实依赖关系，验证先有稳定可信 bootstrap 再开始拨号，加入运行时强制深度 guard。当前仅显式 pin 传输和工具层拒绝，不接受未审查的隐式系统 DNS。
3. **严格连接/缓存作用域**：若未来为了性能引入连接池，须以与本缓存同样的实际代理叶节点、profile、source-scope、network/config/pin generation 进行独立池化和释放验证。本轮维持**不共享连接池**以保证安全。
4. **扩充 DNS 复杂应答和 ECS/DNSSEC**：在可以正确识别 EDNS 选项及作用域、CNAME、多 Question、CD/DO 与签名相关字段前继续保守不缓存；正负缓存策略不替代已有 legacy RFC 2308 语义。
5. **真实数据面**：可信证书下 DoT/DoH 成功路径、真实远端代理 fail-closed、DNS 出口实际抓包和网络切换/并发压测，依然是撤销 `policy-rules` 运行时 gate 的硬前置条件；独立审查与维护者批准也尚未完成。

**行为承诺**：本阶段没有更改 Business Rules 顺序、业务最终出口、旧 DNS fallback、Fake-IP 处理、旧缓存或默认加密 DNS 行为；不能把 S04a 内部隔离能力写成正式用户可用的下一代 DNS。
