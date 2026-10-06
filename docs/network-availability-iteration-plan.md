# 主机网络变化后的可用性迭代计划

日期：2026-10-06。状态：B0–B6 已完成代码级与受控回归；B7 已接入代理端点/DNS socket 路径，为 gRPC/XHTTP H2 池加入逐连接 PathId 选择性退休，并为 VLESS、Trojan、AnyTLS、SOCKS 和 Shadowsocks 的 TCP 流记录最终目标响应路径健康；Trojan/AnyTLS 的 TCP 承载 UDP 也已接入。XHTTP H3 在无法确认物理 PathId 时禁用池复用。Hysteria2/H3、独立 UDP socket 路径及恢复期间过期拨号边界仍待实现或验证。DIRECT 域名/fake-IP UDP 的真实答案族处理已在 B5 覆盖。B8 的 DIRECT TCP 尝试调度、B9 的被动恢复防抖、B10 的有限运行时偏好与 Explain API 已完成相应代码切片。B11 的双网卡物理切换、route-all、休眠、资源趋势及时间预算仍待专用环境验收。

用户确认的目标：主机切换网卡或网络后，自动恢复新连接；已有连接尽力恢复，无法恢复时明确结束。典型场景包括 Wi-Fi ↔ 有线、同一网卡换 Wi-Fi/DHCP 地址、断网重连和休眠唤醒。服务恢复无需用户重启 Chimera、重新加载配置或手动调用 reset。

现有恢复链路作为后续路径调度的基础，不以完整 Core Domain / RouteEngine 重构为前置工作。原完整重构计划继续暂缓；按当前 macOS 环境逐步验证，平台适配和验证状态分别记录。

## 当前执行计划：Flow、多网卡与双栈（2026-10-02 修订）

本节是当前实施队列；下方 A0–A4 及状态机章节保留为历史基线、已完成证据与未完成验收，不再以其中“下一最小步骤”决定代码执行顺序。原用户目标继续有效：**在用户允许的路径内最大限度恢复新连接；已有连接尽力保留，无法恢复时明确结束。**

设计参考：[Flow、多网卡与双栈设计指南](/Users/adam/Downloads/Chimera_Client_Flow_MultiNIC_DualStack_Rust_Design_Guide_zh.md)。该文档提供设计建议；实施范围由用户关于网络切换可用性、状态机观测和“继续代码直到计划完成”的请求，以及本计划的切片门槛决定。文档中的命令、API 和参数不会自动改变默认行为，也不授权运行主机网络实验、提交或发布。

### 现状与设计之间的差距

| 当前工作区能力 | 与指南的差距 / 迁移方式 |
| --- | --- |
| `Session`、Dispatcher、StatisticsManager 已承载会话与统计 | 不另起全局 Flow 单例；以轻量适配建立只保存事实的 `FlowContext` 和独立决策记录，不携带 Router/Resolver 服务对象 |
| `/flows` 按目标/端口/协议聚合统计 | 不等同于逐会话 FlowRegistry；复用 tracker 身份，明确统计聚合与路径决策查询的关系，保留现有 API |
| UDP 每包路由，NAT socket 按 outbound + client source 复用 | 逻辑 UDP Flow 按入站、源、原始目标和必要身份隔离；决策缓存与 NAT socket 所有权分开，保留 full-cone、多目标及多客户端语义 |
| macOS `NetworkPath` 记录 v4/v6 主路径，其他接口是变化指纹 | 尚非全部网卡 × 地址族候选；补实际地址、接口种类和可路由证据，不能将“接口存在”当作可达路径 |
| typed RuntimeStatus、版本防护、组件 reset 报告与有限真实响应证据 | 尚无逐 Path/目的地健康、policyVersion、路径选择/拒绝理由、持续任务健康；现有 trafficVerified 不能直接升级成路径全局健康 |
| 网络观察与恢复串行，实际接口/mark/TUN 为租约保护的进程级变量 | 先独立观察和提交前版本复核；逐步让每次 dial 使用不可变路径选择，不绕过租约或一次重写全部全局变量 |
| 默认出口恢复、UDP 退休、DNS/协议池 reset 与 TUN 防回环已实现 | 保留并接入新模型；不重复做同一轮 reset，不先启动完整 Router/Core 重构 |

### 冻结的行为契约

1. **Route 与 Path 分离。** Router 决定 DIRECT/代理/REJECT；PathScheduler 决定承载 socket 的接口、源地址和地址族。代理连接的目的地是代理端点；经代理访问的最终网站失败不能直接证明承载路径或代理端点不可用。
2. **事实、意图、决策、执行和证据分离。** FlowContext 保存会话事实；ResolutionResult、RouteDecision、PathPlan、ExecutionResult 分别输出；应用生命周期、任务健康、路径健康和目的地健康分别呈现。
3. **硬约束先过滤。** Preference 允许降级，Require 不允许越界。显式接口和现有 IPv6 开关继续约束候选；偏好列表不是允许列表。合法候选为空则明确失败并记录全部拒绝原因。运行时命令可显式更新意图，但不能由健康优化自行覆盖约束。
4. **默认兼容。** 现阶段保留现有系统选路。指南的 Ethernet IPv4 → Wi-Fi IPv4 → Ethernet IPv6 → Wi-Fi IPv6 作为新策略的可选示例与单元测试输入；不因本次调整计划就认定用户要求换默认。未列出的 VPN/Other 候选按明确、可解释的补全规则处理，禁止通过枚举排序或模糊权重偷偷决定。
5. **版本分别表示。** 保留 configVersion、networkVersion、operationId；新增 policyVersion。环境观测、已应用环境和操作编号不能混为同一个 generation。路径身份包含接口重建/地址变化语义；缓存、池和异步完成结果携带相关版本，配置回滚或失败的 policy 更新不提升已提交版本。
6. **旧 Flow 不被强行迁移。** 偏好更新默认只影响新 Flow；普通 TCP 不重放应用数据、不承诺无缝迁移。已失效 UDP 可按新环境重建，但必须保持响应归属；只退休失效路径关联的资源，初期仍可复用已有保守 reset 并记录其范围。
7. **DNS 路径独立。** 保留 nameserver/policy/direct、bootstrap、防递归和 fake-IP 映射；企业/VPN DNS 不被业务 Flow 偏好隐式改路。首版仅全局策略，不加应用级覆盖、Agent 自动改策略、QUIC/MPTCP 迁移或新 crate。

### 实施顺序与每步门槛

每次选择一个可独立验证的切片；所列文件为现有入口，新文件按职责需要建立，不按指南目录一次搬迁。B0–B6 已完成代码级与受控回归；B7 仍有未完成子项，B8–B10 已完成各自当前明确范围内的代码切片，B11 需要专用运行环境。

| 切片 | 工作范围与入口 | 完成门槛 |
| --- | --- | --- |
| B0 恢复期间持续观察 | `app/network.rs`、`lib.rs`：独立可取消采样，watch 只保留最新快照，恢复提交前复核；最多两轮实际恢复，持续变化后明确 degraded 并退避 | A→B 未结束又到 C 时拒绝 B 成功并恢复 C；持续抖动有界；采样错误可见；sampler 随 shutdown 取消。reload/shutdown 场景和真实 macOS 采样仍待实机验收 |
| B1 长驻任务监督（已完成） | `lib.rs`、inbound/DNS/TUN/API runner 与 `runtime_state.rs`：报告 readiness、存活、退出和错误；必要/可选组件明确区分；不自动无限重启 | readiness 有界；任务异常在 `/runtime` 可见并使总健康降级；控制循环返回或 panic 都进入错误路径而不让顶层永久等待；可回收的 API、数据面和采样任务停止并 join |
| B2 最小 Flow / Path / Intent 模型（已完成） | `app/flow.rs`、Dispatcher/tracker：只读适配 FlowId/FlowContext、path 身份、family/kind、policy snapshot、plan/decision 类型 | TCP 原始入站目标、逻辑目标、解析地址及身份分别保留；UDP 聚合 tracker 不冒充单目标 Flow；模型不依赖运行时服务；未启用 scheduler 时现有路由、DNS 时机及 API 行为不变 |
| B3 环境与候选观察（已完成） | macOS `networksetup` / SystemConfiguration、`app/network`、`socket_helpers`：观测每个接口地址族、系统主路由证据与真实本地绑定能力，候选只读输出 | Ethernet/Wi-Fi 同时在线、双栈拆分、同接口换地址、IPv6 scope、VPN 和接口重建均有受控用例；排除自身 TUN 回流，未知种类不猜成 Ethernet；其他平台能力明确 |
| B4 策略编译与影子决策（已完成） | 纯候选过滤/显式排序、immutable intent、PathPlan、CandidateRejection；影子计算复用实际路由结果 | Require Ethernet/IPv4 无满足项必失败；偏好仅列 v4 不禁 v6；偏好顺序与源地址身份可测试；决策记录 route/rule、拒绝理由和 `shadowOnly`，不改变 socket。实际 socket 路径统一回报由 B5/B7 接入 |
| B5 非 TUN DIRECT 新 Flow 接入（已完成） | TCP 按解析地址族选路；UDP literal 或可解析域名按真实地址族选路，逐 Flow 决策缓存，NAT socket 按 `NetworkPathId` 隔离 | 实际 source/interface 绑定与决策一致；硬约束失败明确结束 TCP/UDP；fake-IP 不作为远端地址或族提示；同目标复用决策、不同目标/身份隔离；旧网络代际 socket 退休；多目标/多客户端响应归属保持。活动 TUN 仍沿用当前防回环 socket 保护 |
| B6 非 TUN DIRECT 健康证据（已完成） | TCP、literal/resolved-domain UDP 和 DNS direct 响应/发送错误接入独立健康记录；API 输出有界状态，不改变选路 | 单目标拒绝/超时不判死路径；不同主机网络错误升级；UDP 响应归回实际远端目标；DNS 成功证据绑定上游 PathId；旧版本/重载事件拒绝 |
| B7 代理 / DNS / 池接入（进行中） | 代理端点与最终目标、DNS 独立意图；接入实际 socket 路径；给可复用连接记录实际 path/network 代际 | 已实现非 TUN 代理端点和 DNS direct socket 路径选择、DNS 响应健康证据、VLESS/Trojan/AnyTLS/SOCKS/Shadowsocks TCP 最终目标响应路径证据、gRPC/XHTTP H2 按 PathId 选择性退休；仍需 Hysteria2/H3、独立 UDP socket 路径证据和并发边界回归 |
| B8 有界多路径尝试（DIRECT TCP 范围已完成） | 有界 AttemptBudget、错峰启动、单 winner、取消与清理；代理协议握手竞速另作为后续子切片 | DIRECT TCP DNS+拨号总预算 5 秒、最多 3 次/并发 2、120ms hedge，快速失败立即推进；禁止候选不尝试；失败 socket future 随 winner 取消；不竞速 UDP 业务包或重放应用数据。代理端点竞速尚未接入 |
| B9 首选恢复与防抖（被动证据范围已完成） | cooldown、真实流量响应和稳定窗口；只改变新 Flow 候选可用性 | 冷却期排除不可用路径；恢复至少 3 次真实响应且跨越 15 秒；单次成功不恢复；不发送面向猜测目标的合成探测。主动探测与 minimum-dwell 校准不在当前实现范围 |
| B10 运行时意图与 Explain API（有限范围已完成） | 基于现有鉴权开放偏好更新、effective-paths 和 decision 查询；临时覆盖使用单调时钟及 TTL | 偏好更新校验后在 RuntimeStatus 锁内原子替换并增加 `policyVersion`；临时覆盖到期恢复基础偏好；API 集成测试覆盖写/读/过期/删除；Explain 记录有界且当前只覆盖 DIRECT TCP，代理、失败拨号和重载保留语义尚未完整 |
| B11 实机与平台验收 | 保留 A4 的专用双网卡验证；DIRECT/代理/DNS、双栈/TUN、资源趋势与时间预算 | 不使用 reset 的物理切换、DHCP、离线/唤醒和抖动有真实响应证据；20 轮资源回收可核查；macOS/Linux/Windows 各自记录编译、受控测试与实机结果 |

依赖：B0 → B1 → B2 → B3 → B4 → B5 → B6；B7 的协议/池子切片继续推进，B8 DIRECT TCP 已基于 B5 的 PathPlan 独立验证，B9 消费 B6 的真实流量健康证据，B10 读取并更新运行时 PathIntent；它们不表示 B7 全部已完成。B11 依赖可达的专用多网卡环境。不得把未验证前置标成完成。可取得专用硬件时，既有 A4 基线验收提前运行，不必等 B11；它不能替代新 scheduler 的实机验收。

B5 在执行前已检查 OS 明确不可用状态，B6 才加入被动健康推断。B4 影子观察仅为短期迁移验证，不新增 old/new Cargo feature；启用真实调度并完成对照后移除重复影子执行，保留可查询的最终决策。B10 写 API 最后开放，期间可用 fixture 注入 intent 测试，读侧解释记录随各步实现。

B5 的 UDP 决策缓存设容量与 idle TTL；明确 network/config/规则提供器版本、认证身份变化及失效后的重新决策规则，原始域名/fake-IP 与解析后的地址分别保存。偏好更新默认不打断仍有效的 UDP Flow；其路径失效或 Flow 超时重建时采用新策略。避免为了缓存规则把本可分开的目标或用户合并成一条 Flow。

B10 首版运行时覆盖不落盘，记录来源、创建/到期时间与生效版本；持久化另列后续需求。优先级为显式运行时命令、持久配置约束、偏好、健康优化、默认；命令只改变显式指定的维度，单纯改 preference 不解除已有 Require。重载时临时覆盖是否保留与配置约束冲突如何处理必须在 API 开放前冻结并测试，禁止默默放宽限制。

### 观测设计与验收证据

每个 PathSelected/SelectionFailed/Switch 记录 FlowId（适用时）、from/to、reason、trigger、config/network/policy/operation 版本、候选拒绝理由、时间和实际执行结果。先复用现有 tracing 与有界状态记录，确有多个消费方再抽事件通道；不为了图示先搭建通用 EventBus。

区分“新 Flow 改选路径”“UDP 失效后重建”和“协议实际迁移”，不把不同 Flow 的选择称作旧 TCP 切换。观察阶段为 Unknown/Available/Unavailable，真实响应作为带目标/路径/时间/版本的证据；unknown 不冒充 healthy。目的地、Flow 和事件记录限量、到期释放，API 沿用鉴权，日志不输出代理凭据或完整配置。

指南示例的 100ms hedge、1500ms total、3 次成功 + 15 秒稳定仅为待校准参数；原 2 秒检测/15 秒新连接/30 秒旧连接亦保留为待验收目标。预算要区分采样、资源恢复、DNS、连接和协议握手，不能将普通 connect 成功当作完整业务响应。

最低测试集包含：恢复期间连续新环境、控制任务退出、候选硬约束、偏好缺项、IPv4/IPv6 分离、UDP 决策缓存隔离、路径实际绑定、目的地失败隔离、旧版本健康/池结果拒绝、winner 取消、无业务数据重复、防抖、policy 更新/到期/重载与真实响应。

每步先跑实际影响的 package/feature 与非零定向测试，保留第 5 节相关集成入口；新增用例后记录完整命令和数量。涉及公共 socket/跨组件接口时扩大到默认核心/CLI、支持的最小组合、协议组合及受支持平台检查。精简 feature 的现有失败继续记录，不用启用无关 feature 掩盖。真实网络/TUN 测试仅在明确的隔离或专用环境运行。

### B1 实施与本轮验证（2026-10-02）

- `/runtime` 和 `/network` 的快照新增 `application.health` 与固定组件状态列表：`control`、`api`、`dns`、`inbound`、`tun` 可呈现 `starting`、`ready`、`notConfigured`、`failed`、`stopped`，并给出 `required`。控制循环始终为必要任务；其余组件在配置启用时必要、未配置时标为可选。故障保留受控错误文本和状态变更时间。控制循环每两秒巡检已启动的长驻 listener，异常退出记录日志并将整体健康降为 `degraded`，不做自动无限重启。
- API、DNS、TUN、inbound readiness 等待上限为 30 秒；inbound 启动协调任务现在有句柄并可取消/join。启动失败会记录具体组件；reload 成功或回滚成功后刷新活动组件状态。
- 顶层同时等待关闭信号与控制任务退出。控制循环正常关停和返回错误都统一取消并 join API、DNS、TUN、inbound；panic 会转成错误后执行同一收尾路径。网络 sampler 仍随根取消 token 结束。新增可控测试覆盖控制任务提前结束、取消、panic，以及组件失败导致状态降级；已有 DNS bind failure 和 inbound fail-fast 测试继续验证错误分支。
- `/runtime` 的 DIRECT UDP 集成断言 `control`、`api`、`inbound` 为 `ready` 且应用健康为 `healthy`。没有执行真实 DNS/TUN 故障注入或系统接口切换；各 runner 的持续退出状态由同一类型化状态路径报告，平台端到端仍留待专用验收。
- 验证：`cargo test -p clash-lib --lib --all-features --locked` 为 768 passed、11 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test api_reload_tests --locked -- --test-threads=1` 为 3 + 4 passed；`cargo test -p clash-lib --test api_tests --locked test_get_set_allow_lan -- --exact` 单测通过；`cargo check -p clash-lib --all-features --locked`、`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。
- 完整 `api_tests` 串行运行曾为 7/8：`test_get_set_allow_lan` 在随机 SOCKS 端口重绑定时偶发 `Address already in use`；同用例单独运行通过。记录为集成测试端口冲突，未把整组失败隐藏为通过。
- B3 完成后已进入 B4；B4 完成后，下一最小代码步骤为 B5：先接入 DIRECT TCP 新 Flow 的实际 socket 绑定，再扩展 UDP。

### B2 实施与本轮验证（2026-10-02）

- 新增纯数据模型 `app::flow`：FlowId 复用现有 tracker UUID；FlowContext 不持有 Resolver、Router 或其他运行时服务；NetworkPathId 分开表达接口 index、地址族及 network generation；接口种类保留 `Unknown`，不从接口名猜测；NetworkIntentSnapshot、PathPlan 和 PathDecision 分别携带 policy/network generation，决策记录选择原因和候选拒绝理由。
- TCP Dispatcher 在 fake-IP 反查前保留 inbound destination，并在 tracker 注册时同时保存原始入站目标、反查后的逻辑目标、已有 resolved IP、协议、入站类型、来源、进程名及认证用户。原 TrackerInfo JSON 使用 `serde(skip)` 隔离该内部字段，现有 `/flows`、统计和 route 行为不变。
- UDP Tracker 当前代表 outbound + client source 的 NAT 聚合，可能转发多目标、多用户数据包；因此没有把这个聚合对象错误标成单目标 Flow，也没有改变 NAT/session 复用。未来 UDP Flow 身份须在逐目标决策缓存切片中定义。
- Path/Intent 类型当前只是可序列化的纯模型；没有接入观察器、候选过滤、socket 绑定或运行时 API，`policyGeneration` 尚无运行时来源。系统仍使用既有 DNS 时机、路由和选路行为。
- 验证：`cargo test -p clash-lib --lib --all-features --locked` 为 771 passed、11 ignored；`cargo test -p clash-lib --lib app::flow::tests --no-default-features --locked` 为 2 passed；`cargo test -p clash-lib --lib flow_context_tests --all-features --locked` 为 1 passed；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。真实网络环境及 TUN 未在本切片操作。

### B3 实施与本轮验证（2026-10-02）

- macOS 快照枚举每个非 loopback 接口的单播源地址，按 IPv4 / IPv6 建独立候选；读取 SystemConfiguration 的 IPv4 / IPv6 主默认接口与 gateway 作为路由证据。候选明确区分 `primaryDefaultRoute`、`otherInterface` 和 `noPrimaryRouteObserved`；后两者仅说明不在系统主默认路由上，不能据此断言任意目的地无路由。
- 使用 `networksetup -listallhardwareports` 把明确的 Wi-Fi / Ethernet 硬件端口映射到设备名；Unknown 保持 Unknown，分类命令最多等待 500ms，失败只降级种类信息，不阻止接口观察。IPv6 link-local 候选携带接口 scope/index。
- `socket_helpers` 为每个候选临时创建 UDP socket，绑定接口和源地址后立即释放，绝不 connect 或发送数据。`binding=verified` 只证明当前进程能完成本地绑定，不代表路径可达。绑定与链路种类属于诊断元数据，变化会刷新 `/network` 与 `/runtime` 的 `pathCandidates`，但不会提升 `networkVersion` 或触发 recovery。对候选上限 128，超出数量通过 `pathCandidatesTruncated` 报告；DNS 配置内容不随路径诊断输出。
- TUN 配置提供精确设备名时只排除自身接口；通过外部 FD 启动而名字未知时保守排除 `utun*` / `tun*`，状态以 `tunCandidateExclusion` 说明。这个保守模式可能同时隐藏用户 VPN 候选；拿不到 FD 对应接口的精确身份是剩余限制。TUN 关闭时 VPN 接口可见但类型为 Unknown，不会因 `utun` 名称猜成 VPN 或 Ethernet。
- 用可控接口清单覆盖 Wi-Fi/Ethernet 并存、IPv4/IPv6 分离默认路由、link-local scope、已知/未知 TUN 排除、用户 VPN Unknown、source bind 失败和接口 index 重建；另有一个默认忽略的 macOS 本机 smoke test，读取当前接口并绑定临时 UDP socket但不发流量。该本机检查通过；没有两张物理网卡的真实切换证据，留给 B11。
- 验证：`cargo test -p clash-lib --lib --all-features --locked` 为 776 passed、12 ignored；`cargo test -p clash-lib --test api_reload_tests --test direct_udp_integration_tests --locked -- --test-threads=1` 为 4 + 3 passed，之后为新增 `/runtime.pathCandidates` API 断言单独重跑 DIRECT UDP 3 passed；`cargo test -p clash-lib --lib app::network::tests::live_macos_snapshot_reports_local_bind_capabilities --all-features --locked -- --ignored --exact` 为 1 passed；`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过。

### B4 实施与本轮验证（2026-10-02）

- 新增纯策略编译器 `app::path_policy`，输入有界 OS 候选、不可变 intent、network generation、真实 Router/mode 生成的 outbound/rule，以及可选的出站端点地址族；输出 PathPlan 与 PathDecision。Require 对候选做硬过滤并逐项保留 intent index 拒绝原因；Prefer 按输入顺序尝试，缺少首选时继续回退；默认选择只接受系统 primary-default-route 证据，没有证据或出现等价候选时明确返回 `noDefaultRouteEvidence` / `ambiguous*`，不靠接口枚举顺序猜路。
- `NetworkPathId` 纳入源地址，使同接口、同地址族的多个源地址候选仍有唯一身份。偏好不是允许列表；例如只偏好 IPv4、当前仅有 IPv6 默认路径时仍可选 IPv6。显式约束无满足候选时绝不越界回退。
- TCP Dispatcher 在连接前从 RuntimeStatus 短暂克隆当前候选，锁在纯计算前释放；结构化 debug 记录携带实际 outbound/rule、policy/network generation、地址族提示、候选拒绝/选择理由和 `execution=shadowOnly`。DIRECT 仅在连接目标是 IP literal 时提供 family hint；代理连接不从最终网站地址推断代理端点地址族。此阶段没有把影子选择传给 socket，所以现有路由、绑定和拨号行为保持原样；统一的实际 socket path 回报留给 B5/B7。
- 验证：`cargo test -p clash-lib --lib --all-features --locked` 为 783 passed、12 ignored；覆盖 Require 交集失败、Prefer IPv4 缺项后 IPv6 回退、显式顺序胜过候选输入顺序、代理不继承网站地址族、bind 失败拒绝、DIRECT literal 地址族过滤及多源地址 ID 唯一性。`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。
- 未执行真实双网卡切换；没有运行 TUN 或改变主机网络。当前 policy generation 仍为默认 0，运行时 intent 更新及其版本提交属于 B10；B5 TCP 的 stale network generation 和硬约束失败边界已在本切片处理。

### B5 完成：非 TUN DIRECT TCP/UDP 新 Flow（2026-10-02）

- Dispatcher 对 DIRECT outbound 为 IPv4、IPv6 分别编译 PathPlan，并把当前 Router/mode route、policy/network generation 和选择依据写入结构化 debug。活动 TUN 或平台没有自动候选观察时保持既有保护/拨号流程；当前真实候选来源只在 macOS 提供。
- Direct TCP connector 在 DNS 返回地址后按地址族取对应路径；选中路径时同时绑定 interface index 与具体 source address，并核验成功 socket 的本地地址。解析出 v4/v6 双栈时分别使用匹配路径。无硬约束的缺族路径保留系统拨号行为；显式 interface 要求缺少对应族候选时跳过该地址，不能越界回退。旧 networkVersion 上完成的连接会立即关闭，不进入应用数据转发。
- Direct UDP 的 literal-IP 直接使用地址族；域名在 fake-IP 反查后通过与 DIRECT 一致的 resolver 取得实际 A/AAAA 地址，再按地址族编译路径，不把 fake-IP 当远端地址或族提示。仅选中路径时建立健康 proof，域名 Flow 的路径/目标健康证据记录实际 connect destination，保持真实地址族信息。逐 Flow 决策键包含 outbound、入站类型、客户端源、进程/用户身份、原始与逻辑目标、session/network/policy 代际；缓存每个入站 UDP 会话最多 1024 项并以 10 秒 idle TTL 清理。NAT socket 仍按 outbound + 客户端源 + `NetworkPathId` 复用：同路径不同目标保持 full-cone 多目标语义，不同路径分 socket；网络代际变化清理旧 socket，拨号前后拒绝旧代际结果。硬 interface 约束无法满足或无法绑定时，明确结束该 UDP association。
- Direct handler 为被选路径绑定 interface 和具体源地址，并验证 socket 本地地址。受控回环测试覆盖 TCP/UDP 源地址绑定、双栈 TCP 解析按族选择、硬约束失败、多路径 NAT socket 隔离、目标/用户缓存隔离与 TTL。没有修改主机路由或切换物理网卡。
- 验证：`cargo test -p clash-lib --no-default-features --lib direct_tcp --locked` 为 2 passed；`cargo test -p clash-lib --no-default-features --lib direct_udp_selected_path_binds_its_source_address --locked` 为 1 passed；`cargo test -p clash-lib --lib --all-features --locked` 为 787 passed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1` 为 3 passed，包含 20 轮网络代际 socket 重建、多目标和多客户端隔离；`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-lib --all-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过。
- B5 已覆盖非 TUN DIRECT 的 literal-IP 与可解析域名/fake-IP UDP 真实答案族选择；活动 TUN 继续沿用现有防回环 socket 保护，不宣称已接入新 scheduler。自动候选观察目前只有 macOS 实现；实机双网卡切换仍留给 B11。

### B6 完成：非 TUN DIRECT 路径与目的地健康证据（2026-10-02）

- `/network`（与 `/runtime` 共用的 `RuntimeStatus`）新增 `pathHealth` 和 `destinationPathHealth`。TCP literal-IP 拨号结果关联路径和目标；UDP 每包 proof 随 NAT 队列传递，响应按远端源地址回查目标后才更新。对于 DIRECT 域名/fake-IP 流，路径规划基于真实解析答案地址族，健康 evidence 使用实际 connect destination。DNS direct 成功证据来自所用上游响应并标记其实际 socket PathId。共享 full-cone socket 上不同目标回包不会互相污染。活动 TUN 的新 scheduler 与代理协议握手证据尚未接入。
- 收到非空远端响应将路径标为 `available`，并在目标表更新该目标。DIRECT TCP connect 失败只把对应目标标为 `unavailable`；`ConnectionRefused`、认证等目标侧错误不会判死整条路径。`AddrNotAvailable`、`HostUnreachable`、`NetworkDown`、`NetworkUnreachable`、`TimedOut` 只有在 30 秒内来自至少三个不同目标主机时才将路径标为 `unavailable`；同一主机的不同端口不算独立证据。新真实响应可把路径和对应目标恢复为 `available`。
- 健康表最多保留 128 条路径、256 条路径/目标项，5 分钟无活动过期；失败仲裁每路径只保留三个不同目标的单调时钟记录。目的地主机不以明文序列化，API 使用进程内随机 ID。网络快照变化与配置成功重载清空旧状态，异步证据必须匹配当前 operation/config/network token；健康表目前仅用于观测，尚不改变候选过滤或选路。
- 单测覆盖单目标拒绝只降目标、多主机网络失败升级路径、响应恢复、旧 token 与旧路径 generation 拒绝、5 分钟 TTL、健康表容量淘汰、UDP NAT 回包目标归属、proof 队列上限/TTL 及 proof 只报告一次。健康证据只观测、不改变候选过滤；B5/B7 已接入非 TUN DIRECT 域名/fake-IP 与 DNS 证据，活动 TUN 和代理协议握手仍未接入。B9 将健康状态用于新 Flow 的可用候选，并始终服从用户硬约束。

### B7 首段：代理服务器端点与 DNS socket 选路（进行中，2026-10-02）

- `OutboundManager` 为代理的 `RemoteConnector` 共享一个延迟绑定的网络状态来源。初始运行和配置重载在 Dispatcher 开始服务前，将当前 `RuntimeStatus` 接到新建的 outbound 图；connector 不捕获配置构建时的旧网络快照。
- 普通代理及 dialer-proxy 的底层 DIRECT connector 对代理服务器域名解析出的每个 IPv4/IPv6 地址独立编译路径。自动选路只使用唯一的系统主路由证据；代理配置的显式接口作为 `Require`，观测不到可绑定候选时明确失败，不切换到另一接口。成功 socket 核对本地源地址，并在返回前复核 networkVersion，过期连接被丢弃。
- 当前实际应用范围为自动观察支持的平台、非 TUN 代理端点；活动 TUN 继续走既有 socket protector / 接口保护流程，避免旁路保护或回流。未附着状态、其他不支持自动观察的平台也保留现有拨号路径。Linux mark、DNS bootstrap 与现有代理协议 connector 链仍沿原参数传递。
- DNS direct transport 在 socket 实际创建后记录路径与上游端点，只有收到 DNS 响应才产生成功证据；连接建立失败按实际选中路径上报。它不把最终解析出的业务地址当作 DNS 上游路径，也不改变 bootstrap/rule 防递归。B5 已覆盖 DIRECT UDP 域名/fake-IP 的真实答案族选择，并将目的地证据关联到实际 connect address。代理端点 socket 暂能按解析地址族选出单条路径并在旧 networkVersion 拒绝连接；端点首响应路径证据已接入，但代理协议认证/握手成功及最终业务流量仍未纳入逐 Path 健康证据。
- 代理 endpoint 的实际 socket 在绑定了观察到的路径后，会以 `ProxyEndpointHealthStream` 记录 endpoint 地址、PathId 和首个非空远端响应；读写失败也按实际绑定路径上报。新增 `proxyEndpointTcp` 明确表示代理服务器端点返回了字节，不代表代理认证成功或最终网站可用；没有明确可绑定路径的系统路由 fallback 不伪造路径证据。
- `OutboundManager::get_outbound_for_new_flow` 会在新 Flow 借出代理前检查 network generation，并串行、全局退休上一代全部可复用连接；reset 失败时不推进已退休代际，后续查找会重试。这避免普通新 Flow 复用上一代连接，但目前没有逐连接 PathId，不能只退休失效路径池并保留其他仍健康的池；已经越过代际门槛的并发 Flow 仍靠恢复期取消和拨号完成后的版本检查收敛。因此 B7 整体保持进行中。
- 本轮增量给 gRPC 与 XHTTP 的可复用 H2/H3 连接写入创建时的 network generation；VLESS 借出时只选当前代际，XHTTP 上传、独立下载和 H3 池也按代际隔离，旧代条目会在查找时退休。代理 connector 把底层当前代际传递到 VLESS。回归 `grpc_pool_rejects_a_connection_from_an_older_network_generation` 和 `xhttp_h2_pool_rejects_a_connection_from_an_older_network_generation` 均验证旧代不被借出。该实现仍是代际级保护，不包含每连接 PathId；同一代内的路径切换不能选择性保留其他 NIC 的池。
- 验证还包含 `proxy_endpoint_response_reports_the_bound_path`：真实响应会生成带 endpoint 地址族和实际 path 的 `proxyEndpointTcp` 证据；以及 `stale_pool_generation_resets_once_and_retries_after_failure`：上一代池在新 Flow 前全局退休，失败不会推进代际。

### B8–B10 当前代码切片与验证（2026-10-02）

- **B8 DIRECT TCP 有界调度**：直接 TCP 在一个 5 秒总 deadline 内解析 DNS 并最多执行 3 次 socket 尝试，同时最多 2 个并发，错峰 120ms。首选绑定失败即推进下一候选；偏好候选都失败后，仅非硬约束可尝试系统路由。胜出后丢弃未完成尝试；不会复制或重放应用数据。严格 Require 不会回退系统路由。成功时回报实际 winner 的 `NetworkPathId`；多候选全部失败不会把健康失败错误记到未实际胜出的路径。当前 scheduler 仅用于非 TUN DIRECT TCP；代理端点握手、多 UDP 竞速都不在实现范围。
- **B9 被动恢复与防抖**：路径达到 unavailable 后 30 秒冷却；冷却内新 Flow 排除该路径，冷却后允许真实业务流尝试。恢复需要至少 3 个成功响应，且首次至第三次跨越至少 15 秒；这些响应尚未要求来自不同目的地主机，路径级失败会清零恢复进度。当前不产生主动探测包，避免探测任意/猜测的公网目标；代价是空闲的备用路径无法靠自身探测转为 available，只能由真实 Flow 提供恢复证据。此能力仅影响新 Flow 候选，不迁移稳定 TCP。
- **B10 偏好与 Explain API**：在既有 Controller 鉴权下提供 `/runtime/network/path-preference`（GET/PUT/DELETE 临时覆盖）、`/runtime/network/effective-paths` 和 `/runtime/network/path-decision/{flow_id}`。接口验证接口种类、重复项、条数和 TTL 后原子提交并递增 `policyVersion`；临时 TTL 为单调时钟，范围 1 秒至 24 小时，最多 16 个偏好项。显式接口 Require 仍先于 preference，偏好不构成 allow-list；重载不会将偏好写入磁盘。Explain 记录容量 256、存活 5 分钟，当前仅由 DIRECT TCP 记录 route/rule、版本、候选/拒绝、winner 和原因；代理、UDP、失败拨号、运行时重启后的持久查询仍不覆盖。
- 回归覆盖代理 endpoint 首响应映射实际路径、旧池按网络代际清理、DIRECT 多路径在首选 bind 失败后推进、Require 不回退、DIRECT UDP 域名解析族和健康 evidence 使用实际 connect endpoint、单次成功不足以恢复、3 次/15 秒恢复阈值、冷却与 API 临时覆盖/版本/有效路径查询，以及 gRPC/XHTTP 旧代连接池拒绝。最近全量实际验证：`cargo test -p clash-lib --lib --all-features --locked` 为 812 passed、0 failed、12 ignored；新增旧代用例过滤 `cargo test -p clash-lib --lib older_network_generation --all-features --locked` 为 2 passed，代际查询过滤 `cargo test -p clash-lib --lib network_generation --all-features --locked` 为 5 passed；`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。更早针对 DIRECT、API、endpoint 证据和池重置的定向检查结果仍见各切片记录。
- `cargo test -p clash-lib --lib --no-default-features --locked` 曾尝试但失败：该全量测试组合包含关闭 TUN/XHTTP 后不适用的测试，并触发 TLS provider 初始化冲突；不据此把该 feature 组合标作完整测试通过。无默认 feature 的生产代码编译和本轮 DIRECT TCP 定向测试均通过。
- `cargo fmt --all -- --check` 与 `git diff --check` 在本段记录写入前已针对代码通过；文档修改后会再次运行两项检查。

### B0 实施与本轮验证（2026-10-02）

- `app/network.rs` 的独立 sampler 以一秒周期读取有 2 秒 deadline 的快照；`watch` 容量为 1，仅保留最新采样，并记录单调序号和采样时刻。采样错误继续上报，取消时会中止当前采样 future 并退出。
- 控制循环消费采样结果，资源恢复不阻塞 sampler。恢复提交前只接受操作开始后完成的最新采样；环境变化则将已完成的旧操作记为 `superseded`，封存于有界 `operationHistory` 后，在最新环境重试。连续变化最多执行两轮资源恢复，仍变化则报告 degraded 并进入已有退避，避免网络抖动造成无限同步重试。
- `/network/reset` 的等待上限从 30 调整为 45 秒，以覆盖最多两轮各组件独立 deadline 和一次新快照；现有组件各 7.5 秒，合计约 15 秒/轮。
- 新增屏障测试覆盖恢复挂起时新环境到达后再次恢复并验证版本；持续切换测试验证两轮上限；采样测试覆盖 latest 合并、过期样本丢弃、序号及取消。测试使用注入快照，不操作主机网络。
- 实际验证：`cargo test -p clash-lib --lib --all-features --locked` 为 764 passed、11 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test api_reload_tests --test api_tests --locked -- --test-threads=1` 为 3 + 4 + 8 passed；`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。
- 代码级回归不等于 macOS 真实 sampler 在双网卡切换中的端到端验收；B1 监督也不替代真实 DNS/TUN 故障和平台运行验收。

## 1. 基线与已有能力

本地 Chimera 基线为 `3b0618165a657bd206378e203f22ed6ced4150e5`，本地 `ref/` 为 `39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`。仅以本地检出作为参考。本轮修改计划前已查看 `git status --short`；已有子模块、AGENTS、Nix 和脚本改动保持原状。

| 当前源码 | 已核实的能力与限制 |
| --- | --- |
| `app/net/mod.rs` | `init_net_config` 写入默认出口状态；macOS TUN 无显式接口时选择并保存物理接口。`get_outbound_interface` 按地址/名称优先级排序接口，不能据此认定选中了当前有效默认路由 |
| `proxy/utils/socket_helpers.rs` | socket 选择显式接口或保存的默认接口；Linux/Windows 部分路径已有按目的地选路，需保留平台差异 |
| `app/api/handlers/network.rs` | 已有 `POST /network/reset`，依次重置 DNS transports 和 outbound pools；此函数不更新默认出口接口、TUN 路由或 Dispatcher UDP 会话 |
| `app/dns/resolver/enhanced.rs` | `reset_transports` 涵盖 main/fallback/proxy/policy/direct，并清理普通 reverse lookup cache；不能当作更新所有 DNS 配置或清理所有 DNS 缓存 |
| `app/dns/dns_client.rs` | `reset_transport` 释放客户端、取消后台任务，并标记下一次重建刷新上游地址；仍需核查捕获的旧接口信息 |
| `app/dns/dhcp.rs` | 有 lease / interface TTL 检查，但持有接口对象；不是通用的主机网络事件监听器 |
| `app/outbound/manager.rs`、`proxy/mod.rs` | 有去重后的 connection-pool reset；trait 默认实现返回 0，不能认定所有协议都已覆盖 |
| `proxy/hysteria2/mod.rs` | 已覆写 reset，关闭缓存 QUIC 连接并清理其 UDP session；不等于现有流可迁移到新网络 |
| `proxy/tun/routes/`、`lib.rs` | 已有平台路由、启动/重载、取消与网络独占租约；动态恢复需遵守这些生命周期 |

上述为实施前基线核查；实际实现与验证见第 7 节。已有手动 reset 和平台 socket 保护应优先复用，不重新实现一套平行运行时。

## 2. 恢复契约

1. **新连接恢复优先。** 稳定且可达的新网络出现后，DIRECT TCP/UDP、所配置代理 TCP/UDP 和真实 DNS 查询恢复；只得到 fake-IP 答案或看到接口 UP 不算端到端可用。
2. **已有连接尽力保留。** 未受影响的 TCP 不因每条事件全部断开；确已失效的连接在有限时间内退出并通知客户端。不能把新建普通 TCP socket 当作续传旧 TCP，也不能自动重放已经发送的应用字节。
3. **离线是可表示的状态。** 没有可用物理路径时等待网络，失败请求有超时，重试退避；网络恢复后继续收敛，不要求重启进程。
4. **自动出口与显式绑定不同。** 未指定接口时跟随有效物理路径；用户指定 `interface-name` / 接口 IP 时保留绑定意图。指定接口消失应明确报告不可用，恢复后重试，不能静默改走另一网卡。
5. **DNS 按配置恢复。** 系统/DHCP 派生的 DNS 信息需要重读；显式 nameserver/policy/direct 配置保留。重建受影响 transports、bootstrap 地址及网络相关失败缓存；保留 fake-IP ↔ domain 映射，避免让应用已获得的 fake-IP 无法反查。
6. **TUN 不形成回环。** 新出口不能误选 utun/TUN 自身；主机更换网关、地址族后，核心拥有的排除路由和 socket 保护仍正确。不能为恢复而自动改写系统 DNS 或用户路由策略。
7. **恢复有顺序且有生命周期。** 自动事件、手动 reset、热重载和 shutdown 协调执行；过期恢复结果不得覆盖更新网络或新配置。所有后台任务可取消、可回收，网络状态写入继续由持租约实例执行。

状态建议：`WaitingForNetwork → Recovering → Ready`；部分恢复失败进入 `Degraded` 并有界重试。阶段成功、接口存在和 reset 返回计数都不能直接代表 Ready。

初始验收预算建议：受控测试中网络状态稳定后 **2 秒内检测、15 秒内完成新连接恢复或报告明确失败**；失效旧连接默认在 **30 秒内收敛退出**。这些是待 A0 校准的测试目标，不是已验证的保证；预算与现有协议超时的冲突必须显式解决。持续离线时间不计作已出现可用网络后的恢复耗时。

## 3. 实施切片与门槛

| 切片 | 工作与主要文件 | 完成条件 |
| --- | --- | --- |
| A0：复现与冻结契约 | 追踪 `lib.rs → app/net → socket_helpers → DNS/pools/TUN`；核对本地 `ref/`；盘点当前启用协议的复用资源与旧接口快照；建立可控网络事件/假时钟 fixture | 能复现至少一个切换后仍使用旧出口或旧 transport 的问题，或明确记录没有复现的边界；给出旧连接、显式绑定、恢复时限的测试断言 |
| A1：检测变化 | 在 `app/net/` 附近增加最小网络快照与监测；接入运行时取消；先实现 macOS，平台接口与不支持诊断保持清楚 | 识别接口 index/地址、物理网关/路径、IPv4/IPv6 可用性、系统/DHCP DNS 的相关变化；同网卡换网络也能触发；事件去重、合并、退避，忽略自己安装路由产生的反馈 |
| A2：恢复出口与传输 | 在现有运行时中串行协调；先重新选路/更新自动出口，再刷新 DNS 绑定/信息并复用 reset hooks；自动恢复与手动 reset 共用内部流程 | 下一次 dial/query 使用当前网络；单组件失败不阻止其他独立组件尝试；失败可见且可重试，不能把部分成功标为 Ready；保留现有 API 鉴权与成功响应字段 |
| A3：TUN 与失效会话 | 核查 `proxy/tun/routes/`、socket 保护、Dispatcher UDP 复用及协议内池；只补缺失的失效/重建路径，扩充 deadline/cancel | TUN 下出口切换仍能 DIRECT/代理出站，无回环；旧 UDP/池不永久占用旧接口；不受影响连接保留，失效连接明确结束；启动/重载/停止不会与恢复抢写全局状态 |
| A4：端到端与重复切换 | 新增网络恢复集成用例，复用 loopback DNS/HTTP/SOCKS fixture；在专用环境做真实网卡切换 | 单元、受控集成与实机证据分别记录；连续切换没有任务/socket/路由残留，连接不需要手动 reset 或重启即可恢复 |

A0 → A1 → A2 → A3 → A4 逐步验证。若 A0 显示某个路径已经支持恢复，保留其证据并缩小修改范围。A2 的非 TUN 恢复与 A3 的 TUN 恢复分别验收，不能因一项完成就宣称全场景可用。

A1 先选择现有平台能力能够支持的事件监听或受控轮询；恢复时重新读取当前快照，不依赖单条事件的完整性。快照不能用接口名称排序代替有效物理路由，IPv4/IPv6 路径应分别核查。是否需要额外依赖由该切片诊断决定，不先升级依赖。

A2 为每个网络版本与运行时版本关联恢复请求，合并重复事件；旧版本异步任务的提交需检查版本和取消状态。DNS、代理池和路由变更可能部分成功，不能声称整个过程原子；失败时保留可检查状态和清理责任，重试需幂等。不要直接对运行中的 TUN 再调用完整 `init_net_config` 来刷新接口，因为它也修改其他平台状态。

A3 对普通 UDP 会话按当前网络版本失效后重建下一次出站；能迁移的协议须由其自身能力证明。DNS reset、outbound pool reset 与 Dispatcher NAT/session 是不同资源范围。只清理自身拥有且已失效的状态，不盲目清空 fake-IP 池、规则、用户选择或所有活跃连接。

## 4. 场景矩阵

| 场景 | 重点验收 |
| --- | --- |
| Wi-Fi → Ethernet → Wi-Fi | 自动模式跟随有效物理路径；DIRECT、代理、DNS 新请求成功 |
| 同一网卡切换 Wi-Fi / DHCP 更新 | 名称/index 不变但地址、网关或 DNS 改变时仍检测并恢复 |
| 断网 → 离线一段时间 → 重连 | 请求超时有界、无忙循环；重连自动恢复 |
| 休眠/唤醒 | 不沿用失效 socket/pool；漏事件时仍可收敛 |
| 仅 DNS 改变 | 派生 DNS 刷新、显式 DNS 保留；不无差别中断健康 TCP |
| IPv4/IPv6 路径变化 | 各自正确选路；不在已失效地址族上永久重试 |
| 显式接口消失/重新出现 | 不静默回退其他接口；可用性状态与恢复可观测 |
| TUN route-all / 仅 fake-IP 子网 | 新出口 socket 不回 utun，排除路由可收敛，fake-IP 域名规则保留 |
| DIRECT / 当前使用的代理，TCP / UDP | 分别验证 DNS、目标响应、代理链；代理协议是否支持 UDP 按配置标明 |
| 连续抖动/快速切换 | 合并事件、旧结果不覆盖新网络；建议稳定切换 20 轮检查资源数量 |
| reset 与 reload/shutdown 并发 | 无双重恢复、过期引用、悬挂任务或停止后的路由写入 |
| DNS reset 或某个 pool reset 失败 | 其余可恢复组件继续执行；错误可见、后续重试可恢复 |
| 不变网络 | 不持续 reset，不周期性断开健康连接 |

记录每次的事件发生/检测/恢复完成时间、路径与地址族、真实 DNS 与新请求结果、旧连接结局、清理结果。日志仅记录必要网络 metadata，不输出节点凭据或完整配置。

## 5. 计划验证命令

以下为计划验证命令，实际执行结果单列于第 7 节；未列入实际结果的命令不得当作通过。

```bash
cargo check -p clash-lib --locked
cargo check -p clash-lib --no-default-features --locked
cargo check -p clash-lib --features tun --locked
cargo test -p clash-lib --lib app::net::tests:: --locked
cargo test -p clash-lib --lib app::api::handlers::network::tests:: --locked
cargo test -p clash-lib --lib reset_transports_covers_all_upstream_collections --locked
cargo test -p clash-lib --lib reset_connection_pools_deduplicates_shared_handlers --locked
cargo test -p clash-lib --test api_tests network_reset_reports_dns_and_connection_pool_counts --locked -- --exact
cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1
cargo test -p clash-lib --test api_reload_tests --locked -- --test-threads=1
```

新增自动恢复用例使用可注入快照、故障与假时钟；待新测试建立后记录完整全名和命令，并确认执行数量非零。受控集成测试让旧 transport 失效并验证新请求走更新出口，不能只断言 reset hook 被调用。协议池变化时显式指定所需 feature，保留现有默认与 CLI 转发。

切片结束检查 `cargo fmt --all -- --check`、相关测试和 `git diff --check`；最后核查默认 CLI 的 `cargo check -p clash-rs --locked` 及 CI 对应的 `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`。Dashboard/工具链/既有组合失败须记录，不能加无关 feature 或伪造预构建标记掩盖。

真实网卡切换、TUN、系统路由和休眠验证在专用环境执行并保留恢复方案，不在普通单元测试里修改主机网络。本轮运行了隔离 fake-IP 子网的真实 TUN 测试；没有切换主机网卡、系统默认路由或休眠。macOS、Linux、Windows 的编译、自动测试与实机结果分开登记；没有对应证据的平台不能标为完成。

## 6. 当前执行记录

| 切片 | 状态 | 剩余验收 |
| --- | --- | --- |
| A0 | 调用链盘点、故障回归已完成 | 时间预算仍需实机校准 |
| A1 | macOS 自动观察与取消已实现，事件测试通过 | Wi-Fi/有线、DHCP、睡眠的实际变化采样 |
| A2 | 串行恢复、当前接口/DNS/池、独立失败处理已实现 | 实际代理节点在新网络上的端到端响应 |
| A3 | UDP 网络版本失效、池退休、TCP keepalive、TUN 接口刷新与路由所有权已实现 | route-all 实际出口切换、旧 TCP 失效时限 |
| A4 | 自动事件受控测试、20 轮 UDP 集成、隔离真实 TUN 回归通过 | 专用环境的物理网卡切换、休眠与资源计数 |
| Linux / Windows | 自动观察明确标为 unsupported，保留现有平台选路 | 平台实现、交叉编译与实机验证均未完成 |
| Core / Router 重构 | 暂缓 | 不属于本轮范围 |

## 7. 本轮实现与实际验证（2026-10-02）

基线保持第 1 节记录；未创建提交、未 push。参考 `ref/` 的默认接口初始化仍是静态选取，本轮沿用本地已有网络租约和生命周期，增加 macOS 专属恢复；参考 `ref-mihomo` 的 DNS reset 为资源清理入口，不直接照搬其 Go 运行时。没有在参考版本复现本轮缺陷，不能称其为已确认上游缺陷。

### 实现

- `app/network.rs`：每秒观察 SystemConfiguration 的 IPv4/IPv6 物理主路径、网关、地址/index 与全局 DNS；额外比较其他物理接口，覆盖显式绑定的非主接口变化。排除 TUN/loopback，避免自身路由反馈；快照读取有 2 秒 deadline。失败按 2–32 秒退避，新快照立即重试，不变网络不重复 reset。
- `lib.rs`：自动观察、`POST /network/reset`、重载、停止在原控制任务串行执行，停止可取消恢复。只由持网络租约的实例更新默认出口，保留 mark 和 TUN 索引；DNS-only 变化不清空数据池或 UDP 会话。新增 `GET /network`，鉴权沿用 Controller 中间件，`automaticSupported` 始终说明平台自动观察能力，状态为 `observing/recovering/awaitingTraffic/waitingForNetwork/degraded/unsupported`。reset 完成只表示资源已刷新，不声称外网可达。
- DNS：`#auto` 不固定启动接口；创建 transport 时重读显式接口；DHCP 在探测和 lease 检查时重读接口。所有上游集合及 direct resolver 独立重置，单项 5 秒 deadline，聚合错误；bootstrap reset 失败也释放自身 transport。query/reset 并发时返回明确错误，避免 `expect` panic。fake-IP 映射保持，正常 DNS TTL 缓存保留，NXDOMAIN/ServFail 本来就不写入本地 response cache。系统解析通过现有 libc 查询读取系统 DNS，不修改系统配置。
- 会话/池：Dispatcher UDP 会话按网络版本退出，拒绝切换期间完成的旧 dial；下一包重建。gRPC/XHTTP 池新增 reset hook，由 VLESS/Trojan/AnyTLS 转发；构建与 reset 用传输内读写锁和取消 token 协调；先取消未完成的构建，再取得写锁清池，避免无响应握手阻塞 reset；池退休不主动关闭健康 H2 逻辑流。WireGuard 懒初始化改为可重置状态，旧驱动任务取消；Hysteria2 复用既有 QUIC reset。健康普通 TCP 保留，不重放应用数据，出站 TCP 应用现有 10 秒 idle、1 秒 interval、Unix 3 次 keepalive 参数。
- macOS TUN：长期入站不保存旧默认接口；新拨号刷新当前 index/地址，缺少物理出口明确失败，防止回流 TUN。IPv4/IPv6 默认接口分别保存；DIRECT UDP 在两族使用不同物理接口时分开 socket，轮流接收响应。物理 scoped 路由只记录成功创建的项，停止按原接口/网关清理；网关已改变的路由不删除，原本已有的路由不认领。

### 复现与回归证据

`reset_transport_releases_own_state_when_bootstrap_reset_fails` 在修复前失败：bootstrap 错误跳过了自己的背景任务释放；调整清理顺序后通过。新 UDP 回归验证旧 socket 被退休、旧版本 dial 不能重新入池。真实 TUN 扩展测试初次失败来自 fixture 仅返回固定 marker，已改为回显请求路径，随后通过；不能将其称为网络实现缺陷。

| 实际命令 | 结果 |
| --- | --- |
| `cargo check -p clash-lib --locked` | 基线与实现阶段通过 |
| `cargo check -p clash-lib --no-default-features --locked` | 通过，最后复核在新增双族 UDP 后 |
| `cargo test -p clash-lib --lib --locked` | 609 passed、11 ignored（随后新增 deadline、DNS auto、pool 故障测试由全 feature 测试覆盖） |
| `cargo test -p clash-lib --lib --features wireguard --locked` | 626 passed、11 ignored（随后新增测试见最终全 feature 结果） |
| `cargo test -p clash-lib --lib app::network::tests:: --locked` | 当时 7 passed；随后增加 reset deadline 用例 |
| `cargo test -p clash-lib --test direct_udp_integration_tests --test api_reload_tests --test api_tests --locked -- --test-threads=1` | DIRECT UDP 3、reload 4、API 8 个测试通过；UDP 同一入站会话恢复 20 轮，真实响应成功，出站源端口每次改变 |
| `cargo test -p clash-lib --test tun_fake_ip_real_tests --locked --no-run` | 编译通过 |
| `sudo -n target/debug/deps/tun_fake_ip_real_tests-9820147240b6604f --ignored --test-threads=1` | 隔离真实 macOS TUN 1 passed；3 次恢复后 fake-IP 不变，DIRECT/本地 SOCKS TCP 与真实 DNS 上游继续工作；测试专属路由清理后 `netstat` 无该前缀残留 |
| `cargo check -p clash-rs --locked` | 通过，包含正常 Dashboard 构建 |
| `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` | 实现阶段通过；最终复核结果追加于下方 |

初次 CLI/全 feature 检查遇到 Dashboard 的 root 所有权缓存导致 `npm ci` EACCES；修正 `node_modules` 和 `dist/assets` 的所有权后重跑通过。没有改依赖、生成假 prebuilt marker 或放宽 lint。

两个尝试的精简组合未通过：`--no-default-features --features tun` 在 TLS/DNS/XHTTP 未使用字段报 dead_code；`--no-default-features --features tun,tls,aws-lc-rs` 在 `vless/encryption.rs::validate_crypto_keys` 报 dead_code。未改变这些文件/feature 依赖以掩盖失败，也未在独立基线重跑这两个组合；保留组合债务，不标为支持验证通过。

### 尚未完成的验收

- 2026-10-02 只读检查 `networksetup -listallhardwareports` 与 `ifconfig -a`：Ethernet `en0` 有活动链路；Wi-Fi `en1` 和其他硬件/桥接接口均未活动，因此当前没有可用于切换验收的第二条物理路径。没有人为关闭正在使用的网络，也没有修改接口、路由或 DNS；实际 Wi-Fi↔Ethernet、DHCP 换网、休眠/唤醒、TUN route-all 或真实远程代理验证仍需专用测试环境。
- 20 轮自动测试是可注入快照驱动的生产恢复方法；20 轮 UDP 集成和 3 次真实 TUN 恢复使用 reset API。这些证据组合覆盖链路，不能替代物理自动切换的端到端证明。
- 2 秒检测 / 15 秒新连接 / 30 秒旧连接仍是待校准目标。实际资源重置最多 15 秒，另有快照与具体协议拨号时间；不能承诺整个新连接 15 秒内成功。TCP keepalive 的实际失败时限受 OS、在途数据和协议驱动影响，不能承诺所有旧流 30 秒结束。
- 真实 TUN 当前用 `route-all: false`，仅自身 fake-IP 子网；物理 scoped default 的动态环境、IPv6 两张物理接口、长期资源计数与跨平台运行均待专用环境验证。

下一最小代码步骤：让 Hysteria2/H3 与可归属的独立 UDP socket 在确知实际 PathId 后报告最终目标响应；再用受控测试锁定恢复期间已开始但尚未完成的旧路径拨号不能进入池或报告恢复成功。路径身份不明的 SOCKS/SS UDP 不沿用控制 TCP 的 PathId。物理验收仍需专用 macOS 双网卡环境：保留 fake-IP 与一条旧 TCP 流，轮换物理路径 20 次，采集 `/network`、真实 DNS/HTTP/SOCKS 响应及 socket/路由/任务计数，再校准时限与 A4；平台实现/验证另行排期。

### B7 本轮增量复核（2026-10-02）

- `Transport` 增加带 network generation 的创建/借出入口；`RemoteConnector` 暴露当前 generation，代理链向底层 connector 查询；VLESS 统一在借池和新建 H2 transport 时传递同一 generation。gRPC、XHTTP H2 主池及独立下载池、XHTTP H3 上传/下载池仅保留当前代际连接。generation 缺失的独立测试和没有网络观察的调用仍走 `None` 代际池。
- `cargo test -p clash-lib --lib older_network_generation --all-features --locked`：2 passed；`cargo test -p clash-lib --lib network_generation --all-features --locked` 与 `--no-default-features --locked` 均为 5 passed；完整 `cargo test -p clash-lib --lib --all-features --locked`：812 passed、0 failed、12 ignored；`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、全目标/all-features Clippy、fmt 与 diff 检查通过。
- 仍未证明每个池条目与真实物理 PathId 一一对应，也未测得同代 NIC 改道、代理认证成功或硬件双网卡切换；因此这是 B7 代际隔离增量，不代表 B7/A4/B11 完成。

### B7 PathId 池隔离增量（2026-10-06）

- `RemoteConnector::connect_stream_with_pool_context` 返回成功拨号实际获胜的 `NetworkPathId`；DirectConnector 仍保留原 `connect_stream` 接口，并在返回前沿用旧 networkVersion 校验。VLESS 在借池前查询当前网络代次和允许路径，成功新拨号后将实际 PathId 传给 transport。
- gRPC 与 XHTTP HTTP/2 上传连接条目现在记录 `network_generation + PathId`。借出时同时检查代次与当前候选路径：失效 PathId 被惰性移出，其他仍合格路径的条目可保留；新连接只有实际路径仍在允许集合时才入池。连接路径无法验证时不写入受路径策略管理的池。
- XHTTP HTTP/3 当前不能从 QUIC connector 获得可靠的物理 PathId。存在显式路径候选上下文时会清除未标记的 H3 缓存，并使用单次连接，避免复用路径不明的旧池；没有路径观察的传统调用继续沿用代次级复用。独立下载池仍按代次隔离，因为其直接拨号目前没有返回物理 PathId。
- VLESS、Trojan、AnyTLS、SOCKS 与 Shadowsocks 会在各自协议处理之后观察应用可见的目标响应；证据记录 `proxyTcp` 与最终 destination。Trojan/AnyTLS 的 UDP-over-TCP 使用 `proxyUdp`。VLESS 的代理响应头解析错误不会生成成功证据；代理 endpoint 的先前响应仍单独标为 `proxyEndpointTcp`。SOCKS/SS UDP 使用单独的数据 socket，未把控制 TCP 路径误记到 UDP 流。
- `grpc_pool_rejects_a_connection_from_an_older_network_generation` 与 `xhttp_h2_pool_rejects_a_connection_from_an_older_network_generation` 增加同代路径变更断言：Path A 建立的池在仅 Path B 合格时不再借出并被移除；两者还验证借池返回原 PathId 元数据。`vless_target_response_reports_the_actual_proxy_path` 驱动完整 VLESS 响应头与目标字节，验证只产生最终目标的路径健康证据。`cargo test -p clash-lib --lib older_network_generation --all-features --locked` 为 2 passed；`cargo test -p clash-lib --lib vless_target_response_reports_the_actual_proxy_path --all-features --locked` 为 1 passed；最终 `cargo test -p clash-lib --lib --all-features --locked` 为 814 passed、0 failed、12 ignored。
- Trojan、AnyTLS、SOCKS 和 Shadowsocks 复用同一层 PathId-aware 流观察；当前普通库测试没有为这些协议启动真实代理服务，因此其端到端认证与最终目标响应仍未被本轮受控测试证明。未运行 Docker/远端代理测试。
- 最终验证：`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 均通过。
- 尚未验证双条真实池并存时保留健康 Path B 的端到端行为、代理协议认证成功证据、最终业务目标响应证据和真实网卡切换。H3 活动路径策略下禁用池复用会增加握手开销，是等待路径身份接入前的安全退化。

### 最终复核

- `cargo test -p clash-lib --lib --all-features --locked`：753 passed、0 failed、11 ignored，耗时 7.53 秒；覆盖双族 UDP、自动观察生产恢复方法、DNS deadline、池故障隔离、H2 健康流保留与 WireGuard 生命周期。
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`：通过。
- `cargo test -p clash-lib --test direct_udp_integration_tests --test api_reload_tests --test api_tests --locked -- --test-threads=1`：最终重跑通过（3 + 4 + 8）。
- `cargo fmt --all -- --check`、`git diff --check`：通过。Cargo.lock 无变更，原有 AGENTS/Nix/submodule/脚本改动保留。
- 不将未运行的 workspace 全回归、Docker 协议服务器、吞吐、Linux/Windows 编译或物理切换标为通过。

补充复核：`cargo test -p clash-lib --lib network_reset_cancels_stalled_xhttp_construction --all-features --locked` 实际执行 1 个测试并通过，模拟不返回响应的对端，reset 取消连接构建后及时取得锁，并换用新取消 token。随后全 feature 单元回归 753 passed、11 ignored。最后增加的平台能力字段 `automaticSupported` 已通过全 feature 编译与测试。

一次过滤运行 `cargo test -p clash-lib --lib proxy::transport:: --all-features --locked` 得到 208 passed、1 failed：现有 Reality `test_connection_has_required_methods` 在两个 Rustls provider 同开、其他测试未初始化 provider 的情况下 panic；未修改该非本轮测试，保留其隔离运行的初始化问题。完整全 feature 测试通过不能证明该过滤命令已通过。

## 状态机与可观测性迭代（2026-10-02）

本轮聚焦恢复状态的可信性，不将前述硬件验收或完整任务监督标为完成。

- `app/runtime_state.rs` 是运行时状态转换入口：应用生命周期使用枚举；网络观察、恢复、等待响应、收到响应、离线及失败分别表示。停止/失败后拒绝恢复完成和流量证据；启动监听失败明确进入 failed，取消中的恢复记录 cancelled。
- `/runtime` 与 `/network` 返回同一把锁下克隆的状态快照；原 reset 返回字段不变。新增 `application`、`configVersion`、`networkVersion`、`lastOperation`、`transitions`、`trafficEvidence`、`observationError`、`nextRetryAtMs`、`rejectedStaleResults`、`droppedEvidence`。时间为 Unix 毫秒；重试时间是绝对计划时间，不是会随读取减少的倒计时。
- 操作包含原因、三个版本标记、开始/结束时间、耗时、结果和接口/DNS/连接池独立报告。`refreshed` 只表示资源刷新完成，不证明远端可达。状态转换历史限制 32 项，流量证据每个版本最多四种，证据通道容量 128；满时不阻塞转发并累计丢弃计数。
- 新 TCP/UDP 流在拨号之前捕获版本，收到非空远端响应才报告一次；Linux 零拷贝读取也接入。旧连接不会被重新标记成新版本。`trafficVerified` 只证明 `trafficEvidence` 指明的路径收到过响应，不代表全部代理、DNS、IPv4/IPv6 或应用功能健康；不会解除 DNS/池失败。
- 手动恢复失败会保留重试需求；不变的网络快照不能抹除恢复失败。只有对应成功恢复解除组件错误；网络观察错误单独保存。

### 修复前后证据

`cargo test -p clash-lib --lib unchanged_snapshot_does_not_clear_failed_manual_recovery --locked` 修复前实际失败：失败恢复后下一次相同快照将 degraded 清为 awaitingTraffic；修复后实际执行一个用例并通过。状态单元测试覆盖部分失败、旧操作/配置/网络版本、终止状态、只报告一次及有界队列。UDP 集成通过 `/runtime` 等待真实响应证据，验证证据版本等于最后恢复版本。

### 边界与下一步

应用 `running` 当前表示生命周期已启动并完成现有监听 readiness，尚未汇总每个长驻任务的持续存活状况。网络采样与恢复仍由同一个控制任务串行执行，恢复期间不会独立采样；版本防护拒绝已知旧版本，不能据此承诺立即发现恢复期间发生的另一轮物理切换。进程级实际接口/mark/TUN 变量仍沿用已有租约保护和适配方式，本轮没有迁移成一个原子绑定快照。

下一代码切片：独立、可取消的最新网络快照采样；恢复结束前核对更新快照；为 API/DNS/TUN/inbound 长驻任务建立持续健康报告与退出监督。之后在专用双网卡环境完成既有物理切换验收。上述工作继续以新连接自动恢复、旧连接尽力保留或明确结束为目标，不把有限路径证据称为全局健康。

### 本轮实际验证

- `cargo test -p clash-lib --lib --all-features --locked`：最终 760 passed、0 failed、11 ignored。
- `cargo test -p clash-lib --test direct_udp_integration_tests --test api_reload_tests --test api_tests --locked -- --test-threads=1`：3 + 4 + 8 passed；随后只新增取消结果记录、启动失败状态及单元用例，最终核心回归与 lint 覆盖这些变更。
- `cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`：通过。
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check`：最终通过。
- 未再次运行提权 TUN 测试、物理切换或其他平台运行；不改变前述验收缺口。保留用户既有改动，没有提交或推送。
