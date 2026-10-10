# 主机网络变化后的可用性迭代计划

日期：2026-10-08。状态：B0–B6 已完成代码级与受控回归；B7 已接入代理端点 TCP/UDP 与 DNS socket 路径，为 gRPC/XHTTP H2/H3 池加入逐连接 PathId 选择性退休，并为 VLESS、Trojan、AnyTLS、SOCKS 和 Shadowsocks 的 TCP 流记录最终目标响应路径健康；Trojan/AnyTLS 的 TCP 承载 UDP 也已接入。Hysteria2 普通及 Salamander QUIC 使用 connector 选定路径，QUIC 外层响应和 Hysteria2 UDP 最终目标响应分别记录为代理端点与代理目标证据；独立代理 UDP socket 有有界路径绑定尝试。Hysteria2 端口跳跃复用注册的 connector，已知 PathId 时新 hop socket 固定在建连路径，未知时不改选新观测路径；网络恢复取消令牌也会取消进行中的 hop socket 建立。本轮继续补入 Relay 首跳 PathId 传递、活动/关闭 Flow 的 `networkPaths` 观测和 `/flows.flowIds` 关联字段；它只报告本机实际使用的 NIC，不声称能观察代理服务器之后的远端转发路径。B10 Explain 代码扩展为 TCP/UDP 路径规划、拨号成功/失败、旧网络结果丢弃与配置 reload 版本差异，并提供近期决策列表端点；成功 UDP 关联 ID 可从 `/flows.flowIds` 关联到决策记录。B8 代理端点 TCP 拨号新增有界多 PathId 尝试。UDP 会话退休会把网络代次变化记为 `networkChanged`，空闲清理记为 `idleTimeout`。上述代码及回归用例仍未编译或运行；B7 代理协议服务器端到端覆盖仍待验收。DIRECT 域名/fake-IP UDP 的真实答案族处理已在 B5 覆盖。B8 的 DIRECT/代理端点 TCP 尝试调度、B9 的被动恢复防抖和 B10 的有限运行时偏好已完成相应代码切片。Linux 网络快照与路径绑定观察代码已加入；本轮继续补充关闭流原因和 Linux 观察用例，但均尚未编译或运行。Linux 能力不能标为已验证支持；Windows 仍 unsupported。B11 的双网卡物理切换、route-all、休眠、资源趋势及时间预算仍待专用环境验收。

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
| B7 代理 / DNS / 池接入（进行中） | 代理端点与最终目标、DNS 独立意图；接入实际 socket 路径；给可复用连接记录实际 path/network 代际 | 已实现非 TUN 代理端点 TCP/UDP 与 DNS direct socket 路径选择、DNS 响应健康证据、VLESS/Trojan/AnyTLS/SOCKS/Shadowsocks TCP 最终目标响应路径证据、gRPC/XHTTP H2/H3 按 PathId 选择性退休、Hysteria2 普通及 Salamander QUIC connector 路径、端口跳跃沿用 connector 并固定到初始 PathId、代理端点 UDP 与 Hysteria2 UDP 最终目标响应证据、Relay 首跳 TCP/UDP 本机 PathId 传递，以及活动/关闭 Flow 的 `/flows` `networkPaths` 字段；该字段不代表代理服务器之后的远端转发 NIC。代理协议服务器端到端与 pooled transport 行为仍待验证 |
| B8 有界多路径尝试（DIRECT 与代理端点 TCP 代码已接入，待验证） | 有界 AttemptBudget、错峰启动、单 winner、取消与清理；只竞速代理端点 TCP 建连，协议握手不跨连接重放 | DIRECT 与代理端点 DNS+拨号总预算均为 5 秒、最多 3 次/并发 2、120ms hedge，快速失败立即推进；代理端点计划最多纳入 3 个 DNS 地址，跨地址族与候选 PathId 轮次调度；Preference 保留一个 system-route 回退名额，Require 不回退；旧 networkVersion 完成的 socket 丢弃；失败 socket future 随 winner 取消；不竞速 UDP 业务包或重放应用数据。连接与 API 行为待验证 |
| B9 首选恢复与防抖（被动证据范围已完成） | cooldown、真实流量响应和稳定窗口；只改变新 Flow 候选可用性 | 冷却期排除不可用路径；恢复至少 3 次真实响应且跨越 15 秒；单次成功不恢复；不发送面向猜测目标的合成探测。主动探测与 minimum-dwell 校准不在当前实现范围 |
| B10 运行时意图与 Explain API（代码范围扩展，待验证） | 基于现有鉴权开放偏好更新、effective-paths 和 decision 查询；临时覆盖使用单调时钟及 TTL | 偏好更新校验后在 RuntimeStatus 锁内原子替换并增加 `policyVersion`；临时覆盖到期恢复基础偏好；Explain 记录有界并覆盖 TCP/UDP 路径规划失败、DIRECT/PROXY 拨号成功与失败、旧网络代次结果丢弃；记录候选 PathId、策略拒绝原因、版本和操作编号；成功 UDP 关联的 `flowId` 出现在 `/flows.flowIds`，可查询 `/runtime/network/path-decision/{flowId}`；记录连接完成时发现的 reload 版本差异，`/runtime/network/path-decisions` 可列出近期结果。物理代理端点 TCP/UDP 拨号错误以结构化 `io::Error` 来源保留候选、实际尝试 PathId 与策略/健康拒绝原因，Dispatcher 将其写入 Explain；协议 TLS/认证阶段错误仍保持现有错误边界，不伪称已逐协议分类。全部代码与 API 行为待验证 |
| B11 实机与平台验收 | 保留 A4 的专用双网卡验证；DIRECT/代理/DNS、双栈/TUN、资源趋势与时间预算 | 不使用 reset 的物理切换、DHCP、离线/唤醒和抖动有真实响应证据；20 轮资源回收可核查；macOS/Linux/Windows 各自记录编译、受控测试与实机结果 |

依赖：B0 → B1 → B2 → B3 → B4 → B5 → B6；B7 的协议/池子切片继续推进，B8 DIRECT TCP 已基于 B5 的 PathPlan 独立验证，B9 消费 B6 的真实流量健康证据，B10 读取并更新运行时 PathIntent；它们不表示 B7 全部已完成。B11 依赖可达的专用多网卡环境。不得把未验证前置标成完成。可取得专用硬件时，既有 A4 基线验收提前运行，不必等 B11；它不能替代新 scheduler 的实机验收。

### B11 验证安排（计划，尚未执行）

本计划不在当前 Mac 上安装或启动 Linux 虚拟机，也不改动宿主机网络。后续 Linux 测试使用专用 Linux 主机或一次性虚拟机；每轮记录代码提交、内核版本、网络拓扑、配置摘要和完整测试命令，不复制生产凭据、`config-prod.yaml`、缓存或数据库。

| 阶段 | 环境与操作 | 通过条件 / 证据 |
| --- | --- | --- |
| V0 环境准备 | 确认隔离 Linux 环境支持 network namespace、veth、`iproute2` 与 `CAP_NET_ADMIN`；在干净检出中构建，测试流量只留在隔离网络 | `uname -a`、`ip -details link`、路由表、代码基线和配置摘要归档；确认不会改宿主机接口或默认路由 |
| V1 Linux 当前能力基线 | 在 Linux 上编译并运行最小配置，查询 `/network`；本分支已接入 Linux 快照代码，源代码预期报告自动观察支持，但结果尚未验证 | 确认实际启动可采样接口、IPv4/IPv6 地址、main-table 默认路由及可绑定候选；编译失败、快照失败或 API 与观测不一致均退回修复，不进入 V3 |
| V2 网络观察能力门槛 | Linux rtnetlink observer、默认路由签名、DNS 可见配置签名和本地绑定探测代码已加入；本机可运行的平台无关单测已通过，Linux 专属解析与链路变化验证尚未执行 | 链路/地址/默认路由改变可生成新 network generation，重复快照不重复 reset，shutdown/reload 可取消采样；非 Wi-Fi 接口保持 `unknown`，避免把 sysfs 设备猜成 Ethernet；策略路由表、内核 multipath 和 systemd-resolved 后端差异须记录限制或另行补齐。通过前不进入 V3 |
| V3 双虚拟路径切换 | 在 namespace 中建立 client、两条独立 gateway 路径和同一测试服务；按顺序执行 A 链路 down/up、A 地址/DHCP 替换、默认路由变化、短暂断网和抖动。每种变化至少 20 轮，记录新 TCP、UDP、DNS 与配置的代理协议结果 | 不调用 `/network/reset`；新连接在路径失效后自动选择合格路径，硬接口/地址族约束仍生效；旧 TCP 不重放应用数据，能存活的流继续运行，传输失败或空闲超时后进入 terminal 状态；检查 `/flows?include_closed=true` 聚合字段 `endReasons`，TCP 仅在网络代次变化与传输错误同时出现时计入 `networkChanged`，UDP 旧 association 因代次切换退休时计入 `networkChanged`，API 主动关闭计入 `controllerRequested`；分别报告检测、资源恢复、新拨号、旧流结束的 P50/P95/max 与失败轮次 |
| V4 真实平台验收 | 有专用双网卡设备后分别在目标平台执行 Wi-Fi/有线切换、DHCP、断网重连、睡眠唤醒和 TUN 场景；Linux namespace 结果不替代 macOS SystemConfiguration、真实驱动或物理 TUN 验证 | 平台、场景和结果分别登记；保留旧 TCP、真实 DNS/HTTP/代理响应以及 socket/任务资源计数；稳定重复后再校准并批准恢复时限 |

阶段顺序是 V0 → V1 → V2 → V3 → V4。Linux 观察代码已开始实现，但 V1/V2 通过前不把 Linux 自动恢复标为完成；不能用 `ip link` 成功切换代替产品观察能力。Linux 虚拟网络结果也不能替代专用 macOS 双网卡验收。

### 代码与验证增量（2026-10-08）

- Linux observer 代码与解析单测已写入 `app/network.rs`，包含 main-table unicast 默认路由和最小 metric 选择、ECMP 歧义保留、DNS 可见配置签名、链路 down 不被本地 bind 成功掩盖。当前主机为 macOS；Linux 专属解析分支、rtnetlink 实际事件和 namespace 换网仍须在 V0–V3 环境验证。
- TCP 关闭历史新增 `endReason`，`/flows` 聚合为 `endReasons` 计数。dispatcher 在流建立时保存 network generation；传输异常结束时若观察到 generation 已变化，标记为 `networkChanged`。该字段只表达同时发生的诊断证据，不断言网络变化是唯一原因；半关闭后由 inactivity guard 结束也会单独报告 `idleTimeout`。UDP association 的 session map 保留追踪器句柄，在网络代次切换退休或拒绝过时代次的延迟拨号时标记 `networkChanged`，idle 清理时标记 `idleTimeout`。
- Controller 单条/全部主动关闭会进入关闭历史，标记 `controllerRequested`。关闭原因、idle-timeout、历史记录和 API 聚合的回归用例已在全量库单测中执行并通过；Linux-only 结果仍须在 V1 环境取得。
- UDP association 的网络代次退休与空闲过期现在分别写入追踪器的 `networkChanged` / `idleTimeout` 终态。代次切换退休、过时代次拨号拒绝、空闲过期均有定向用例；回环网络恢复集成测试检查 `/flows.endReasons.networkChanged` 与 flow/decision ID 关联，已通过。
- Relay 首跳 connector 现在复用 OutboundManager 提供的网络观察源；DIRECT、常用代理 TCP/UDP、Hysteria2 与 XHTTP HTTP/3 传输会把连接时实际拿到的本机 `NetworkPathId` 留在 stream/datagram 链中，代理链包装器继续传递该身份。tracker、关闭历史和 `/flows` 聚合提供可选 `networkPaths`，不把远端代理服务器的转发接口伪装成本机事实。
- 代理端点 TCP dial 改为有界调度：最多 3 个 DNS 地址/PathId 尝试、最多 2 个并发、120ms hedge、5 秒含 DNS 的总预算；Preference 保留 system-route 回退，Require 不回退；完成时再次核对 networkVersion。物理 endpoint dial 错误保留候选、实际尝试路径和拒绝原因，便于 Explain 关联。这里只在原始 TCP socket 层竞速，不会重放或并发执行 TLS/代理认证握手。
- TCP/UDP 代理 endpoint 物理 socket 拨号错误通过类型化 `io::Error` 来源携带候选路径、实际尝试路径和拒绝原因；TCP Dispatcher Explain 可查询到该信息，UDP 硬约束/尝试失败也可查询候选与拒绝原因。错误来源关联与路径调度单测已在全量库单测中执行并通过；TLS/代理认证失败继续遵循协议当前的错误边界。
- `/flows` 聚合记录现在包含可选 `flowIds`，让多个连接折叠在同一目标记录时仍能保留 tracker 身份。
- Explain API 记录 TCP/UDP 路径规划失败、DIRECT/PROXY 拨号结果和旧网络代次连接丢弃；决策携带编译阶段候选 PathId 与策略拒绝原因。物理代理端点错误保留候选、尝试与拒绝详情。成功 UDP 关联复用 tracker 的 `flowId`，可由 `/flows.flowIds` 关联到 path decision。全量库单测和回环集成用例已覆盖相关 ID、候选计划、硬接口 fail-closed 与 UDP 终态关联；后续 Linux/专用环境仍需覆盖真实多路径 bind、5 秒 deadline、hedge loser 取消和切网期间旧 socket 丢弃。协议 TLS/认证阶段错误仍沿现有错误边界，可能没有物理端点 PathId。

本轮实际验证如下：

```bash
cargo fmt --all -- --check
cargo check -p clash-lib --all-features --locked
cargo check -p clash-lib --no-default-features --locked
cargo check -p clash-lib --locked
cargo check -p clash-rs --locked
cargo test -p clash-lib --lib --all-features --locked
cargo test -p clash-lib --test api_tests --all-features --locked runtime_path_preference_updates_are_versioned_and_temporary -- --nocapture --test-threads=1
cargo test -p clash-lib --test direct_udp_integration_tests --all-features --locked network_recovery_replaces_udp_socket_without_restarting_inbound -- --nocapture --test-threads=1
git diff --check
```

结果：格式检查、core all-features/no-default/default 编译及 CLI 默认编译通过；库单测 831 passed、0 failed、12 ignored；运行时路径偏好 API 测试 1 passed，UDP 网络恢复集成用例 1 passed。测试只使用本地 Controller 和 UDP echo，没有切换宿主机网卡。以上不覆盖 Linux 专属解析、namespace 换网、真实双网卡和平台 TUN。

`app::network::tests::` 中的 Linux parser 用例必须在 Linux 目标执行；在 macOS 上过滤后零个测试运行不构成覆盖。之后再按 V0–V4 执行 namespace 与专用硬件验收。

V3 开始前先冻结测试的时间预算和终止状态定义；现有 2 秒检测、15 秒新连接、30 秒旧连接仍是待校准目标，不能预先当作通过标准或产品承诺。任何最终阈值都由测试结果与用户确认后写入验收标准。

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
| Linux / Windows | Linux 快照与自动观察代码已加入、未验证；Windows 仍 unsupported | Linux 编译、定向用例、namespace 换网和实机验收待后续统一执行；Windows 平台实现与验证未完成 |
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

下一最小代码步骤：用受控 Hysteria2 服务端验证端口跳跃跨多轮切换与 reset 取消，再评估代理链逐跳 PathId 的可观测边界。路径身份不明的 SOCKS/SS UDP 不沿用控制 TCP 的 PathId。物理验收仍需专用 macOS 双网卡环境：保留 fake-IP 与一条旧 TCP 流，轮换物理路径 20 次，采集 `/network`、真实 DNS/HTTP/SOCKS 响应及 socket/路由/任务计数，再校准时限与 A4；平台实现/验证另行排期。

### B7 本轮增量复核（2026-10-02）

- `Transport` 增加带 network generation 的创建/借出入口；`RemoteConnector` 暴露当前 generation，代理链向底层 connector 查询；VLESS 统一在借池和新建 H2 transport 时传递同一 generation。gRPC、XHTTP H2 主池及独立下载池、XHTTP H3 上传/下载池仅保留当前代际连接。generation 缺失的独立测试和没有网络观察的调用仍走 `None` 代际池。
- `cargo test -p clash-lib --lib older_network_generation --all-features --locked`：2 passed；`cargo test -p clash-lib --lib network_generation --all-features --locked` 与 `--no-default-features --locked` 均为 5 passed；完整 `cargo test -p clash-lib --lib --all-features --locked`：812 passed、0 failed、12 ignored；`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、全目标/all-features Clippy、fmt 与 diff 检查通过。
- 仍未证明每个池条目与真实物理 PathId 一一对应，也未测得同代 NIC 改道、代理认证成功或硬件双网卡切换；因此这是 B7 代际隔离增量，不代表 B7/A4/B11 完成。

### B7 PathId 池隔离增量（2026-10-06）

- `RemoteConnector::connect_stream_with_pool_context` 返回成功拨号实际获胜的 `NetworkPathId`；DirectConnector 仍保留原 `connect_stream` 接口，并在返回前沿用旧 networkVersion 校验。VLESS 在借池前查询当前网络代次和允许路径，成功新拨号后将实际 PathId 传给 transport。
- gRPC 与 XHTTP HTTP/2 上传连接条目现在记录 `network_generation + PathId`。借出时同时检查代次与当前候选路径：失效 PathId 被惰性移出，其他仍合格路径的条目可保留；新连接只有实际路径仍在允许集合时才入池。连接路径无法验证时不写入受路径策略管理的池。
- 在该阶段，XHTTP HTTP/3 尚未从 QUIC connector 获得物理 PathId；有路径候选上下文时清除未标记缓存并使用单次连接。此临时限制已由下方 2026-10-06 的 B7 UDP/H3 增量更新：目前 QUIC UDP connector 返回池上下文，按已知 PathId 复用，路径不明时仍不缓存。
- VLESS、Trojan、AnyTLS、SOCKS 与 Shadowsocks 会在各自协议处理之后观察应用可见的目标响应；证据记录 `proxyTcp` 与最终 destination。Trojan/AnyTLS 的 UDP-over-TCP 使用 `proxyUdp`。VLESS 的代理响应头解析错误不会生成成功证据；代理 endpoint 的先前响应仍单独标为 `proxyEndpointTcp`。SOCKS/SS UDP 使用单独的数据 socket，未把控制 TCP 路径误记到 UDP 流。
- `grpc_pool_rejects_a_connection_from_an_older_network_generation` 与 `xhttp_h2_pool_rejects_a_connection_from_an_older_network_generation` 增加同代路径变更断言：Path A 建立的池在仅 Path B 合格时不再借出并被移除；两者还验证借池返回原 PathId 元数据。`vless_target_response_reports_the_actual_proxy_path` 驱动完整 VLESS 响应头与目标字节，验证只产生最终目标的路径健康证据。`cargo test -p clash-lib --lib older_network_generation --all-features --locked` 为 2 passed；`cargo test -p clash-lib --lib vless_target_response_reports_the_actual_proxy_path --all-features --locked` 为 1 passed；最终 `cargo test -p clash-lib --lib --all-features --locked` 为 814 passed、0 failed、12 ignored。
- Trojan、AnyTLS、SOCKS 和 Shadowsocks 复用同一层 PathId-aware 流观察；当前普通库测试没有为这些协议启动真实代理服务，因此其端到端认证与最终目标响应仍未被本轮受控测试证明。未运行 Docker/远端代理测试。
- 最终验证：`cargo check -p clash-lib --no-default-features --locked`、`cargo check -p clash-rs --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 均通过。
- 本增量当时尚未验证双条真实池并存、代理协议认证成功、最终业务目标响应和真实网卡切换；后续受控测试补充项见下方 B7 UDP/Hysteria2/H3 增量。路径身份仍未知时禁用 H3 池复用会增加握手开销，是保守退化。

### B7 UDP / Hysteria2 / H3 / 端口跳跃增量（2026-10-07）

- 只读对照基线：本地 `ref/` 为 `39d06a4`，`ref-mihomo/` 为 `63bd52e`。`ref/` 的 `UdpHop` 直接创建未受保护的系统 UDP socket，切换 socket 与上一 socket 清理较简单；当前工作树已具有接口/mark 保护、异步预建及 5 秒旧 socket 接收宽限。没有覆盖本地实现，而是在其生命周期上补 connector 与路径约束。
- `RemoteConnector` 增加携带池上下文的 UDP 拨号入口。DirectConnector 在代理端点 UDP socket 上按当前可选 PathPlan 最多尝试 3 条路径，绑定失败后有限推进；显式接口/Require 无法满足时明确失败，软偏好候选耗尽时保留系统路由回退。socket 只有在实际绑定并通过网络版本复核后才携带 PathId。
- 代理端点 UDP 使用独立的 `proxyEndpointUdp` 证据类型；只有 QUIC 数据报获得实际响应时才更新路径健康，并归属代理端点与实际绑定路径。受控本地 UDP echo 测试 `proxy_endpoint_udp_response_reports_the_bound_path` 验证此归属。
- Hysteria2 UDP 隧道在请求与响应之间按目标地址关联证据，使用 `proxyUdp` 记录最终目标的真实回包；待关联目标数有 64 项上限，路径和 reporter 缺失时不生成证据。受控本地 UDP echo 测试 `proxy_target_udp_response_reports_the_bound_path` 验证目标归属，与外层 `proxyEndpointUdp` 证据分开。
- Hysteria2 普通 QUIC、Salamander QUIC 和端口跳跃都通过注册的 connector 建立 UDP socket，因此仍经过配置的代理链。Hysteria2 可复用连接保存创建时的路径与代次，借出时按当前候选过滤并退休失效连接。端口跳跃的新 socket 限制在初始 QUIC PathId 上；当 connector 只能提供 generation 时，将继续传递该 connector 并要求代次不变，不会私自直连或另选观测路径。network reset 取消正在握手的旧连接构建；连接取消令牌也传给 `UdpHop`，阻止旧连接继续建立 hop socket。`port_hop_sockets_are_pinned_to_the_initial_path`、`unknown_port_hop_path_does_not_select_a_new_observed_path`、`network_reset_cancels_an_inflight_hysteria_dial` 和 `connection_retirement_cancels_a_pending_port_hop_socket` 覆盖路径约束与取消边界。
- XHTTP H3 的 QUIC connector 现在返回实际 UDP socket 的池上下文；上传/下载 H3 连接按路径和代次复用或退休，握手完成后再次检查路径资格。无法确认物理 PathId 的路径受控连接不进入可复用池。QUIC 层响应仅证明代理端点路径可用，不等于最终网站业务响应已成功。
- 最终验证：`cargo test -p clash-lib --lib --all-features --locked`（821 passed、0 failed、12 ignored）、`cargo test -p clash-lib --lib --all-features --locked hysteria2::`（10 passed）、`cargo check -p clash-lib --features hysteria --locked`、`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、格式和 diff 检查均通过。此前 `cargo check -p clash-lib --no-default-features --features hysteria --locked` 未通过，错误是精简 feature 组合触发的既有 `dead_code` deny（`dns_client.rs`、`app/net/mod.rs`、`app/network.rs`、`common/tls.rs`），本轮未放宽 lint 或修改无关 feature 边界。
- 尚未覆盖代理链逐跳 PathId、端口跳跃在真实 Hysteria 服务器上的多轮切换，以及绑定失败后跨多物理 NIC 的真实恢复；Docker Hysteria 服务器、真实双网卡和物理切换均未运行。上述受控状态机测试不替代代理服务端协议验收。

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

## UDP 路径决策缓存策略版本修复（2026-10-09）

- 基线：Chimera `92c330b`（`master`），工作区初始无未提交改动；参考目录 `ref/` 为本地 `39d06a4`，本轮仅修改本地缓存版本使用，不迁移参考实现。
- 问题：`Dispatcher::dispatch_datagram` 创建 `UdpFlowDecisionKey` 时将 `policy_generation` 固定为 `0`。当 `/network` 的路径偏好更新而物理网络版本未变化时，同一目标持续复用旧缓存，错误归属旧策略；有界缓存空闲超时不足以处理持续活跃的 UDP 流。
- 修复：统一取得当前 `network_version` 与 `policy_version` 并使用二者作为缓存键；在读取前刷新临时路径偏好到期状态。网络状态提供不复制完整路径候选的版本读取；路径规划返回时、使用缓存路径前和建立 UDP association 后同时核对策略与网络版本。版本失效时丢弃当前包或新建 association，不使用过期的路径选择。
- 回归：`udp_flow_decision_cache_invalidates_after_policy_change` 在修复前实际执行 1 个用例并失败（`left: 0, right: 1`），修复后 1 passed；既有 `udp_flow_decision_cache_is_scoped_to_target_and_inbound_user` 1 passed。无默认 feature 的相同新用例 1 passed。
- 验证：`cargo test -p clash-lib --lib --locked` 为 686 passed、0 failed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1` 为 3 passed；`cargo check -p clash-lib --no-default-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过，均在 `nix develop --command` 环境中执行。
- 未验证：真实双物理网卡的 UDP 路径迁移、活跃 socket 的端到端接管、Linux/Windows 真实平台运行仍待专用环境；本轮不修改网络/TUN 配置、不进行发布或推送。

## DIRECT fallback 出站身份一致性修复（2026-10-09）

- 基线：Chimera `92c330b`（`master`），本轮开始时保留上一切片的 `dispatcher_impl.rs`、`runtime_state.rs` 与本计划未提交改动；本地 `ref/` 为 `39d06a4`，参考行为同样在目标出站缺失时使用 DIRECT 回退，本轮不调整兼容策略。
- 问题：TCP 取得 DIRECT fallback handler 后仍以原规则出站名选择 DNS resolver、路径规划与健康证据类型；UDP 的 fallback handler 也保留旧名称，导致 DIRECT 路径相关逻辑未执行，且缺少原始/实际目标区别。
- 修复：TCP/UDP 共用 `select_outbound_with_direct_fallback`，返回真实 handler、有效出站名和是否发生回退；只有查找返回 `None` 时才使用 DIRECT，查找或连接池重置的实际错误仍按错误处理。TCP 后续 DNS、路径和健康分类使用有效名称；UDP 有效名称仍可从 Proxy Group 取得活跃子节点，不改变普通组选路，fallback 的 Explain 保留原规则目标。
- 回归：新增 `missing_outbound_fallback_uses_direct_network_behavior_for_tcp_and_udp` 和 `outbound_fallback_only_happens_when_target_is_missing`，覆盖 TCP/UDP 缺失出站、DIRECT resolver、禁止 proxy-resolve-local 意外解析域名、存在的节点不触发回退、查找错误不回退、DIRECT 缺失的返回结果。
- 验证：`cargo test -p clash-lib --lib --locked` 为 688 passed、0 failed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test lan_proxy_tests --locked -- --test-threads=1` 分别为 3 和 2 passed；`cargo check -p clash-lib --no-default-features --locked` 通过。以上命令由 `nix develop --command` 在 macOS 上执行。
- 边界：未对可变更规则集的真实缺失出站场景进行端到端注入；此切片不修改 Proxy Group → DIRECT 的实际路径指令传递、不验证多网卡物理切换、不更改默认 DIRECT fallback 安全策略。未提交、未推送。

## Selector → DIRECT 真实路径证据修复（2026-10-09）

- 基线：本地 `master` `92c330b`，参考 `ref/` 为本地 `39d06a4`；本轮开始时保留前三个文件的前两轮未提交改动。本轮聚焦 Selector/Direct 的 TCP 与 UDP，不改动网络配置或参考仓库。
- 原问题：TCP 对 Selector 的逻辑名称不识别已选择的 DIRECT 子节点，因而缺少 DIRECT 路径规划；Selector 的 `connect_*_with_path_selection` 没有透传到底层；`OutboundHandler` 默认 TCP 路径返回方法可以把规划候选当作执行结果。UDP 会话键、健康证据与 Explain 曾同时使用未验证的规划路径 ID。
- 修改：在 TCP 路径规划前读取 Selector 活跃子节点，用其名称选择 DIRECT DNS 与路径策略；Selector 的 TCP/UDP 特殊连接方法把路径指令交给当前选中的子处理器。默认 TCP `connect_stream_with_path_selection_result` 仅从返回流 `network_path_ids()` 获取已报告的执行路径，不再猜测候选。UDP 内部继续用规划路径 ID 区分会话，但 scoped 的响应健康证据只在该 ID 与 Datagram/Tracker 的已观测路径一致时生成；`get_observed_path_id` 从既有 `TrackerInfo.network_paths` 取得信息，不另存冗余状态。已连接 Explain 不再用规划 ID 兜底，失败和取消时也不将规划路径当作已建立连接。日志明确标识 `pathPlanned`。
- 回归：新增 `selector_forwards_tcp_and_udp_path_selection_and_preserves_observed_path`，用模拟子处理器验证 DIRECT/PROXY 切换后的 TCP/UDP 路径指令及返回路径；新增 `planned_udp_path_is_not_treated_as_observed_socket_path` 验证无实际 ID 或 ID 不符时不能构造 scoped 证据，并检查会话复用。现有 `outbound_handle_map_separates_sockets_by_selected_path` 同时核对已登记的实际路径。
- 已通过验证（本轮）：`cargo test -p clash-lib --lib --locked` 为 690 passed、0 failed、12 ignored；`cargo test -p clash-lib --lib --no-default-features --locked selector_forwards_tcp_and_udp_path_selection_and_preserves_observed_path` 为 1 passed；`cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1` 为 3 passed；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 全部通过，均在 Nix 环境执行。
- 仍需验证：真实双网卡/TUN 的物理路径验证、Selector 正在切换时从读取活跃节点到打开 socket 的并发窗口、嵌套 Selector 及其他代理组类型（Fallback/UrlTest/LoadBalance）均未在本轮覆盖；因此不能宣称所有代理组或竞态均已修复。未提交、未推送。

## Selector 单连接选路快照（2026-10-09）

- 基线：本地 `master` `92c330b`，参考 `ref/` 为本地 `39d06a4`；开始前工作区已有前三轮未提交的五个文件修改，全部保留。本轮不修改参考仓库和系统网络配置。
- 复现依据：旧 Dispatcher 的 TCP/UDP 流先通过 `get_active_proxy()` 判断 DIRECT 并在异步 DNS/规划后调用原 Selector handler；后者在真正拨号时又调用 `selected_proxy(true)`，用户在这段间隔切换 Selector 会导致规划节点与实际拨号节点不一致。
- 修复：`PinnedOutbound::capture` 在每个 TCP/UDP 新连接开始规划前，沿 Selector 链固定最终的 `AnyOutboundHandler`，使用与实际拨号相同的 provider-touch 选择方式；DNS、路径规划、拨号共享快照结果。Selector 切换仅影响此后的新连接；成功连接后以由内到外顺序补齐原来的 Selector 链记录。嵌套 Selector 递归捕获，拒绝循环或超过 16 层的异常配置。非 Selector 组仍沿用当前逻辑，未改造 Fallback/UrlTest/LoadBalance。
- 回归：`pinned_selector_ignores_later_switch_for_tcp_and_udp` 在固定 DIRECT 后切至 PROXY，再验证 TCP/UDP 均使用原节点、新连接选择 PROXY、链记录不丢失；`nested_selectors_pin_leaf_and_preserve_chain_order` 验证嵌套捕获、切换内层后不影响旧连接、链顺序正确。测试为确定性快照/切换场景，非真实多线程竞态或双网卡实验。
- 验证：`cargo test -p clash-lib --lib --locked` 为 692 passed、0 failed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test lan_proxy_tests --locked -- --test-threads=1` 分别为 3 与 2 passed；`cargo test -p clash-lib --lib --no-default-features --locked pinned_selector_ignores_later_switch_for_tcp_and_udp` 为 1 passed；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 全部通过。以上均在 `nix develop --command` 环境执行。
- 边界：单次拨号节点固定，不意味热更新的整个配置或 DNS/网络版本原子固定；Proxy Group 的非 Selector 动态组选路、代理链中的 Relay/Fallback、物理双网卡/TUN、其他 OS 实机尚待验证。未提交、未推送。

## Fallback / UrlTest / LoadBalance 单连接选路快照（2026-10-09）

- 基线：`master` `92c330b`，参考仓库本地 `ref/` 为 `39d06a4`；前四轮 6 个文件的未提交修改全部保留，本轮没有提交/推送或改动系统网络配置。
- 问题：先前 `PinnedOutbound::capture` 只展开 Selector。Fallback 在健康状态变化、UrlTest 在延迟/可用性变化、LoadBalance 的 RoundRobin 在新流到来时都可能重新选择节点。Dispatcher 的 DNS 与路径规划如果依据组名而实际拨号由组内部再选子节点，会导致 DIRECT 物理路径与真实连接错位；LoadBalance 不能在规划与拨号阶段分别消费 RoundRobin 计数。
- 修复：沿用现有 `PinnedOutbound`，在 TCP/UDP 单次连接开始规划时把 Selector、Fallback、UrlTest、LoadBalance 沿组链展开到同一个最终子处理器。`GroupProxyAPIResponse::select_proxy_for_connection(&Session)` 允许 Session 感知的选路，Fallback 按健康状态调用原 `find_alive_proxy(true)`，UrlTest 沿用普通连接的 `fastest(false)`，LoadBalance 仅调用一次 `selected_proxy(true, session)`；新选出的节点决定 Resolver、DIRECT 路径规划、实际拨号与物理路径证据。连接成功后恢复由内到外的原代理组链顺序。Fallback 无可用子节点时返回明确错误，不再对空列表索引越界。其他类型（如 Relay）保留原逻辑。
- 确定性回归：`fallback_health_change_does_not_change_captured_tcp_or_udp`、`urltest_latency_change_does_not_change_captured_outbound`、`loadbalance_round_robin_selects_once_per_connection`、`selector_over_fallback_pins_direct_and_preserves_group_chain` 和 `empty_fallback_group_returns_error_not_panic` 均通过，测试覆盖捕获后节点状态变化、TCP/UDP 子节点调用计数、嵌套 Selector → Fallback → DIRECT 与链顺序。
- 验证：`cargo test -p clash-lib --lib --locked` 为 697 passed、0 failed、12 ignored；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过；`cargo test -p clash-lib --test direct_udp_integration_tests --test lan_proxy_tests --locked -- --test-threads=1` 分别为 3 与 2 passed；`cargo test -p clash-lib --lib --no-default-features --locked path_selection_tests` 为 8 passed，均在 `nix develop --command` 中执行。
- 边界：这轮的测试是可控的选路快照/状态变化与普通本地 TCP/UDP 转发，**不是**真实 Fallback/UrlTest/LoadBalance 多网卡环境端到端测试；未覆盖 Relay 的多跳链、运行时热重载/Provider 变更的并发交错、真实双网卡/TUN 迁移、跨平台运行和多线程竞争压力测试。特别是策略决策取用的 `Session` 为选路时刻的路由会话（在代理本地 DNS 解析之前），后续需要针对基于地址的负载均衡规则单独确认兼容预期。

## 网络版本与连接池退役竞争（2026-10-09）

- 基线：`master` `92c330b`，本地参考子模块 `ref/` 为 `39d06a4`。开始前保留前五轮九个文件未提交改动。范围仅限 `clash-lib/src/app/outbound/manager.rs` 的新连接池版本检查，不修改系统网络/TUN 或参考仓库。
- 调用链：运行时的手动网络恢复与配置热重载由控制循环串行处理；但网络观测状态可以异步更新，新连接的 `get_outbound_for_new_flow` 会等待 `pool_reset_gate`（其他流或网络恢复也使用此锁）。旧实现进入锁之前调用 `NetworkPathSource::snapshot()`，因此排队期间网络版本变化会使实际重置目标版本过期；重置过程中变化又会直接返回 `Interrupted`，即使新版本能够立即再清理一次。
- 修复：先获得 `pool_reset_gate` 和已有的 `pool_network_generation` 锁，再读取网络版本。若重置期间网络版本变化，重新获取最新快照并执行退役，最多三轮；成功仅将稳定的实际版本写入 `pool_network_generation`。持续变化达到上限时返回 `Interrupted`，不错误地把过期版本标记为完成；重置处理器的实际错误保持立即返回。已有失败后重试测试使用可多次调用的 `FnMut` 回调。
- 可控并发回归：`network_change_during_pool_retirement_retries_new_generation` 验证重置中观测变更时二次执行退役、最终记录版本 2；`queued_flow_uses_latest_generation_after_concurrent_reset` 通过 `Notify` 控制第一个流在退役中暂停，网络变化后第二个排队流不重复执行；`continuously_changing_network_bounds_pool_retirement_retries` 验证三次上限、错误类型和不记录过期版本；原有 `stale_pool_generation_resets_once_and_retries_after_failure` 继续通过。未为热重载启动/回滚的完整数据面执行集成测试。
- 验证：`cargo test -p clash-lib --lib --locked` 为 700 passed、0 failed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test lan_proxy_tests --locked -- --test-threads=1` 分别为 3、2 passed；`cargo test -p clash-lib --lib --no-default-features --locked pool_retirement` 为 2 passed；定向排队及原有失败测试均单独通过；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 均通过。上述命令在 `nix develop --command` 中执行；all-features Clippy 曾因 `clash-lib/build.rs` 调用 Dashboard `npm ci` 花费较长时间，但最终正常退出。
- 未完成：配置热重载和真实网络切换交错的端到端场景、手动重置和热重载同时由外部控制时的资源切换、某个无关出站池重置失败导致全局新连接失败的故障隔离、Linux/Windows 实机，以及实际多网卡/TUN 长跑压测。此切片不解决这些独立问题。未提交、未推送。

## 出站连接池故障隔离（2026-10-09）

- 基线：本地 `master` `92c330b`、参考子模块 `ref/` 为本地 `39d06a4`。本轮之前保留前六轮 10 个未提交文件修改；未改动参考仓库、依赖或系统网络配置。
- 问题：旧 `get_outbound_for_new_flow` 在新网络版本首次查询时执行全量连接池退役，任何一个不相关 handler 的错误/超时都会使所有出站查找失败；简单忽略全局错误又可能让失败 handler 复用旧池。
- 修复：仍对 registry 与 Provider 中的已知 handler 做去重、带超时的全量退役，但按实际 handler 身份记录各自成功或失败；稳定网络版本可标记已完成全量扫描。正常出站不受其他池错误影响，失败或新替换的 handler 在新连接前单独重试池退役，失败则拒绝使用该 handler，不触发 DIRECT fallback。动态 Selector/Fallback/UrlTest/LoadBalance 的最终子节点在 Dispatcher TCP/UDP 捕获后验证；Relay 对其可见子处理器保守验证。按规则选 DNS 出站也捕获最终子节点并检查失败状态。手动网络恢复仍会聚合报告任一池的真实退役错误，但将稳定版本的正常池状态保留，避免后续新连接被无关错误阻断。
- 对象生命周期：成功集合使用 `Weak<dyn OutboundHandler>`，核对 `Arc::ptr_eq`，避免 Provider 热更新时复用同一内存地址误继承旧安全状态，也不强引用过期代理节点。
- 回归：`failing_pool_does_not_block_unrelated_outbound_and_stays_fail_closed`、`manual_pool_reset_reports_failed_pool_without_poisoning_healthy_flow`、`failed_pool_recovery_is_scoped_and_not_retried_after_success`、`retirement_bookkeeping_does_not_keep_replaced_provider_handler_alive` 通过；原有重置去重、失败重试及网络版本并发测试继续通过。
- 验证：`cargo test -p clash-lib --lib --locked` 为 704 passed、0 failed、12 ignored；`cargo test -p clash-lib --test direct_udp_integration_tests --test lan_proxy_tests --locked -- --test-threads=1` 为 3、2 passed；`cargo test -p clash-lib --lib --no-default-features --locked app::outbound::manager::tests::` 为 10 passed；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。全部在 Nix 开发环境执行。
- 限制：本轮只模拟连接池成功/失败/恢复与生命周期；没有启动真实 VLESS/Hysteria2 故障代理或验证热更新时所有 DNS bootstrap 与 Relay 的异步内部出站；未覆盖两个不同 handler 共享同一底层 Transport 实例的特殊配置，也未做物理双网卡/TUN/跨平台运行。API 状态与已有连接对重置错误的反应保持原有逻辑。未提交、未推送。

## Windows GitHub Actions 回归工作流（2026-10-09）

- 现有 `.github/workflows/ci.yml` 的 `quality` 已有 `windows-latest`（Clippy、LAN 代理测试），`compile` 已有 Windows x64/x86/ARM64（PR 中部分目标跑 Cargo 测试）。新增独立的 `.github/workflows/windows-network-regression.yml` 不改变原 CI 或发布过程。
- 触发：`workflow_dispatch` 手动运行；`master` 的相关源码提交、面向 `master` 的相关 PR 自动运行（按 `clash-lib`、`clash-dns`、`clash-netstack`、Cargo/toolchain/workflow 文件过滤）。GitHub 官方要求 `workflow_dispatch` 工作流先存在于默认分支，才能通过 Actions UI 手动选择运行。
- 环境：`windows-latest` x64/MSVC、稳定 Rust、NASM、Protoc、PowerShell、依赖缓存。默认 feature 下执行 `clash-lib` 全库单元测试、`direct_udp_integration_tests`、`lan_proxy_tests`；无默认 feature 下分别执行 OutboundManager 故障隔离、Selector 路径与 Dispatcher 路径测试，全部串行指定 `--test-threads=1`。
- 隔离：只运行普通库测试以及回环 TCP/UDP socket 测试；`direct_udp_integration_tests` 的 `/network/reset` 只调用 Chimera 内部协调器，不更改 Windows 主机物理网卡/TUN/DNS/路由。此工作流不需要管理员权限或真实双网卡，不声称验证了物理 TUN 与网络切换。由于默认 feature 不包含 Dashboard，此专用工作流不调用前端 npm 构建，已有全 feature CI 保持原样。
- 验证状态：本地已使用 Ruby YAML 解析器校验工作流语法和触发/runner/steps 结构，并通过 `git diff --check`。**尚未推送/合并，不能声称已经在 GitHub Windows runner 上跑过这份新工作流**；下一步通过用户发起 PR，或将工作流加入默认分支后使用 Actions → Windows Network Regression → Run workflow。

## CI 跨平台 UDP 首包恢复与 Linux 诊断（2026-10-09）

- 基线：PR #56 对应 `test/windows-network-reliability-20261009`，Windows Network Regression/Windows Rust Quality 成功，但完整 CI 中 Linux x64 的 `/network/reset` 返回 HTTP 500、macOS AnyTLS UDP 偶发超时、Linux ARM 容器进程查询触发 `sock2proc` NETLINK_SOCK_DIAG panic。
- 可复现原因：本地 macOS 对 `integration_test_anytls_udp` 重复运行时捕获到 `discarding UDP socket created for a stale network path`，唯一首包在自动网络版本变化后被丢弃；此前的循环只消费新的 UDP datagram，不再处理旧首包。该竞态与真实网络版本切换有关，增加测试超时无法修复。
- 修复：Dispatcher 为尚未发送成功、因网络版本或路径策略过期而丢弃的 UDP 首包保留最多 3 次重规划机会。再次读取最新生成版本、重新选择路由和出站，避免在旧 Socket 上重发；真正的拨号错误/required 路径失败、已交给活动出站的包均不会盲目重放。补充 `stale_udp_first_packet_is_replayed_with_a_bounded_retry_budget` 测试确保有效载荷保留与有界重试。
- Linux ARM：上游 `sock2proc` 在 NETLINK_SOCK_DIAG 不受内核支持时对 socket 创建失败执行 `unwrap()`。Linux 进程识别结果不应影响数据转发，使用 `catch_unwind` 将异常降级为无进程名；不修改系统内核或配置。后续可考虑修复上游错误处理，避免 panic hook 输出。
- `/network/reset`：先增强 `api_tests` 的失败报告，输出 HTTP 500 的实际响应正文，用于区分 DNS/Pool 退役失败、网络观测失败、无物理路径和重复网络采样竞态；尚未据此改变 HTTP API 语义，也未降低成功断言要求。
- 本地验证：修复后 macOS AnyTLS UDP 重复运行 10 次均通过，第一次重试上限单元测试通过；全库/Clippy 等最终结果取后续实际执行日志。以上测试都在 Nix 开发环境运行，未使用管理员 TUN 或真实双网卡。本节的 Linux 根因必须以更新后的 GitHub Actions 日志复核；未完成前不得宣称整个 CI 全绿。

## macOS/Linux 热重载监听端口释放（2026-10-09）

- PR #56 的 CI #571 显示 macOS ARM64 `test_config_reload_via_empty_path_uses_stored_config_path` 中旧 SOCKS listener 已结束、替换监听器仍在旧端口得到 `EADDRINUSE`，API 状态 500；本地重复测试又复现 API Controller 自己的相同端口重绑定错误，严重时回滚后原 API listener 也无法重新绑定。
- 处理：在共享 TCP inbound socket helper 及 API Controller 上为 *AddrInUse* 增加最多五次有界的异步退避重试（25/50/100/200/400ms，累计不超过 775ms），避免单纯等待 task join 与 OS 端口释放之间的短暂竞争；其他 socket 错误即时返回，持久端口冲突依然不能被忽略。Socks、HTTP、Mixed、Redir、Shadowsocks、AnyTLS 的 TCP listener 统一调用新 helper；UDP/TUN socket 行为没有改动。
- 新增 `tcp_listener_retries_only_while_previous_bind_is_active`、`api_listener_rebinds_after_old_address_is_released` 可控测试；macOS 配置 reload 集成测试重复 8 次通过，`cargo test -p clash-lib --lib --locked` 707 passed / 12 ignored，完整 API 集成 9 passed，direct_udp 集成 3 passed，all-targets all-features Clippy 与格式检查通过。均在 Nix 开发环境执行。
- Linux x64 CI #571 已确认 `/network/reset` 在单独 API 集成测试中通过，但随后在正在执行的 `direct_udp_integration_tests` 的第一个网络恢复请求上再次返回 500；该测试已添加响应正文报告以便 CI 明确暴露失败成因。不在原因确认前放松 200 / socket 替换的断言。

## Linux 受限容器的网络观测退路（2026-10-09）

- CI #572 Linux x64/ARM64 的 `/network/reset` HTTP 500 已由测试响应正文定位为 `operation error: observation: A netlink request failed`。不能简单吞掉恢复错误或假装已观察到可用物理路径。
- 修复：Linux 优先用原有 rtnetlink 链路、地址与主路由证据；仅在 netlink 观测失败时，使用内核只读 `/proc/net/route`、`/proc/net/ipv6_route` 和 `/sys/class/net` 获取主表默认路由、真实链路状态。仍要求命中系统接口索引、route-up 标志、正确的默认目的地和接口地址，不把未知/不可用链路当成 verified；如果 procfs 也不可读取则保留真正错误。运行时会记录回退警告，禁止靠忽略错误满足 API 成功断言。
- 新增 Linux 特定默认路由解析回归，包含 v4/v6 网关与 metric、错误接口以及非默认/非 up 路由。不改动 Linux 系统路由、DNS、TUN 或容器权限。macOS 端本地全库/API/UDP 回归通过；Linux 平台编译/测试仍需后续 GitHub CI 验证。
- Windows Shadowsocks UDP 多 session 回包在 CI 曾超时，VLESS gRPC TLS 吞吐量 E2E 曾报告 `tls handshake eof`。本次未跳过或放宽这些测试，两者仍需分别验证真实失败原因。

## Windows Shadowsocks 双客户端重放与 VLESS gRPC Docker 就绪（2026-10-09）

- Windows x64 全量 Cargo 集成在 `integration_test_shadowsocks_udp_session_isolation` 中第二个客户端超时。日志证明同一 Shadowsocks 2022 客户端源地址 + `client_session_id` + `packet_id=0` 的首包在服务端被解密转发了两次，抢占 UDP echo 的第二次请求机会，第二个独立客户端无法得到响应。这不是提高等待时限能解决的问题。
- 修复：在 Shadowsocks 2022 UDP inbound 上增加按来源 / 客户端会话隔离的 128 包滑动重放窗口；只接受不重复的新 ID、允许有限乱序和客户端 session 重建；过期包、重复 packet id 直接丢弃，最多保留 2048 个来源的窗口，避免无限占用内存。并不会影响没有 SS 2022 控制信息的旧算法。
- 回归：`shadowsocks_2022_duplicate_packet_is_not_forwarded_twice` 在启用 all features 的单元测试中通过；本地 macOS 四个 Shadowsocks TCP/UDP 集成用例（包括两个客户端共用目标）均通过，Windows 仍需本轮后续 GitHub CI 复核。
- VLESS `test_vless_grpc_tls` Docker E2E 曾报告 `tls handshake eof`；原测试只等待 Xray TCP 端口可连接，再 sleep 一秒，不能证明服务端已经完成 TLS/h2 初始化。为测试容器启动增加真正的 TLS 握手加 h2 ALPN 就绪探测，有界 20 秒超时；不重试已发送的应用请求、不影响生产 TLS/GRPC 实现。Docker 运行结果待 CI；未通过前不宣称修复完成。

## Linux ARM64 SOCK_DIAG 与复核补丁（2026-10-09）

- CI #573 Linux ARM64 单独的 SS 2022 TCP 多用户测试出现 `sock2proc` 内部 netlink socket `EPROTONOSUPPORT` panic 记录、以及上层 `early eof`。原 `catch_unwind` 仍会运行不受支持的库调用并触发 panic hook。现在在 Linux 进程归属查询前使用 `libc::socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)` 探测一次内核支持能力，随即 close；不支持时跳过可选的进程名，阻止调用上游库；后续调用仍保留异常隔离。ARM64 TCP 归属用例还需新 CI 证实。
- 同轮 macOS ARM64 SS UDP 双客户端测试也出现一次首包超时。新增的 AEAD2022 包去重解决了 Windows 日志中明确的相同客户端 session+packet-id 重复转发，但不宣称已经排除全部启动时序或 UDP 送达故障。下一次 GitHub CI 继续保留相同真实集成测试。

## 合并前 ARMv7/i686-musl CI 闭环（2026-10-09）

- PR #56 commit `5720117` 的 Windows regression、Windows/macOS/Linux quality 和 x86_64 Linux 完整 CI 通过；跨平台测试中 ARMv7 `lan_proxy_tests` 出现 `SOCKS-IN` 与 `MIXED-IN` **同用端口 36325** 的确定性冲突。原因是四次独立的 `bind(0)` 后立即释放，内核可能再次分配相同端口。测试改为同一时间保留四个通配 IPv4 TCP socket，再统一取端口，增加 32 轮互异性检查，绝不吞掉启动失败。
- 同轮 i686 musl `ss2022_tcp_attributes_traffic_to_authenticated_user` 出现 `UnexpectedEof`，但缺少握手失败证据。原 `ClashInstance::start` 仅等待传入列表的 **首个 API 端口**；在慢速 cross/QEMU runner，不能由 API ready 推断 Shadowsocks server TCP 或 client SOCKS TCP listener ready。本测试增加真实业务监听端口 `wait_port_ready` 的启动同步，且四个测试服务端口同时保留以避免重复分配。这里只消除已知时序隐患，不宣称已定位所有架构兼容问题，需后续 i686 musl 真实运行复核。
- macOS Nix 验证：`cargo test -p clash-lib --test lan_proxy_tests --all-features --locked -- --test-threads=1`（3 passed）、`cargo test -p clash-lib --test shadowsocks_multiuser_tests --all-features --locked -- --test-threads=1`（2 passed）、all-features Clippy `-D warnings`、fmt/diff check 均通过。绝不因多平台 CI 失败而跳过跨平台测试。

## Shadowsocks 双客户端回显测试生命周期（2026-10-09）

- 在 PR #56 `e308eb3` CI 中，ARMv7 GNU hard-float 的 LAN 代理 Cargo 测试已通过；Linux aarch64 GNU 的 `integration_test_shadowsocks_udp_session_isolation` 仍出现第二客户端超时。该测试的 UDP 回显 target 仅在收到**两个报文**后退出，收到重复报文就会提前关闭，使独立的第二客户端无回包。即使 SS2022 inbound 有自己的包重放过滤，测试不能依赖底层 UDP 网络恰好传输两个报文。
- 测试修复：回显 UDP socket 在测试生命周期中持续回应，两个独立客户端的完整 payload 回包断言均成功之后才主动 abort 回显任务；超时断言保持不变，绝不跳过或放宽。Shadowsocks E2E pair 也改为同时占有四个随机服务端口作预约，并分别等待真正的 Shadowsocks TCP 与 SOCKS TCP listener ready，避免慢速 cross/QEMU runner 的控制面就绪与代理就绪竞态。
- 本地 `cargo test -p clash-lib --test shadowsocks_integration_tests --all-features --locked -- --test-threads=1` 4/4 通过；Clippy all-features `-D warnings`、fmt/diff check 通过。跨平台 CI 仍需新提交后复核。

## 跨平台根因复核：区分代码、测试与环境（2026-10-09）

- **不要将跨平台 CI 失败一概归为 Runner 问题。** PR #56 `4a6d8de` 的最新 CI 显示 GNU Linux x86_64、Windows x86_64、macOS ARM64、ARMv7 均通过，但 Linux x86_64-musl 的 SS2022 TCP 用户归属测试报 `UnexpectedEof`，Linux i686-musl 的 AnyTLS UDP 测试在十秒后无回包且 echo 目标未接收包。x86_64-musl (`-F perf`) 与 GNU (`-F plus`) 的有效 feature 等价：`perf = ["plus"]`，因此 feature 开关本身不能解释两者差异；然而 musl libc、cross 容器运行环境和内核网络行为仍可能影响时序。单靠 OS/ABI 对比不能证明是库缺陷或平台缺陷。
- **测试协议错误，已修复：** `shadowsocks_multiuser_tests` 的 TCP echo 服务器原先只执行一次 `read()`，立即把不一定完整的前缀回写并关闭 TCP 连接；客户端却要求 `read_exact(payload_len)`。TCP byte-stream 不保证一次 read 等于一次 write，分片或读短会直接诱发 `UnexpectedEof`。改成 echo 服务端对明确的 payload 长度 `read_exact()` 后再回写完整消息，所有字节断言保留。这是与平台无关的测试缺陷，在不同 libc/调度下暴露概率可能不同。
- **生产状态缺陷，失败先行确认：** PR 新增 SS2022 UDP anti-replay 窗口曾只按客户端 SocketAddr 保存当前 session；相同 socket 的 A(0)→B(0)→A(0) 会错误接纳最后的 A(0)。新增测试 `replay_from_previous_session_must_not_be_accepted_after_session_change` 在旧实现实际失败，修复为键 `(source, client_session_id)` 的 128-bit 有界滑窗，仍允许 session 切换与乱序合法包，不跨 session 重置已见过的序号。缓存总项数限制 2048，并以淘汰换取有界内存；不能声称对无限久以前的 session 提供持久抗重放保证。
- **musl AnyTLS UDP 根因暂未证明：** 当前只有 SOCKS5 UDP 单发 10 秒无回包、目标 echo 未收到的证据，不能由此判定底层 UDP 不支持，也不能只加大超时。测试为 musl 环境开启端到端 debug 日志，并在发出 SOCKS5 UDP datagram 时记录 relay/target 地址。还同时保留四个唯一的监听端口、分别等待 AnyTLS 和 SOCKS 业务端口就绪，以排除已知端口/启动竞态；协议断言和超时阈值未改变。等 Linux i686-musl 的下一轮完整 CI 判断 datagram 卡在 SOCKS、AnyTLS UoT 还是网络规划层。
- **平台证据边界：** 这里的本地 all-features 单元、Shadowsocks 多用户与 AnyTLS TCP/UDP 集成测试是在 macOS/Nix 运行，不代表 musl 或 i686 真实运行通过。Linux 专用网络采样/sock_diag 检查和实际 ABI 差异仍必须用各 Runner 的日志确认。主分支合并前尤其要求 musl 原失败目标的可复现验证和 CI 结果，不通过 skip、`allow-failure` 或降级断言伪造绿灯。

- **更正 AnyTLS UDP 旧诊断歧义：** 原日志 `echo_server_received_packet={echo_task.is_finished()}` 只检查回显任务是否结束，不能证明报文有没有到达，尤其无法区分目标收到报文后尚未回写与真正没有收到。新测试在 UDP echo `recv_from()` 成功后用 `AtomicBool(Release)` 记录真实到达事实；超时日志分别报告 `echo_server_received_packet` 和 `echo_task_finished`，避免用任务结束状态推断网络丢包。测试成功条件、原有 10s 截止与端到端回包断言保持不变。

## Missing outbound selection: fail closed

A route, proxy group, or runtime mode must explicitly authorize DIRECT.
When a rule selects a named outbound that cannot be found at dispatch time,
TCP is closed and UDP datagrams are dropped rather than transparently falling
back to DIRECT.

## Why this matters

The configuration validator already rejects references to unknown proxies
at initial load. A missing handler can nevertheless occur at runtime if
outbounds or providers are being replaced, or if a route and registry are
temporarily out of sync. Treating absence as permission to use DIRECT
can expose destination traffic that the user intended to proxy.

The Dispatcher shares outbound resolution between TCP and UDP; a missing
handler has no substitute, while genuine lookup/pool errors remain errors.
Direct mode, an explicit DIRECT rule, and a group that has deliberately
selected DIRECT continue to use direct networking.

This is an intentional tightening of existing compatibility behavior. A
configuration that depended on an implicit direct fallback should add an
explicit MATCH,DIRECT rule (where direct traffic is intended) rather than
rely on a missing proxy name.

## Verification

- A regression test first demonstrated that a missing named outbound would
  select the available DIRECT handler; after this change it does not even
  query that handler.
- A separate test confirms an explicitly selected DIRECT handler works.
- An integration test confirms unknown names in static routing rules are
  rejected during configuration load.
- Existing composite TCP/UDP DIRECT integration tests and UDP recovery
  tests verify explicitly allowed traffic remains functional.

This does not claim that every possible dynamic registry race is exercised
end-to-end: those scenarios still need deterministic injectable runtime
lifecycle tests.
