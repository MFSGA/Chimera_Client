# Core / Router 渐进式重构迭代计划

日期：2026-10-02。状态：暂缓，实施尚未开始。

用户已将当前目标调整为主机网络变化后的可用性。下一轮执行 [网络变化可用性计划](network-availability-iteration-plan.md)；本记录保留作为后续架构设计参考，R0–R3 不再是当前实施队列，也不是网络恢复的前置依赖。

本轮目标：建立最小 Core 数据模型和可替换的路由调用边界，保留当前 Router 的决策、DNS 调用、Session 更新、统计与错误行为。交付边界为 R0–R3；通过每个切片的检查后才推进依赖它的下一步。

设计参考为用户提供的 `Chimera_Client_Progressive_Refactor_Coding_Guide_zh.md`。其中示例是设计建议，本计划按当前源码调整；本次请求只涉及计划，不执行文档中的实现、提交或启动步骤。

## 1. 基线与工作区

| 项目 | 本轮只读核查结果 |
| --- | --- |
| Chimera HEAD | `3b0618165a657bd206378e203f22ed6ced4150e5` |
| 本地 `ref/` | `39d06a49ccb5c812ed7cd70b3028f3efcebeae6b` |
| 本地 `ref-mihomo/` | `63bd52ec794b7051569b76ede2f6cdbf4c091fda` |
| 本地 `ref-meow/` | `3bf59376708809386c20b648c4d709148a077a79`；本轮无需迁移其实现 |
| 工具链 | `rustc 1.99.0`，`cargo 1.99.0`；仓库选择 `stable`，并使用本地 `tokio_unstable` / `RUSTC_BOOTSTRAP` 配置 |
| 架构起点 | 当前无 `core` 模块、`FlowContext`、`RouteEngine` 或 `CompiledRouteEngine` |
| 已有资料 | 根目录 `ITERATION_PLAN.md` 保留历史迁移记录；`docs/20260928-tun-dns-macos.md` 保留 TUN/DNS 验证边界 |

开始时已有用户改动：`.gitmodules`、`AGENTS.md`、`flake.lock`、`flake.nix`、新增子模块 `ref-meow`，以及未跟踪的 `mihomo-tun-start.sh`、`record-release-log.sh`、`run-tun-fake-ip-demo.sh`。这些不属于本轮重构，保留原状。三个参考目录的 `git status --short` 均为空；参考提交来自本地检出，不声称是远端最新版。

当前 `clash-lib` 默认 feature 为 `zero_copy,tls,aws-lc-rs,tun,port,reality,vless-encryption,extended-health-check`；CLI 默认为 `standard,aws-lc-rs,dashboard`。新 Core 类型不引入可选依赖，不增设表示迁移状态的 Cargo feature，也不改变默认 feature。当前 `trojan` 已依赖 `tls`，历史文档中的旧描述不能作为本轮事实。

## 2. 已核实的调用链与契约

```text
clash-bin/src/main.rs → start_scaffold → 运行时组件装配
Inbound / TUN → Dispatcher
  TCP：dispatch_stream
  UDP：dispatch_datagram 内逐包构造 Session
    → fake-IP 反查与进程名补充
    → mode = Rule 时 Router::match_route(&mut Session)
    → OutboundManager 按目标名查找 handler
    → connect_stream / connect_datagram → 流量跟踪

DNS respect-rules → DnsRuntimeProvider::pick_outbound
                 → Router::match_route(&mut Session)
Controller /rules 与 rule-provider API → 同一 Router 的快照 / provider
```

核心入口为 `clash-lib/src/app/router/mod.rs::Router::match_route`：

```rust
pub async fn match_route(
    &self,
    sess: &mut Session,
) -> (&str, Option<&Box<dyn RuleMatcher>>)
```

| 当前行为 | 重构必须保留的约束 |
| --- | --- |
| 按 `rules` 原始顺序扫描，首条匹配即返回 | 不能按 matcher 类型重新排序 |
| 需要 IP 的规则可调用 `resolve(host, false)` | 保留调用时机、次数及 `no-resolve`；解析失败后仍可能在后续规则重试 |
| 匹配过程中写入 `resolved_ip`、`country`、`asn` | 不能在临时 Session 中更新后丢弃，也不能只比较目标名 |
| 无规则命中返回 `("MATCH", None)` | 区分显式 MATCH 规则与无命中；不提前改写为 DIRECT |
| 目标名既可指代理节点，也可指组或内建出站 | 不把指南的 `Proxy(String)` 限定为组名 |
| Dispatcher 找不到目标时回退 DIRECT | 保留 TCP/UDP 数据面的现有回退行为 |
| DNS respect-rules 在 router / outbound 不可用时返回错误 | 保留 DNS 路径的 fail-closed 行为 |
| `TrackedStream` / `TrackedDatagram` 使用匹配规则的类型与 payload | 只有 target / rule index 不足以保留 Controller 统计 |
| TCP 在缺进程名时补充；UDP 逐包查进程并设置 `inbound_user` | 不合并两条路径而改变身份或归属信息 |
| fake-IP 映射缺失时丢弃对应 TCP 流 / UDP 包 | 在路由适配层前保留拒绝路径 |

`Session` 目前只有 `process_name`，没有可靠 PID、独立 process path 或 application attribution。`PROCESS-PATH` 当前对 `process_name` 做子串匹配。模型不能凭空填入 PID，也不能借重构改变该规则语义。

本地 `ref/` 使用 `RuleEntry` 包装 matcher，本地 Chimera 返回 matcher 本身；迁移参考测试时需适配类型。本轮优先冻结 Chimera 的现有行为，单独记录差异，不把参考实现机械覆盖到本地。

源码核查发现三项需独立调查的语义疑点：`RuleSet` / `CompositeRule` 未覆写 `should_resolve_ip()`；IP-CIDR provider 查询未使用 `Session.resolved_ip`；provider 查询锁忙时返回不匹配。相关代码在本地 `ref/` 也有类似实现，但本次没有运行最小复现，不能认定为已确认的上游缺陷。R0 先记录当前结果，并让 provider fixture 等待初始化完成；结构重构不顺带修正这些行为。

## 3. 本轮切片

| 切片 | 产出与涉及文件 | 验收条件 |
| --- | --- | --- |
| R0：冻结当前契约 | 在本记录补齐调用链；在 `app/router/mod.rs` 附近新增路由兼容测试；复用 resolver mock、临时 provider 文件与现有集成辅助 | 新用例在原 Router 上实际执行；记录目标、匹配规则、Session 更新和 resolver 次数 |
| R1：最小 Core 模型 | 新增 `core/{mod,flow,decision,trace}.rs`，在 `lib.rs` 导出；Session 转换放在内部适配层 | Core 本体不依赖 Router/DNS/出站；转换保留地址、端口、协议与已知身份，不改变调用链 |
| R2：Legacy 适配层 | 在 `app/router/` 新增 `RouteEngine` 和 `LegacyRouteEngine`，包装已有 `Arc<Router>`；先不切换调用方 | 同一组 fixture 分别运行原 Router 与 adapter，结果、规则信息、DNS 调用及 Session 副作用一致 |
| R3：TCP/UDP 接入 | 修改 `dispatcher_impl.rs` 及 `lib.rs` 装配；保留同一 Router 供 DNS、API 和 providers 使用；扩充本地集成回归 | TCP 与 UDP 的 Rule 模式均经过 adapter；Global/Direct、统计、回退、热重载和 DNS 路径保持兼容 |

R0 必须先于 R2/R3。R1 可以在 R0 的契约明确后实施；每个切片应可独立编译、审查和回退。若 R3 中装配与数据面变化过大，可分为两个提交，但不得留下 TCP/UDP 使用不同决策实现的最终状态。提交粒度是未来实施建议；本次不创建提交。

### R1 的模型边界

- 保留指南建议的 `TransportProtocol`、`Endpoint`、`ProcessIdentity`、`ApplicationIdentity`、`FlowContext`、`RouteTarget`、`RouteDecision`、`DecisionTrace`。
- `Endpoint` 保留 IPv4/IPv6 socket 与原始 domain/port；转换时不额外解析或规范化域名。注意现有 `SocksAddr::clone()` 会把 IP 字面量 domain 转成 IP，不能无意将这种行为引入新的借用转换。
- `FlowContext` 作为快照，增加独立的可选 `resolved_ip`，允许域名与解析 IP 并存。其余尚未迁移的执行字段仍由原 Session 持有，不做 Flow → Session 的反向重建。
- `ProcessIdentity.pid` 使用 `Option<u32>`；已知名字可保留，PID/path 未知时为 `None`。`ApplicationIdentity` 只预留类型，适配结果为 `None`，本轮不做进程归因采集。
- `RouteTarget::Proxy(String)` 表示任意命名代理节点或组；未知名字原样保留。规则序号统一为原始列表的零基索引，`None` 表示无匹配规则；序号只在所属 Router 实例内有效。
- 新类型附公开 API 注释；不增加无调用场景的序列化格式或 Controller 字段。

### R2/R3 的适配决定

第一版 `RouteEngine` 放在应用层，使用 async 方法并保留 `&mut Session` 和当前借用结果（目标名与匹配 matcher）。`LegacyRouteEngine` 原样调用 Router，不新增一次 DNS 查询、Session clone 或规则日志。这样先建立可替换边界，并保留现有 tracker 调用。

这是相对指南 `decide(&FlowContext) -> RouteDecision` 的明确过渡设计：当前不可变快照无法完整表达 Router 的更新与统计依赖。Core 模型先独立建立，Flow 原生接口在后续拥有明确的 enrichment / rule metadata 契约后再接入；不承诺本轮已经实现 Flow 原生路由。

保持现有 `Dispatcher::new` 的对外调用兼容，可在构造函数内部包装 adapter；测试注入入口控制在内部。API/provider 与 `RuleDispatch` 继续引用同一 `Arc<Router>`；重载时 adapter 随新 Router 一起构造，不留旧实例引用。DNS 路由本轮继续使用 Router，并通过回归证明其错误行为不变。

## 4. 兼容用例清单

以下是 R0–R3 的目标覆盖，不是已通过的测试。已有覆盖应复用，缺失项补用例；使用明确输入和 mock 断言，不靠“测试数达到 10”代替行为覆盖。

| 用例组 | 必须断言的行为 |
| --- | --- |
| DOMAIN / DOMAIN-SUFFIX | 精确、子域、标签边界、当前大小写语义；域名先命中时不调用真实解析 |
| DOMAIN-KEYWORD / DOMAIN-REGEX | 当前匹配语义与负例 |
| first-match | 多种规则同时匹配时最早规则胜出；重复规则保留身份和顺序 |
| IP-CIDR v4/v6 | 纯 IP 与 domain 解析路径；正确目标和 `resolved_ip` 更新 |
| GEOIP / GEOSITE 与地理信息 | 本地可控 fixture / mock；目标匹配及 country/asn 更新，不触发数据库下载 |
| no-resolve / SRC-IP-CIDR | 不发 DNS 请求；保留已有解析 IP 与源地址的当前使用方式 |
| DNS 失败 / 空答案 | 后续规则、可能的重复解析及最终 fallback；不将当前容错改成新错误 |
| PROCESS-NAME / PROCESS-PATH | exact / substring 与未知进程；不依赖 OS 查询结果 |
| NETWORK / SRC-PORT / DST-PORT | TCP/UDP、源/目的端口不混淆 |
| AND / OR / NOT | 复合表达式、嵌套与当前解析行为 |
| RULE-SET | 本地 provider fixture，顶层目标、provider 更新可见性和当前解析语义 |
| MATCH / 空规则 | 显式 MATCH 的规则信息与无命中的 `None` 不混淆 |
| DIRECT / 命名节点 / 命名组 / REJECT | 保留原目标、后续 handler 行为及规则统计 |
| 缺失目标 | Dispatcher 回退 DIRECT；DNS respect-rules 报错，两条路径各自验证 |
| fake-IP | TCP/UDP 反查保留域名；无映射拒绝；IPv6 不丢失地址族 |
| 出站本地解析 | 保留 `proxy_resolve_local` 与 DIRECT resolver 的当前选择，不新增提前解析 |
| tracker / reload | 规则 type/payload、代理链、`inbound_user` 保留；重载后新连接使用新规则 |

发现现有行为疑似错误时，先记录最小复现与参考提交，区分本地差异、上游问题和测试环境失败。R0 的 characterization 用例不等于认定该行为是长期正确契约；修复另开切片，避免混入结构重构。

## 5. 实施时验证顺序

所有命令从仓库根目录运行；以下均为计划命令，本次未执行编译或测试。

R0 先确认原有基线：

```bash
cargo check -p clash-lib --locked
cargo test -p clash-lib --lib session::tests:: --locked
cargo test -p clash-lib --lib config::internal::rule::tests:: --locked
cargo test -p clash-lib --lib app::router::rules:: --locked
cargo test -p clash-lib --lib app::dispatcher::dispatcher_impl::tests:: --locked
cargo test -p clash-lib --lib app::dispatcher::statistics_manager::tests:: --locked
cargo test -p clash-lib --lib app::dns::runtime::tests:: --locked
cargo test -p clash-lib --test composite_rule_integration_tests --locked -- --test-threads=1
```

每个切片运行受影响用例，并保留命令、执行数量和结果。新测试模块建立后，定向运行它；使用 `-- --list` 确认全名，精确用例加 `-- --exact`，零用例不计通过。

| 检查层 | 命令 | 执行时机 |
| --- | --- | --- |
| 格式 | `cargo fmt --all -- --check` | 每个切片；检查前仅格式化本轮文件，避免带入无关改动 |
| 最小候选组合 | `cargo check -p clash-lib --no-default-features --locked` | R0 重新建立当前基线，R1–R3 检查新增无条件依赖；历史记录通过不代替本次结果 |
| 基础加 TUN | `cargo check -p clash-lib --no-default-features --features tun --locked` | 涉及装配或条件编译时；失败需定位，不追加无关 feature 掩盖 |
| 默认核心 | `cargo check -p clash-lib --locked` | 每个切片 |
| 默认 CLI | `cargo check -p clash-rs --locked` | R1 导出变动与 R3 装配后；包含真实 Dashboard 构建前提 |
| Ring 组合 | `cargo check -p clash-lib --no-default-features --features ring,port,trojan,ws --locked` | R3；不叠加强制 AWS-LC 的 Reality |
| 本地数据面 | `cargo test -p clash-lib --test composite_rule_integration_tests --locked -- --test-threads=1` | R0、R3 |
| UDP / 代理链 | `cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1`；`cargo test -p clash-lib --test connection_chain_tests --locked -- --test-threads=1` | R3 |
| 热重载 | `cargo test -p clash-lib --test api_reload_tests --locked -- --test-threads=1` | R3 |
| CI lint | `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` | R3 完成前 |
| CI 数据面 | `cargo test -p clash-lib --test lan_proxy_tests --all-features --locked` | R3 完成前 |
| 默认单元回归 | `cargo test -p clash-lib --lib --locked` | R3 完成前；不自动运行 ignored 测试 |
| 最终 diff | `git diff --check` 与人工审阅本轮 diff | 每个切片 |

若 Dashboard、原生依赖或既有 feature 组合阻塞，记录完整错误和影响范围。关闭 Dashboard 的 CLI 检查可以帮助定位，但不能替代默认 CLI 验收。R0 失败项先分类；与其相关的依赖切片保持待验证，只推进独立分析。真实 TUN、系统 DNS、公共网络、跨平台实机与吞吐验证不作为本轮常规执行项；编译成功不等于这些行为已验证。

## 6. 下一轮入口与后续顺序

R0–R3 验收后，下一轮先设计 Flow 原生请求/结果契约，明确 enrichment、匹配规则元数据和 provider 快照，再引入线性 `CompiledRouteEngine`。

Shadow 必须显式启用，生产结果继续来自 Legacy；比较 target、规则索引/元数据及相关副作用。新引擎不得重复发送真实 DNS 查询、修改共享 Session、更新生产缓存或影响 provider 生命周期；使用同一规则版本和受控解析事实进行对照。Shadow 出错不改生产决策，并记录有界、脱敏的差异；运行时启用前明确耗时预算、取消和任务回收，不直接把第二次 await 串入生产关键路径。若当前数据不足以重放，先补采集契约，不能把有副作用的两次路由调用直接并排运行。

兼容性通过后逐项考虑：Domain 索引 → IP 索引 → Process / RuleSet 索引 → 带 policy generation 的缓存 → ApplicationIdentity 归因 / APP-ID → Resolver 抽象 → FakeIPMapper。每项重新建立验证门槛，不以本轮计划授权全部实施。

缓存键届时必须覆盖实际规则所依赖的源/目的地址与端口、协议、进程及其他身份信息；指南的示例键不能直接覆盖当前 SRC-IP-CIDR、SRC-PORT、PROCESS 与复合规则。provider 更新和配置重载都需要明确的失效策略。

## 7. 持续执行记录

| 项目 | 当前状态 | 证据 / 下一步 |
| --- | --- | --- |
| 本轮计划 | 已完成 | 已只读核查调用链、Cargo 清单、现有测试、CI 和本地参考代码；本次修改计划文档，并为新记录添加精确的 `.gitignore` 例外 |
| R0 | 待开始 | 先运行第 5 节基线命令，再建立 Router characterization fixtures |
| R1 | 待开始 | R0 明确契约后新增最小类型与转换用例 |
| R2 | 待开始 | 原 Router / adapter 双路径等价检查 |
| R3 | 待开始 | TCP/UDP 接入、装配与本地集成回归 |
| Compiled / Shadow | 后续评审 | 本轮完成后确定 Flow 原生契约与无额外副作用的比较方案 |

本次计划交付检查：`git diff --check` 通过；两份计划文件的存在与行尾空白检查通过；`git status --short` 确认新记录未被忽略，已有用户改动保留。未运行 Rust 编译、测试或任何网络实例，R0–R3 不计为已验证完成。

实施时在本节追加：起止提交、实际改动文件、验证命令与测试数量、失败/未运行项、本地偏离及下一最小切片。不要仅修改状态为“完成”而省略证据。
