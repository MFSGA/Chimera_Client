# Chimera 下一代 DNS：面向 AI 编码代理的开发实施规范

> **文档版本**：v2.0 / 开发执行版（2026-10-22）  
> **项目**：`MFSGA/Chimera_Client`，Rust，下一代 Host / Gateway 网络管理核心  
> **对照源码**：公开 `master` 的提交 `71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`（2026-10-21 UTC）；执行时必须先核验本地 HEAD 并重新审计变化  
> **文档状态**：待维护者批准的设计与工作合同；本文新增 YAML/Rust API 属于**拟议设计，不是已实现配置**  
> **使用方式**：把本文放入项目 `docs/` 作为 RFC + AI 执行依据，AI 每次只推进一个可验证切片。现有仓库 `AGENTS.md` 与 `docs/ai-development-governance.md` 优先约束实际 Git/提交/审批动作。

## 0. AI 的执行目标（先读这一节）

**一句话目标**：在 Chimera 既有 DNS/代理/路由体系上，实现“Fake-IP 保持域名身份 → Business Rules 严格按用户原有顺序决定业务出口 → 真正需要解析时，DNS Policy 按 QNAME+QTYPE+用途选择解析器与 DNS 出口”，并提供安全的 SRV/GeoDNS 诊断。

必须交付的结果：

1. **选择性配置兼容**：不以全量 Mihomo 兼容为目标；明确被承诺保留的旧字段、条件保留字段及明确放弃的字段。被承诺保留的旧字段，语义不得悄悄改变。淘汰任何已存在行为都需要记录理由和迁移方案。
2. **精细 DNS Rules**：指定域名/后缀 + A/AAAA/SRV 等 QTYPE，能选择解析器与“访问 DNS 上游时”的 DIRECT/PROXY 路径；不影响应用业务出口。
3. **域名身份与解析用途分离**：Fake-IP 客户端应答不触发无意义的真实查询；DIRECT 业务内部解析，域名 PROXY 业务尽量远端解析；前置 GEOIP/IP 规则该解析仍解析，不改用户规则顺序。
4. **严格出口与缓存边界**：显式 DNS 代理路径失败不得私自回退直连；不同 DNS 出口的响应、连接池不能越权复用；Bootstrap 不形成递归依赖。
5. **游戏服务发现/诊断**：正常处理 SRV 与后续 A/AAAA 的独立规则；只读比较 DNS 污染、GeoDNS/负载均衡及游戏实际目标网络质量；不擅自改 SRV Priority/Weight 或业务出口。
6. **可执行交付**：每一切片有明确源码位置、输入/输出、自动化测试、失败注入、退出标准与可回滚边界。

**硬约束**：不把“DNS 解析更快”当作改变 Business Rules、用户强制出口或防泄漏策略的理由；不宣称未测试的功能已经兼容 Mihomo。

### 0.1 AI 开工前必须执行的检查

```bash
# 仓库根目录；先阅读仓库自身规则
cat AGENTS.md
cat docs/ai-development-governance.md
# 无破坏性 git 操作，只读检查
 git status --short --branch
 git rev-parse HEAD master origin/master
 git submodule status
# 核对配置/调用链/测试是否与本文基线一致
rg -n 'nameserver_policy|nameserver-policy|fake_ip_filter|respect_rules|direct_resolver' clash-lib/src
rg -n 'exchange_with_resolver|match_policy|exchange_no_cache|pick_outbound' clash-lib/src/app/dns
rg -n 'dns_|fake_ip|GEOIP|no-resolve' clash-lib/tests
```

如工作区有用户未提交改动、`master` 被其他 worktree 占用、SHA 分叉，先保护现状；不自动 `reset/stash/rebase/cherry-pick`。仓库约定默认**本地 `master` 分阶段签名提交**，而不是每轮自动建 PR；不能自动推送、合并、发布。每个本地提交依 `AGENTS.md` 使用 `git commit -S`、`git verify-commit HEAD` 核验；签名条件不满足则停止提交并报告，不能降级为未签名提交。

### 0.2 功能不会仅因本文存在就自动启用

- 本文 `dns.policy-rules`、`resolver-profiles`、`service-discovery-mode`、诊断 API 均是**设计提案**。
- 实施中不得一次把下面所有 Rust 结构和配置字段一起落地；先测试、再增加最小配置、再执行、最后做高级诊断。
- 任何需要修改系统 TUN、路由表、DNS 重定向的集成测试必须在隔离环境执行；普通自动化测试只使用离线报文、Mock DNS/Proxy 与回环接口。

---

## 1. 需求与可证明的行为边界

### 1.1 正确的产品预期

- **客户端答案与上游查询不同**：Fake-IP 客户端 A/AAAA 若能本地合成，即使配置了 DNS egress，也不会因此额外访问上游。
- **上游解析路径与业务路径不同**：`dns.egress = proxy` 的意义是“Chimera 如何连接 DNS 服务器”，不是“游戏或网页流量走代理”。
- **DNS 污染与目标阻断不同**：代理 DoH 获取可信答案后，业务 DIRECT 仍可能失败；不能据此默默改成代理业务连接。
- **代理场景不无故解析真实目标**：规则已决定 `PROXY` 且出口支持主机名时直接发送域名；如果用户把 GEOIP 放在域名规则前，必须按匹配语义执行必要的 IP 分类查询（`no-resolve` 例外）。
- **游戏 SRV 不等于某地区节点**：DNS 返回不同 SRV 可能是污染、GeoDNS、权重轮换、递归器缓存或运营商策略；诊断应展示证据和“不确定”。
- **下载加速不属于 DNS 的保证**：DNS 只负责正确解析与提供候选目标；多出口下载吞吐和单 TCP 连接聚合属于 PathScheduler/传输层的后续能力。

### 1.2 第一版明确非目标

- 不实现 Mihomo DNS 所有字段；具体范围见 §2。
- 不自动选择、重排或改写 SRV Priority/Weight；不擅自添加游戏地区节点。
- 不修改 Business RuleEngine 的用户顺序、first-match 或 `no-resolve` 语义。
- 不默认启用 ECS、不默认把所有真实解析走代理、不无限重试 DNS。
- 不宣称能识别所有 ECH/DoH/硬编码 IP 客户端流量的域名。
- 不在数据包快路径调用 LLM 做 DNS 决策。

---

## 2. **选择性兼容契约**：核心继承、有据淘汰、禁用静默忽略

> 设计方向已确定：**不要求全面兼容 Mihomo**。但“不兼容”必须是有记录的产品选择，尤其不能让用户以为配置生效却实际上被忽略。

### 2.1 三种状态必须分别标注

- **A — Core/Keep（稳定承诺）**：当前 Chimera 已支持，且属于下一代核心场景；保持格式与既有语义，可在内部重构实现。
- **B — Legacy/Review（受控继承）**：当前已实现但与新体系部分重复；第一版可保留旧路径，后续决定迁移、废弃或提供兼容层。没有批准和回归测试前不可移除。
- **C — Skip/Reject（明确不追随 Mihomo）**：Mihomo 存在而当前 Chimera 尚未实现、且不属于优先方向的功能，允许不实现；若用户显式配置，应在**约定的 native 严格解析模式**告知不支持与替代方案，而非假装实现。

**一条额外约束**：已经在 Chimera 中真实实现并被使用的行为，不会因为“现在划进 C 类”而自动变成无成本弃用。删除它仍然是破坏性变更，需要单独决策记录。

### 2.2 第一轮字段取舍建议（候选，需代码审计确认）

| 配置/机制 | 初步状态 | 原因与处理方案 |
|---|---|---|
| `enable`、`listen`、`ipv6` | A | DNS 服务基础配置；保留原默认与协议含义 |
| `nameserver` | A | 默认上游不可缺；旧值形态保持 |
| `nameserver-policy` | A（**当前已实现子集**） | 域名选择解析器有价值；保持现有 `HashMap<String,String>` 输入能力，不承诺 Mihomo 全部值形式 |
| `enhanced-mode: fake-ip`、`fake-ip-range`、`fake-ip-filter` | A（**当前已实现子集**） | 域名身份的基础；保留已证实的实际语义，不假设未测试的 Fake-IPv6 支持 |
| `proxy-server-nameserver`、`default-nameserver` | A | 节点及 DNS 端点引导仍需要专用解析策略 |
| `direct-nameserver` | A（现有可用行为） | DIRECT 连接真实解析仍是核心；可在新用途模型中逐步统一 |
| `respect-rules`、服务器地址 `#proxy` / `#interface`（实际支持的部分） | B | 老机制有实用价值，但不应与新显式 DNS egress 冲突；保留旧行为，再逐项决定是否弃用 |
| `fallback` / `fallback-filter` | B | 现有实现有行为依赖；下一代可用命名 resolver group、显式 failure policy 取代，但不能无评审直接删除 |
| `fake-ip-range6` | B（验证实现程度） | 字段存在不等于 Fake-IPv6 数据面完整；先补端到端测试 |
| `enhanced-mode: redir-host` | B（待审） | 当前代码存在“不支持/告警”路径；如拟废弃，必须说明识别旧值与实际执行差异 |
| Mihomo `fake-ip-filter-mode: rule/whitelist` | C（若当前未实现） | V1 不追完整语法；未来可通过明确的客户端应答策略扩展，不影响现有 filter |
| Mihomo `proxy-server-nameserver-policy`、`direct-nameserver-follow-policy` | C（若当前未实现） | 暂不实现特殊政策叠加；新规则按用途建模，但必须明确迁移差异 |
| Mihomo `cache-algorithm`、`prefer-h3`、`fallback-lazy-query` | C（若当前未实现） | 不优先追逐调参字段；先保证正确缓存隔离与传输安全 |
| Mihomo 高级 DNS URL 修饰语、rule-set 值数组/高级 geosite 语法 | **逐项审计** | 已支持部分按 A/B 处理；未支持且无产品需求的部分按 C，不可用一句“全面兼容”概括 |

本矩阵是建议的**兼容边界**，不是自动执行的删除清单。最终是否属于当前已实现，必须用固定 commit 的源码、测试与实际加载行为标注 `implemented / partial / unsupported`；与“产品是否打算保留”两个维度**分别记录**。

### 2.3 需要允许破坏性变更时，必须写出具体理由

破坏性变更是允许的，但必须同时满足：

1. 指明**明确的旧行为/字段**，提供可复现配置与真实影响；不能用“旧设计不好”概括。
2. 证明不兼容的必要性，例如安全泄漏、语义不可消除的冲突、维护成本明显超出使用价值、与新能力长期存在不可解决的行为分歧，或用户已明确决定不提供该功能；必须给出证据/权衡。
3. 说明为什么不能通过新字段 opt-in、兼容解析层或 deprecation warning 保留。
4. 给出迁移示例、错误提示、可回滚策略、测试和生效版本。
5. 需要维护者按仓库治理规则审查和批准。**本文不能替代批准**。

模板：

```text
Decision: DNS-COMPAT-XXXX
旧配置与实际语义：
新设计/不支持的具体能力：
决定：KEEP / DEPRECATE / REJECT / REMOVE
实证理由与替代方案比较：
受影响用户、版本与配置示例：
不保留兼容层的原因：
迁移前后完整示例：
加载失败/弃用警告文案：
安全和功能回归测试：
发布日期/弃用期/回滚方案：
评审与批准状态：
```

**示例提案，未批准**：如果未来用统一 `resolver-profiles` 取代 `fallback-filter`，理由可以是过滤式后备容易与显式严格 DNS 出口/信任组产生歧义；但如果没有证明真实冲突、迁移等价性与使用情况，不能立刻移除 `fallback-filter`。保留旧模式是第一选择。

### 2.4 未支持配置的解析行为：避免“静默假成功”

- 新定义的 `policy-rules` / `resolver-profiles` 对象建议采用严格字段校验（如局部 `deny_unknown_fields`），拼错动作应**加载失败**。
- 当前项目老配置使用 Serde/YAML，部分不认识的 Mihomo 字段可能被默认忽略。直接把整个旧 `dns` 对象改成“所有未知字段都报错”，本身是破坏性变更；不得偷偷实施。
- 建议先建立**旧兼容解析路径 + 新配置严格校验路径**：对已明确决定不支持的字段记录警告；确需改为报错时，按上面 Decision 模板评审其破坏范围。
- 对声称支持的字段，**不得解析成功但运行时无效且无解释**。已知实现缺口记录为 `partial` 并给出诊断。

### 2.5 Phase 0 必须先产出两张矩阵

`docs/dns-compat-matrix.md` 每行至少含：字段、Mihomo 语义/来源、当前代码是否接受、当前真实行为、产品取舍(A/B/C)、是否会破坏、迁移例子、验证用例、决策编号。另建 `docs/dns-legacy-golden.md` 或测试 fixture 索引，记录被保留配置的**可观察输出**（应答类型、选中解析器/出口、失败与回退、规则 trace）。

禁止“因为新架构优雅，批量删除旧字段”；每项弃用单独决策。

---

## 3. 源码基线和已确认可复用模块

**基线 SHA：** `71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`，公开 master（2026-10-21）。实施以本地检出为准；若本地 HEAD 不一致，先建立差异表，不能把本文观察当作最终事实。

| 位置 | 基线可见事实 | AI 该做什么 |
|---|---|---|
| `clash-lib/src/config/def.rs` | `DNS.nameserver_policy: HashMap<String,String>`，包括旧 `nameserver`、`fallback`、`direct_nameserver`、`respect_rules` | 保留现有字段的反序列化；新增字段保持可选 |
| `clash-lib/src/app/dns/config.rs` | `NameServer` 包含 `proxy`、`interface`；`parse_nameserver_policy()` 当前返回单个 `NameServer` 映射 | 新策略单独编译，不改旧解析器输入含义 |
| `clash-lib/src/app/dns/resolver/enhanced.rs` | `EnhancedResolver` 有 `match_policy`、`ip_exchange`、`lookup_ip`、`lru_cache`、`direct_resolver`；`match_policy` 按域名选择 DNS client | 新增查询上下文和计划，先在真实解析入口 shadow 对比 |
| `clash-lib/src/app/dns/server/handler.rs` | `exchange_with_resolver()` 处理合成 Fake-IP、非 A/AAAA 的保守应答，近期增加 Fake-IP PTR 与多 Question FORMERR | SRV/HTTPS 的 opt-in 安全策略必须从此链路入手，不能直接全局放开 |
| `clash-lib/src/app/dns/fakeip/` | 已有映射存储与反查 | 验证映射生命周期、租户隔离、IPv6 交付范围 |
| `clash-lib/src/app/dns/runtime.rs` + `rule_dispatch.rs` | `respect-rules` 的 DNS dialer 可复用已有 outbound；不能让新 DNS egress 意外再次执行业务规则 | 在 dialer 入口显式传 `DnsEgressPlan`，先完成回环测试 |
| `clash-lib/src/app/dns/health.rs` | **已经有**被动 DNS 健康跟踪，NXDOMAIN 不算端点失败；上游观测与本地 Fake-IP 分离 | **不要再创建第二个健康系统**；只补充按出口/网络代际的上下文与诊断 |
| `clash-lib/src/app/dispatcher/dispatcher_impl.rs` / `router/` | 已有 Dispatcher、规则选择、Direct 路径相关逻辑 | 不动规则顺序；给最终解析传递用途，避免分类解析当成代理目标 |
| `clash-lib/tests/dns_config_tests.rs`、`tun_fake_ip_real_tests.rs` 等 | 已有 DNS/TUN 用例 | 先补旧行为快照，然后加新规则与故障注入用例 |

**近期源码差异提醒**：原先设计稿以较早仓库状态为依据；当前基线已出现 `dns/health.rs`、Fake-IP PTR、多问题检查、DNS 请求诊断等改动，**AI 必须复读当前代码，不能照旧稿直接添加重复模块**。

参考资料：
- 源码：<https://github.com/MFSGA/Chimera_Client>（固定 SHA：`71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`）。
- Mihomo 官方 DNS 说明：<https://wiki.metacubex.one/en/config/dns/>，仅作为被选择功能的语义对照，**不作为全量移植清单**。
- DNS SRV：RFC 2782；ECS：RFC 7871；DNS 基本语义：RFC 1034/1035。标准只指导协议正确性，不保证游戏一定 GeoDNS。

---

## 4. 最终架构：一条流量链、三类独立策略

```text
[客户端 DNS] ----> DnsFrontend ----> ClientAnswerPolicy
                        |                 | fake/local/real/reject
                        |                 v
                        |            FakeIpRegistry / RealAnswer
                        |
[客户端连接] ----------> FlowIdentity <-- Fake-IP reverse map
                             |
                             v
                      Business RuleEngine
                      严格用户顺序 / first-match
                             |
                 +-----------+------------+
                 |                        |
              DIRECT                    PROXY
                 |                        |
       RealResolutionPlanner       支持域名目标？
           purpose=Direct           |yes          |no
                 |                  v             v
       DNS Policy + Resolver     传递域名    显式的目标解析
                 |                  |             |
                 +---------> PathScheduler <------+
                                  |
                             Connection Execute
                                  |
                       Observation / DecisionTrace

真实 DNS 查询路径：
RealResolutionPlanner / ClientRealAnswer / Diagnostic
          -> DnsQueryContext
          -> DnsPolicyMatcher
          -> LegacyResolverPlanner（若新规则不覆盖）
          -> DnsEgressPlanner（direct / proxy:group / legacy）
          -> ResolverRuntime -> ResponseGuard -> Cache / Diagnostics
```

### 4.1 不可违反的策略分工

- **ClientAnswerPolicy**：客户端看到 Fake-IP 还是正常 DNS 响应；尊重 `fake-ip-filter` 等旧机制。
- **DnsPolicy**：若实际需要上游查询，选择谁解析、按何种网络路径访问它、失败能否回退。
- **Business Rules**：决定业务流量 DIRECT、PROXY、REJECT 等；匹配顺序是用户意图。
- **PathScheduler**：在已经允许的业务出口约束中选择网卡/IP 族/具体代理节点；不篡改 Business Rules。
- **DnsDiagnosticService**：可主动测试多种解析路径，但其结果不能自动生效成路由策略。

### 4.2 业务规则顺序是绝对契约

```yaml
rules:
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,example.com,PROXY
  - MATCH,DIRECT
```

如果第一条 GEOIP 规则需要解析且未设置 `no-resolve`，则必须进行分类用途 DNS 查询：
- 命中 CN：DIRECT，后续域名规则不执行。
- 未命中：再尝试 DOMAIN-SUFFIX，可能 PROXY。
- 即使最终 PROXY，且代理支持域名连接，分类时查询到的本地 IP 不应强制成为代理的连接目标。

将 DOMAIN 规则放到前面可能更快，但引擎只能提示，**绝不自动调整**。如果 DOMAIN 规则已先命中 PROXY，就不再向后匹配前置不存在的 IP 规则，也不应无缘无故本地解析真实 IP。

---

## 5. DNS 查询模型与解析用途

```rust
// 拟议结构，不是当前现有代码
struct DnsQueryContext {
    qname: CanonicalDomain,
    qtype: RecordType,
    qclass: DnsClass,
    purpose: DnsPurpose,
    source: QuerySourceScope,       // Host: app; Gateway: device/tenant
    network_generation: u64,
    config_generation: u64,
    dnssec: DnssecFlags,
    ecs: Option<ClientSubnet>,
}

enum DnsPurpose {
    ClientRealAnswer,             // 客户端要求真实应答
    RouteClassification,          // IP/GEOIP 规则所需
    DirectDestination,            // 最终业务直连
    ProxyDestinationLocal,        // 代理不支持域名目标，必须本地解析
    ProxyNodeBootstrap,          // 代理节点自身域名
    ResolverBootstrap,           // DoH/DoT 上游域名
    Diagnostic,                  // 只读诊断探测
}

enum DnsEgressPolicy {
    InheritLegacy,
    Direct { interface: Option<InterfaceId> },
    Proxy { group: ProxyGroupId },
}

enum FailurePolicy {
    InheritLegacy,
    Fail,
    FallbackWithinDeclaredTrustGroup,
}

struct DnsPolicyDecision {
    resolver_profile: Option<ResolverProfileId>, // None = 沿用旧行为
    egress: DnsEgressPolicy,
    failure: FailurePolicy,
    rule_id: Option<RuleId>,
}
```

`DnsPurpose` 主要用于内部路径隔离和诊断，不应成为 V1 用户必须理解的复杂配置选项。后续若实际需要按用途细分策略，可再提供**可选** `purpose` 条件。

### 5.1 域名身份（Domain Identity）

业务连接关联优先级：

1. 显式入站协议携带的目标域名（例如 SOCKS 域名目标）。
2. Chimera 已分配且仍有效的 Fake-IP 映射。
3. 有上下文约束、可证明的 DNS 关联（仅作为较低可信度的辅助）。
4. SNI/HTTP Host 等可见的协议字段（有 ECH、QUIC、IP 直连等限制）。
5. 不知道域名：保留 `Unknown`，只使用用户允许的 IP/设备/应用规则。

不得简单按 `RealIP -> 最近查询过的域名` 全局推断。CDN 共享 IP、多设备并发、缓存、DNS 加密和多个域名共用地址都会使这种映射不可靠。

### 5.2 Fake-IP 映射生命周期

- 分配的 Fake-IP 映射必须在活跃流期间有效，不可提前复用给其他域名。
- 映射受租户/设备/命名空间及配置版本约束；同一局域网是否共享映射，应根据实现的路由身份边界决定。
- 过期可清理，但存量会话引用映射时不能无提示错绑。
- 明确 IPv4 和 IPv6 的 Fake-IP 策略，不允许严格模式中悄悄返回真实 AAAA 后仍声称保留域名。
- 命中 `fake-ip-filter` 的客户端查询继续走旧行为；此时透明连接可能只有真实 IP，不能凭空恢复域名。

---

## 6. 增量配置方案（对被保留的子集严格兼容）

### 6.1 推荐：被保留的旧字段原样保留，新字段 opt-in

**以下仅为 Chimera 设计草案；新字段在当前版本尚不可直接使用。**

```yaml
# 对已列入保留清单的 Chimera 字段，不改变原名称和类型
dns:
  enable: true
  enhanced-mode: fake-ip

  nameserver:
    - 192.168.1.1
  nameserver-policy:
    "+.corp.internal": 192.168.1.1
  direct-nameserver:
    - 192.168.1.1
  proxy-server-nameserver:
    - 192.168.1.1
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "+.corp.internal"

  # Chimera 新增：命名解析器；未配置则完全不影响旧配置
  resolver-profiles:
    local:
      servers: ["192.168.1.1"]
    trusted:
      servers: ["https://cloudflare-dns.com/dns-query"]

  # Chimera 新增：仅在此规则命中时覆写明示动作
  policy-rules:
    - match:
        domain-suffix: broken.example
        qtype: [A, AAAA]
      action:
        resolver: trusted
        egress: "proxy:DNS-OUT"
        on-failure: fail

    - match:
        domain: _minecraft._tcp.play.example
        qtype: SRV
      action:
        resolver: trusted
        egress: "proxy:DNS-OUT"
        on-failure: fail
```

注意：

- `DNS-OUT` 需引用已有合法代理/代理组；若代理组不可用，严格策略失败，不允许悄悄换到 DIRECT。
- `resolver-profiles` 表示解析器的可信语义及地址；`egress` 仅控制到它的传输路径。
- **不把 QTYPE 字段直接塞到旧 `nameserver-policy` 键字符串中**，避免改变旧匹配逻辑。
- 新字段默认不启用，意味着已承诺兼容的旧配置完全不依赖它。
- `policy-rules` 第一条命中生效。若命中规则缺少 `resolver`/`egress`/`on-failure` 等动作，则该维度**沿用已有配置选择**，不可自动填上新默认值。
- DNS 上游的 `#代理名`、`#接口`、`#RULES` 等旧地址修饰语按原优先关系处理；新 `egress` 若与已有服务器级强制路径冲突，应在编译期**明确拒绝歧义配置**或要求显式覆盖模式，不允许静默决定谁赢。

### 6.2 明确的决策优先级

在 **启用 `policy-rules`** 后：

1. 计算 legacy decision（包括 `nameserver-policy`、`direct-nameserver`、`respect-rules`、DNS 地址参数和默认值），但尚不执行网络请求。
2. 按 `policy-rules` 先后顺序匹配 QNAME、QTYPE、可选来源/用途。
3. 第一条命中后，仅覆盖明确填写的动作字段；未填写字段继承 legacy decision。
4. 校验出站、DNS 引导依赖、严格失败策略等冲突。
5. 建立实际 DNS 上游请求；否则如果未命中新规则，**完整执行原版 legacy 路径**。

这是一种“覆盖计划”而非另起一套 DNS 执行器。为更严格地确保旧行为，首版实现应保留 `if new_rules.is_empty() { legacy_exchange(...) }` 快捷路径，并通过对照测试证明等价。

### 6.3 QTYPE 匹配原则

- 默认不填写 `qtype` = 不限制 QTYPE。
- 支持 A、AAAA、SRV、HTTPS(TYPE65)、SVCB、TXT、MX、PTR 等标准类型，允许未认识的数值 TYPE，以便未来扩展。
- 不应只读取多问题 DNS 消息中的第一条问题后直接忽略其他问题；可以先按协议/产品约束明确拒绝多问题请求，或逐项校验，不能把一条规则误用于全部问题。
- 规则匹配基于规范化 QNAME（大小写不敏感、尾点统一、国际化域名一致化）及明确 QCLASS。

---

## 7. 客户端 DNS 应答与内部真实解析必须分离

### 7.1 A/AAAA 与 Fake-IP

**客户端请求 `example.com A`**：

1. 先沿用原有 `hosts`、Fake-IP filter 与客户端应答模式决策。
2. 若应答为 Fake-IP：在本地分配/复用虚拟 IP，记录映射；**该请求本身不需要上游查询**，所以 `egress` 不会被执行。
3. 客户端连接 Fake-IP，恢复域名。
4. Business Rules 按顺序决定 DIRECT/PROXY/REJECT。
5. DIRECT 才按 `DnsPurpose::DirectDestination` 进行真实解析；PROXY 且支持域名目标可直接转发域名。

**客户端要求真实 A/AAAA（如 fake-ip-filter 命中）**：才按 `DnsPurpose::ClientRealAnswer` 进行上游解析。若此时只有真实 IP，透明业务域名识别能力可能降低，这是原有模式的现实限制，不允许假装拥有 Fake-IP 语义。

### 7.2 业务域名 PROXY 与本地 DNS

若规则是：

```yaml
rules:
  - DOMAIN-SUFFIX,video.example,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
```

先匹配 DOMAIN，则选 PROXY；代理支持域名目标时不需要为业务连接本地真实解析。**但代理节点本身的引导 DNS 仍可能需要**。

若前置 GEOIP/IP-CIDR 需要解析，则不可跳过分类查询；`no-resolve` 语义必须原样保留。分类查询结果不得不加判断地代替代理端的真实目标 IP。

### 7.3 DIRECT 的真实解析

- `Business Rules -> DIRECT` 后，才执行最终真实解析。
- 区分 **DNS 可信性** 与 **IP 相对当前直连出口的可用性/CDN 适配**。
- DNS 经代理获取可信结果、业务再 DIRECT 是合法但相对少见的救援场景；不作为默认模式。
- 可信 DoH 经代理访问可能产生海外 CDN 地址；ECS 仅作为用户授权的可选提示，不提供必然的区域匹配保证。
- 不能仅因解析返回 IP 不通，就擅自把业务改为 PROXY；需按业务策略报告失败或允许的重试。

---

## 8. SRV / 游戏服务发现与 GeoDNS 诊断

### 8.1 正确的 SRV 链路

```text
_minecraft._tcp.play.example SRV
       -> SRV target=node1.game.example, port=25565, priority, weight
       -> 客户端可能查询 node1.game.example A/AAAA
       -> Fake-IP 保留 node1.game.example 身份
       -> 游戏连接依据 Business Rules 选择出口
```

- SRV 的 `Target`、`Port`、`Priority`、`Weight` 均是真正的服务发现信息；不可随意改写。
- 初始 `_minecraft._tcp.play.example` 和后续 `node1.game.example` 是**不同 QNAME**；后者 A/AAAA 独立匹配自己的规则。
- 通过代理解析 SRV **不等于**游戏连接必须经过相同代理。
- SRV 响应附加区若含 A/AAAA，需要 ResponseGuard 在严格 Fake-IP 模式中按已有兼容策略进行保护，防止客户端直接利用真实地址绕过映射；不应随意改动 DNSSEC 签名内容。
- 如果 SRV 目标使用的是应用内部连接逻辑且客户端不再主动查询 DNS，可能无法依靠 Fake-IP 捕获原始目标；需要说明边界。

### 8.2 “SRV 被污染”不等于“GeoDNS”

**诊断矩阵**（全部仅在用户主动执行诊断时测试）：

| 对照组 | DNS 解析器 | 上游路径 | 用途 |
|---|---|---|---|
| A | 当前本地 DNS | DIRECT UDP/TCP | 还原用户实际故障 |
| B | 同一可信 DNS | DIRECT DoH/DoT（若可达） | 判断本地明文 DNS 是否异常 |
| C | 同一可信 DNS | 代理出口 1 | 比较地域/路径影响 |
| D | 同一可信 DNS | 代理出口 2 | 观察跨地区差异 |
| E（条件允许） | 授权查询的权威 DNS | 可控网络路径 | 补强可信度与权威策略判断 |

每次记录：完整 Query、QTYPE/QCLASS、ResponseCode、SRV **无序记录集合**、TTL、CNAME 链、additional section、DNSSEC 状态、递归器/远端端点、ECS、出口网络/代理、耗时、时间戳、异常与重试次数。

**判定原则**：

- 本地明文 DNS 返回 NXDOMAIN/异常记录，而多个可信加密渠道长期稳定返回另一组可验证答案：**疑似 DNS 污染/本地 DNS 故障**。没有进一步证据时不能断言一定遭到污染。
- 同一可信服务经不同出口反复返回有效但不同地域的服务目标：**疑似 GeoDNS/负载均衡策略**，并非自动认定污染。
- SRV 一致但目标 A/AAAA 异常：重点排查后续目标地址解析。
- 所有可信路径都指向同一高延迟节点：DNS 更换不能凭空产生其他服务器；转向游戏路径或运营商部署问题。
- 仅返回顺序变化不应被视为目标变化；TTL、权重和优先级要作为证据保存。

对于 GeoDNS 归因，需控制变量：同一个 Anycast 解析器名在不同地区也可能到达不同实例，记录实际远端、网络位置和重复时间窗口；DNS 权威也可能本身按地域响应。可选 ECS 对照实验需用户授权，且必须允许不携带 ECS 作为基线。

### 8.3 游戏网络延迟探测

- 对实际 SRV 指向的 `target:port` 探测，不以 DNS 查询耗时当作游戏延迟。
- TCP 游戏：可观察连接 RTT；支持安全状态查询的协议可测应用响应时间。
- UDP 游戏：只有在协议支持无副作用的握手/查询时主动探测；UDP 无响应不等于高延迟。
- 多次采样，保存延迟分布和失败率，避免仅看单个 RTT。
- 遵守服务器服务语义，SRV Priority/Weight 不默认改写；严禁后台高频探测。

### 8.4 示例诊断报告

```yaml
# 仅供说明的诊断输出，不是现有 API
query: _minecraft._tcp.play.example
qtype: SRV
findings:
  local_plain_dns: "NXDOMAIN"
  trusted_direct: "node.hk.example:25565"
  trusted_via_proxy: "node.jp.example:25565"
  pollution: "suspected; not confirmed"
  geodns: "possible"
  target_a_aaaa: "needs separate validation"
  game_latency: "not measured"
recommendations:
  - "尝试直连可达的可信加密 DNS"
  - "记录权威应答及不同出口的重复采样"
  - "SRV 与 target A/AAAA 使用各自 DNS 规则"
policy_mutated: false
```

---

## 9. ResponseGuard：复杂类型与 Fake-IP 的兼容

第一版必须显式处理下列情况，且不暗改旧配置：

| 记录类型/路径 | 原则 | 严格新模式策略（opt-in） |
|---|---|---|
| A / AAAA | Fake-IP 映射与真实解析分离 | 支持 IPv4+IPv6 一致虚拟应答；不可失配 |
| HTTPS / SVCB | 可能带 `ipv4hint`/`ipv6hint`、ECH、ALPN | 若尚不能安全解析/转换，可保守 NODATA；记录 HTTP/3/ECH 优化损失 |
| SRV | 提供目标/端口/权重，可能含附加 A/AAAA | 保留 SRV 语义，审查/抑制不安全附加地址 |
| MX/NS | 可能附加真实地址 | 关注附加区地址泄漏，后续 A/AAAA 查询重新匹配 |
| PTR | Fake-IP 所属地址应在本地反查 | 其他 PTR 按适当 DNS 规则执行 |
| DNSSEC | 不能把合成或改写的响应伪称为验证通过 | 不伪造 AD 位、不擅改已签名 RRset；明确拒绝/兼容策略 |
| `.local`、私有后缀 | 通常需 mDNS / 局域网/企业 DNS | 不向公共解析器发送私有名称 |

兼容层面，已有服务器逻辑如果已对 Fake-IP 模式的非 A/AAAA 请求返回空响应，不应以“新规范更正确”为由立即全面放行 HTTPS/SVCB。先记录老行为，建立可选增强模式，再按明确的兼容测试推进。

---

## 10. DNS 上游连接与引导解析

### 10.1 解析器与出口是两种资源

例如 `resolver=trusted` 可指向 DoH endpoint，而 `egress=proxy:DNS-OUT` 决定如何连接 DoH。它**不改变**业务出口。不要把 `resolver=trusted` 默认为“必须代理”，也不要把 `egress=proxy` 当作“选择海外 DNS”。

### 10.2 DNS 拨号计划的约束

- 显式路径优先于性能调度；代理组缺失或不可用则按配置失败。
- `egress=direct` 可受到指定出接口/网络代际约束。
- 同一解析器的连接复用必须按 egress/接口/网络版本分桶；不可让原本经代理的连接池被直连查询复用。
- DNS over UDP/TCP/DoT/DoH 的拨号方式需要统一受控，不能某协议绕过出口选择。
- 若沿用 Mihomo `#proxy/#interface/#RULES`，先保留旧语义；新规则与旧服务器级强制路径冲突必须有显式确定性校验。

### 10.3 引导依赖图

典型递归：

```text
DoH endpoint 域名 -> 需要 DNS -> DNS 需经代理
代理节点域名 -> 需要 DNS -> 代理尚未建立
```

解决思路：

1. 配置显式 bootstrap 解析器与允许的网络出口；IP literal 最简单但不是唯一方式。
2. 加载配置时建立静态依赖关系；识别强制循环并拒绝错误配置。
3. bootstrap 的解析结果与普通 DNS 缓存隔离；为 DoH/DoT 保留正确 SNI/证书验证名称。
4. 旧配置继续使用旧引导语义；严格新模式不得默默借用不可信系统 DNS。
5. 代理重连、网络切换后按网络代际重建需要的连接/缓存，避免死循环和错误共享。

---

## 11. DNS 缓存、健康和网络状态

### 11.1 缓存正确性优先于命中率

至少按响应会改变的维度隔离：

- 规范化 QNAME、QTYPE、QCLASS、DO/CD 等请求选项。
- resolver profile / 信任组、DNS 出口或其网络位置、必要的 ECS。
- 解析用途/来源租户或命名空间（**当它们确实影响响应**时）。
- 配置代际与影响规则结果的策略版本。
- 客户端 Fake-IP 合成缓存与真实记录缓存**不能混在一起**。

同一域名由本地 DNS 和通过代理的可信 DNS 返回不同 CDN IP 是合法现象；缓存绝不能将它们无条件混用。

### 11.2 健康表示事实，策略决定动作

- NXDOMAIN 是合法响应，不等于 DNS 服务器宕机；不要因此把服务器判死。
- SERVFAIL 可能是域/区级故障，不一定说明整台 DNS 不可用。
- 记录成功率、超时、端到端 RTT、网络代际、出口及错误分类。
- 只允许在同等信任/同等策略允许的解析器集合内进行健康切换。
- Hedged queries 与多 DNS 并发属于后续优化，需限制并发、成本和泄漏风险。

### 11.3 失效与网络切换

- 网卡变化、网络代际/策略代际变化时，按作用域使连接池和缓存失效；不是无差别清空所有有效结果。
- 过期结果能否 stale serve 是**策略**，不是缓存自行决定。
- 关键日志记录：QNAME（可按隐私策略脱敏）、QTYPE、用途、命中规则、解析器、DNS 出口、网络路径、耗时、结果、失败/回退理由、策略版本。

---

## 12. 场景决策表（便于开发验收）

| 场景 | 客户端回答 | DNS 上游行为 | Business Rules | 最终连接 |
|---|---|---|---|---|
| 普通网站 DIRECT | Fake-IP | 最终 DIRECT 时本地真实解析 | DIRECT | 直连真实 IP |
| 污染域名但 IP 可直连 | Fake-IP | 内部按特定 QTYPE 经代理查询可信 DNS | DIRECT | 真实 IP 仍 DIRECT |
| 网站 PROXY，域名规则先命中 | Fake-IP | **无目标域名本地真实解析** | PROXY | 将域名交给支持远端解析的代理 |
| 前置 GEOIP 需解析 | Fake-IP | 查询用于 RouteClassification | 用户有序首命中 | 命中结果决定 DIRECT/PROXY |
| 游戏 SRV | SRV 真实记录 | 按 SRV 规则获取，后续 A/AAAA 独立匹配 | 游戏连接规则 | 不自动改写端口、权重与服务目标 |
| SRV 地域差异排查 | 不修改现有业务回答 | 按诊断矩阵多路径只读探测 | 原样 | 原样，给诊断结论 |
| DNS PROXY 不可用、显式 fail | Fake-IP 若本地可答；最终真实解析失败 | 不得越权 DIRECT fallback | DIRECT 依旧 DIRECT | 报错，不强制改成 PROXY |
| 网关某设备固定 IP 连接 | 无法保证域名映射 | 只处理真实观察到的 DNS | 保留 IP/设备规则 | 不凭空推断域名 |

---

## 13. 当前 Chimera 源码落点（锁定公开版本观察）

以下是已查看的文件与建议修改位置。**不是完整代码审计；实施前应锁定具体 commit 并复核分支差异。**

| 文件 | 观察到的现状 | 推荐落点 |
|---|---|---|
| `clash-lib/src/config/def.rs` | `DNS.nameserver_policy: HashMap<String,String>`；已有 legacy DNS 字段 | 新增可选 `resolver_profiles`、`policy_rules`，保留旧字段原形 |
| `clash-lib/src/app/dns/config.rs` | `NameServer` 已有 `proxy`、`interface` 等；policy 解析为单个服务器 | 扩展新字段解析、规则编译、冲突与依赖校验；旧 parser 不改语义 |
| `clash-lib/src/app/dns/resolver/enhanced.rs` | `match_policy` 主要按域名 trie；有 `ip_exchange`、`lookup_ip`、Fake-IP、缓存 | 在真实查询入口引入 `DnsQueryContext` / `DnsPolicyDecision`；保持 `legacy_exchange` |
| `clash-lib/src/app/dns/server/handler.rs` | A/AAAA 合成响应、Fake-IP 时处理某些非 A 查询 | 客户端应答策略、ResponseGuard、严格模式选项 |
| `clash-lib/src/app/dns/fakeip/` | 有 Fake-IP 反向映射与存储 | 生命周期、作用域、IPv6 Fake-IP 的完整闭环 |
| `clash-lib/src/app/dns/runtime.rs` | `DnsRuntimeProvider` 可选择已有 outbound；`respect-rules` 用路由匹配；支持 network path 信息 | 显式 `DnsEgressPlan` 与 legacy route dispatch 双路径，禁止新模式递归匹配业务规则 |
| `clash-lib/src/app/dns/rule_dispatch.rs` | 持有晚绑定 Router/OutboundManager | 保持 legacy 功能；新显式 DNS 出口不必再触发普通路由 |
| `clash-lib/src/app/dispatcher/dispatcher_impl.rs` | 最终业务出口和直连路径已分离 | 传递可信域名身份、区分分类解析与最终 DIRECT 解析 |
| `clash-lib/src/app/flow.rs` | 有业务网络路径相关结构 | 可增加 DNS purpose/trace 关联 id（避免无限扩张 FlowContext） |

### 13.1 已发现、需专门复核的行为差距

1. 源码中 `EnhancedResolver::match_policy` 看起来按域名匹配，暂没有完整 QTYPE 规则策略。
2. `DnsRuntimeProvider::pick_outbound` 已具备 `respect-rules` 的独立出站；新显式 DNS 出口可复用拨号/handler，但不应重用“普通业务规则重新分类”的语义。
3. `direct_resolver` 的构造路径可带到主 resolver 的备用行为；新显式 `on-failure: fail` 必须封堵跨策略回退，而**旧配置保留原行为**。
4. 源码中可见 Fake-IP IPv6 配置结构，但 `EnhancedResolver::resolve_v6` 当前主要走真实 AAAA，尚未证实与 IPv4 对等的 Fake-IPv6 生成闭环，**不能因存在配置字段就宣称已经支持**。
5. 旧 `nameserver-policy` 的 value 类型与 Mihomo 文档支持的数组并不完全一致；属于对 Mihomo 的**兼容差距**，应评估补齐但不破坏现有 string 格式。

### 13.2 推荐 Rust API（内部）

```rust
// 拟议 API：新功能可选；旧配置走 legacy 路径
trait DnsPolicyEngine {
    fn plan(&self, query: &DnsQueryContext, legacy: &LegacyDnsPlan)
        -> Result<DnsPolicyDecision, PolicyError>;
}

trait DnsResolverRuntime {
    async fn exchange_with_plan(
        &self,
        question: &DnsQuestion,
        plan: &EffectiveDnsPlan,
    ) -> Result<DnsResponse, DnsError>;
}

trait DnsDiagnostics {
    async fn diagnose_srv(
        &self,
        query: &SrvDiagnosticRequest,
    ) -> Result<SrvDiagnosticReport, DiagnosticError>;
}
```

性能原则：旧规则不应被新规则引擎的复杂匹配路径拖慢；先按域名 trie + qtype 过滤实现，后续索引优化不得改变首条命中语义。

---

## 14. 技术阶段计划（每阶段均可独立验证）

### Phase 0：基线和兼容测试（必须最先完成）

- [ ] 锁定当前稳定 commit/fixture，与 Mihomo 文档分别建兼容矩阵。
- [ ] 补充现有 DNS、Fake-IP、出站路由、缓存与失败语义的金标准测试。
- [ ] 明确 Host/Gateway、IPv4/IPv6、DNS 协议支持范围。
- [ ] 建立新配置 opt-in 和被保留配置 legacy 的 A/B 测试框架。

**准出条件**：能判断一次 DNS 改造有没有破坏旧配置，而不仅是能编译。

### Phase 1：精细规则与 DNS 拨号

- [ ] 可选 `resolver-profiles`、`policy-rules` 解析/验证。
- [ ] QNAME+QTYPE 首条命中，按字段叠加到 legacy decision。
- [ ] 真实查询在 DIRECT / `proxy:group` / legacy 路径上正确拨号。
- [ ] `on-failure: fail` 禁止未授权回退。
- [ ] Bootstrap 依赖校验、基本决策日志与新旧行为对比。

**准出条件**：已承诺保留的旧配置全通过；新策略的 DNS egress 与业务 egress 可独立验证。

### Phase 2：Fake-IP / 流量闭环

- [ ] 客户端 fake vs real 回答不变；内部真实解析用途完整区分。
- [ ] Business Rules 的规则先后、`no-resolve` 及代理远端解析行为回归。
- [ ] DIRECT 最终真实解析与用户指定上游规则衔接。
- [ ] IPv6 Fake-IP/AAAA 的正确性和失败边界。
- [ ] 目标解析和业务路由的 trace 关联。

**准出条件**：TUN、TCP/UDP、Host/Gateway 关键用例不丢失域名身份、不越权切出口。

### Phase 3：SRV、复杂 DNS 响应与诊断

- [ ] SRV、HTTPS/SVCB、MX/NS additional section 的安全处理与兼容模式。
- [ ] SRV 多路径查询、权威/可信/本地对照、GeoDNS 证据评分。
- [ ] SRV Target 的 A/AAAA 单独校验、游戏协议许可的低频探测。
- [ ] 报告必须有“不确定”和“证据不足”状态。

**准出条件**：不随意改写 SRV，诊断不会自动修改规则。

### Phase 4：网络状态与性能调度

- [ ] 分出口/网络代际 DNS 健康和缓存隔离。
- [ ] 同信任级别的解析器健康调度、可控 hedging。
- [ ] 多网卡/IPv4-IPv6 的出口绑定；可选 ECS 严格授权。
- [ ] 性能指标与失败解释面板。

**准出条件**：提升性能，但不改变既有用户策略结果与信任边界。

---

## 15. 必测验收用例

| 编号 | 输入 | 预期 |
|---|---|---|
| C-01 | 旧 DNS 配置，不含新字段 | 对保留子集，与旧版解析/应答/出站/回退等价 |
| C-02 | Mihomo `nameserver-policy` 旧 string 值 | 继续可读，含义不变 |
| C-03 | `policy-rules` 不匹配 | 完全走旧流程 |
| C-04 | 同域名 A=proxy、AAAA=direct | 各匹配正确且连接池和缓存隔离 |
| C-05 | Fake-IP A 请求 | 不产生不必要的真实上游查询 |
| C-06 | Domain 业务规则先命中 PROXY | 不做最终业务目标的本地真实解析 |
| C-07 | GEOIP 前置、未设 `no-resolve` | 按旧语义先执行所需分类 DNS |
| C-08 | GEOIP 前置、设 `no-resolve` | 不为该规则强行发起 DNS |
| C-09 | DIRECT + 指定可信代理 DNS | 经代理查询 DNS，但业务始终 DIRECT |
| C-10 | 新规则指定 PROXY DNS、`on-failure: fail` | 无直连泄漏、无主 resolver 偷偷回退 |
| C-11 | 不同策略的相同 A 查询 | 无缓存串用 |
| C-12 | 网络切换中复用 DNS 连接 | 不复用过时的出口连接 |
| C-13 | SRV 指向另外域名 | SRV 与目标 A/AAAA 分别匹配各自规则 |
| C-14 | SRV Priority/Weight 不同 | 默认不改写选择语义 |
| C-15 | HTTPS/SVCB 含 IP hints | 严格 opt-in 模式不产生域名身份绕过 |
| C-16 | Fake-IP IPv6 与严格 AAAA | 不会将真实 AAAA 错当作 Fake-IPv6 |
| C-17 | 代理节点域名解析依赖自身代理 | 阻止循环或使用明确 bootstrap，不暗漏 |
| C-18 | 多设备同一 CDN IP、不同域名 | 不用全局 `IP->domain` 猜测误归因 |
| C-19 | SRV 本地 NXDOMAIN、可信返回值不同 | 仅给“疑似污染”，不伪称证明 |
| C-20 | SRV 正常但 A/AAAA 不同 | 报告指出异常更可能在目标解析 |
| C-21 | 新规则与选择保留的老 `#proxy/#RULES` 路径冲突 | 加载期有确定的拒绝或明确选择机制 |
| C-22 | 用户旧配置含合法但低性能规则顺序 | 提示但不重排、不更换业务路由 |

测试方式：单元（匹配/计划）、集成（模拟解析器/代理）、端到端（TUN/网关）、回归（金标准 fixture）、故障注入（timeout、SERVFAIL、NXDOMAIN、网络切换）、安全（缓存跨租户/泄漏/引导循环）。

---

## 16. 需要评审的开放问题与默认决议

| 问题 | 默认决议 | 需要更多依据时 |
|---|---|---|
| 新配置挂在哪里？ | `dns.policy-rules` + `dns.resolver-profiles` 可选扩展 | 以代码解析器的兼容程度复核最终命名 |
| 新规则与旧 DNS Server `#` 参数冲突？ | 配置编译报错，不自动猜优先级 | 可加入显式 override 但不能隐式生效 |
| `purpose` 暴露给用户吗？ | V1 先不暴露，内部明确区分 | 有真实跨用途需求后再加可选字段 |
| SRV GeoDNS 是否自动选择最低延迟？ | **不自动**；只做诊断与用户可读建议 | 得到真实数据和协议验证后考虑 opt-in |
| DNS 经代理但业务 DIRECT 是否默认开启？ | **否**；是特定信任/污染场景的显式规则 | 用户可以自行指定域名/QTYPE |
| 是否自动向 DNS 附加 ECS？ | **否**；独立授权开关 | 明确隐私和实际效果后小范围实验 |
| 老配置中的不安全自动回退？ | 先保留旧行为并告警；新严格模式 fail-closed | 真实漏洞需按兼容性例外流程评审 |
| 规则发生潜在冲突怎么处理？ | 明确旧规则优先关系、只覆盖新动作明示字段；无法判定时拒绝配置 | 不得静默替用户决定 |

---


## 17. AI 任务地图：依赖、最小改动、Done 条件

> 以下用 **Slice** 表示可以单独验证的修改批次。按仓库 `AGENTS.md` 默认在本地 `master` 形成**签名的独立提交**；只有高风险/多人协作等确有需要时才提议分支或 PR。每批次若测试不通过或风险超范围，不允许擅自继续下一批次。

| ID | 依赖 | 范围（只在必要时扩展） | 该批必须输出 | Done 门槛 |
|---|---|---|---|---|
| **S00 基线** | 无 | `docs/`、DNS 既有 tests | 取舍矩阵、基线 fixture、观测对照 | 能用回归测试检测旧逻辑变化 |
| **S01 纯规则** | S00 | `config/def.rs`、`dns/config.rs`、新 `dns/policy.rs`（名称可调整） | 规则序列化、编译校验、QNAME/QTYPE first-match | 全离线测试，无任何网络 side-effect |
| **S02 计划器** | S01 | `resolver/enhanced.rs` 等 | `DnsQueryContext` 与叠加现有行为的 EffectivePlan | 新字段未启用与旧路径差异为零 |
| **S03 显式 egress** | S02 | `dns/runtime.rs`、`dns_client.rs`、`helper.rs`、`rule_dispatch.rs` | DNS DIRECT/PROXY 独立拨号与失败策略 | 代理失效不偷跑直连；DNS wire protocol 覆盖 |
| **S04 缓存/Bootstrap** | S03 | DNS 缓存、client pool、配置验证 | 跨出口缓存隔离、引导依赖检测 | 不泄漏/不循环/无连接池跨出口复用 |
| **S05 Fake-IP/Flow** | S04 | `server/handler.rs`、`fakeip/`、Dispatcher/Router 最小调用点 | 客户端应答与内部解析用途分离 | PROXY 域名不多解析，前置 GEOIP 仍照常解析 |
| **S06 SRV/Response Guard** | S05 | DNS server/response helper | opt-in SRV 安全应答，复杂记录与 DNSSEC 错误边界 | 不丢 SRV Target，不放行可造成 Fake-IP 绕过的地址 |
| **S07 只读诊断** | S06 | 新 `dns/diagnostic/`，可选 API | 多路径 DNS/SRV 证据报告 | 不修改用户配置/代理选择，不假定所有 DNS 不同=污染 |
| **S08 文档/发布门槛** | S07 | `docs/`、全相关 tests、可选 Dashboard | 配置迁移指南、示例、测试结果、风险清单 | 维护者决定是否进入 release 候选 |

### 17.1 S00：必须首先固定的 golden tests

**配置基线输入**：空 `dns`、普通 `nameserver`、域名 policy、fallback、fake-ip-filter、`direct-nameserver`、`proxy-server-nameserver`、`respect-rules`、IPv6 on/off、网络路径选项及合法但潜在低效的 GEOIP 前置规则。只为**拟保留**配置承诺 A/B 等价；已选淘汰但尚未批准的字段仍按当前行为保留。

**观测输出**：解析是否成功、客户端 A/AAAA/SRV 实际回答、目的域名是否保留、上游 DNS server ID/网络路径、业务匹配规则 ID、失败是否触发 fallback、DNS 响应 rcode/TTL（允许明确的时间差或 ID 归一化）。**避免用“整段日志文本字节一致”作为金标准**。

实现：使用本地 Mock DNS、Mock outbound、稳定时间与固定 IP 地址；请求计数器断言“本次是否真的访问上游”；同一个 fixture 跑 legacy 前后，写入精确差异说明。

### 17.2 S01：配置与编译器（仅类型/校验，不接触流量）

新增建议的原始类型（**示意 API**，最终依据 Serde 和现有配置风格实现）：

```rust
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyRuleDef {
    pub r#match: DnsPolicyMatchDef,
    pub action: DnsPolicyActionDef,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyMatchDef {
    pub domain: Option<String>,
    pub domain_suffix: Option<String>,
    pub qtype: Option<Vec<String>>, // 编译时转为 Hickory RecordType / TYPE####
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsPolicyActionDef {
    pub resolver: Option<String>,
    pub egress: Option<String>, // "direct" | "proxy:组名"；编译后转强类型
    pub on_failure: Option<String>,
}
```

**编译期必须拒绝**：同时配置冲突的 domain/domain-suffix（除非规范定义了逻辑）、空域名、非法 DNS 类型、空/未知 resolver、未知代理组、DNS 出口循环、显式代理路径与旧服务器级强制路径冲突但又无明确优先规则、没有作用的空 action、明显未实现的严格模式。

规则匹配必须**用户配置次序优先**。可使用索引先找到匹配规则，再取最小原始 ordinal；不得把“exact 比 suffix 优先”硬编码成覆盖用户先后顺序的策略。

首版可用简单顺序扫描完成正确性，后续性能索引由单元测试确保匹配规则 ID 不变。

### 17.3 S02：不产生网络副作用的 DNS 计划器

建议以**两级入口**保护兼容：

```rust
async fn resolve_dns(input: DnsInput, runtime: &DnsRuntime) -> Result<DnsResponse, DnsError> {
    if runtime.compiled_policy_rules.is_empty() {
        // 沿用当前稳定代码路径，不能先以全新引擎替换它。
        return runtime.legacy_exchange(input).await;
    }
    let ctx = DnsQueryContext::from_input(&input)?;
    let plan = runtime.build_effective_plan(&ctx)?; // 仅计划，不拨号
    runtime.exchange_with_plan(&ctx, &plan).await
}
```

`legacy_exchange` 是设计中的接口名称，实际可保留原 `exchange_no_cache`/`ip_exchange` 调用，不要求先改成这个函数名。新规则只覆写**显式填写的动作字段**，缺失字段继承当前解析器/出口/失败语义。注意 Legacy 的 fallback 可能有按应答结果动态选择路径的行为，不能假设可无损压成“单个固定 resolver”；计划可以包含**受约束的执行策略**而非仅一个 DNS IP。

规划应传 `DnsPurpose`：`ClientRealAnswer`、`RouteClassification`、`DirectDestination`、`ProxyDestinationLocal`、`ProxyNodeBootstrap`、`ResolverBootstrap`、`Diagnostic`。第一版 `purpose` 可以只存在 Rust 内部，不一定作为用户 YAML 匹配条件。

**验收**：设置 `policy-rules` 但未命中时，对照现有 legacy `nameserver-policy/fallback`；恰好命中 A、AAAA、SRV 的规则保持配置顺序；同域名不同用途根据显式语义获得正确 plan。

### 17.4 S03：DNS 上游出口执行器

需要把 `DNS wire protocol` 与 `DNS egress` 清晰分离：

```text
DNS wire: UDP / TCP / DoT / DoH（现有能力为准）
DNS egress: legacy / direct(iface?) / proxy(group)
```

拨号 plan 至少带：resolver endpoint（含真实证书校验名）、出站选择、用途、出接口（若配置）、网络代际、配置代际、超时、总请求 deadline、fallback 约束。使用现有 `DnsRuntimeProvider` 和 proxy handler，**显式出站时不调用普通 Router 的 Business Rules**；旧 `respect-rules` 走旧入口并保留现有语义。

1. 测试 same resolver IP 经 DIRECT 与 PROXY 会走不同 Fake outbound，且 PROXY 路径失败无 DIRECT dial 尝试。
2. 测试 UDP/TCP/DoT/DoH 在各自已支持的 transport 上遵守出站路径，TLS hostname/SNI/证书验证不因 IP bootstrap 丢失。
3. 测试代理组缺失、节点下线、超时和重载时明确失败；不要吞掉 selected outbound error。
4. `on-failure: fail` 是不可放宽的上限；只允许显式配置的等价信任组内重试，不用 legacy fallback 偷换 DNS 路径。

### 17.5 S04：缓存、连接池与引导依赖

**缓存键不可以只有 `(QNAME, QTYPE)`**。推荐按影响应答的最小维度组成：

```text
namespace / QNAME / QCLASS / QTYPE /
DO, CD 及相关 EDNS 特性 / resolver-profile /
DNS 出口作用域（或实际递归器地理实例身份）/
ECS / policy-generation / 必要的 source-scope
```

不同出口只是网络路径相同时未必改变答案，但在 GeoDNS/Anycast 下可能改变；为防错，**新规则首版宁可更保守地分桶**，以后基于同源性证据优化复用。Fake-IP 映射与真实结果是不同存储/类型。TTL/negative cache/serve-stale 需要显式策略；旧 legacy 缓存保持现状，不能因新策略加载就更改其有效性规则。

**连接池 key** 至少包含 resolver endpoint、wire protocol、出站 handler/代理组实际叶节点、出接口、网络代际及影响 TLS/ECS 的上下文。网络变更时清理旧 pool；不能把之前经代理建立的 DoH 连接复用为“直连”。

**Bootstrap**：构造配置依赖图，例如 `proxy.example -> bootstrap resolver`、`doh.example -> proxy:DNS-OUT`，拒绝 `proxy.example -> doh.example -> proxy.example` 的强制环；对于无法静态判定的动态选择器，执行时也需有 recursion guard / depth budget。旧配置可保留原 bootstrap，新的严格路径必须明确允许的 bootstrap 解析来源。

### 17.6 S05：Fake-IP、规则顺序与实际业务闭环

**用例一：域名规则先命中代理**

```yaml
rules:
  - DOMAIN-SUFFIX,video.example,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT
```

预期：客户端 A 获取 Fake-IP，映射可恢复域名；业务第一条命中 PROXY。代理支持域名目标时，对 `video.example` 的**业务目标真实解析次数为 0**（代理节点自身 bootstrap 查询不计入）。

**用例二：IP 规则前置**

```yaml
rules:
  - GEOIP,CN,DIRECT
  - DOMAIN-SUFFIX,video.example,PROXY
  - MATCH,DIRECT
```

预期：GEOIP 如需解析且未设 `no-resolve`，先执行 `RouteClassification` 真实解析；若命中 DIRECT，则不继续 DOMAIN。若未命中，后续 DOMAIN 可命中 PROXY，最终代理连接仍应优先传域名。不得自动重排配置。若 GEOIP 设 `no-resolve`，就按原语义不触发解析。

**用例三：DNS 经代理、业务直连**

客户端 Fake-IP → Business Rules DIRECT → 目的解析 `DirectDestination` 按显式 policy 经 `proxy:DNS-OUT` 请求可信 DNS → 得到真实 IP → 业务 DIRECT。若 DNS-OUT 不可用则失败，**绝不可悄悄将业务改成 PROXY 或将 DNS 改成 DIRECT**。

同时检查：Fake-IP 反查有效期、共享 CDN IP 不导致跨域身份错绑、网关不同来源作用域、IPv4/IPv6 一致性。当前仓库 Fake-IPv6 不能只凭已有配置字段宣称完成；先补离线 TUN 回归，再决定是否开启。

### 17.7 S06：SRV 与响应安全（处理一个已知实际矛盾）

**必须特别注意当前 `server/handler.rs` 的事实**：基线的 `should_skip_fake_ip_upstream` 对需要 Fake-IP 的域名会保守拦截非 A/AAAA（包括 SRV）并返回空应答。这与用户希望游戏 SRV 正常服务发现存在实际冲突。

**不能粗暴删除这段判断**，因为 HTTPS/SVCB 里的 IP hints 和 additional A/AAAA 可能绕过 Fake-IP。推荐：

- 首版引入**显式选择**的 `dns.service-discovery-mode: safe`（字段名待最终审查）。未启用则沿用原行为；没有用户授权不能以“修复”为名直接改变已支持配置的应答行为。
- safe 模式：SRV 的 Target、Port、Priority、Weight 按原始正确 RRset 保留；若 additional section 存在会泄漏真实目标的 A/AAAA，经过完整验证后选择安全抑制策略，或在无法安全处理时明确 NODATA/失败；**绝不**擅自把 SRV Target 改成某个更快节点。
- HTTPS/SVCB 中可能含 `ipv4hint/ipv6hint/ECH`；在严格 Fake-IP + 尚不能安全处理时可 opt-in NODATA，并清楚告知对 HTTP/3/ECH 的兼容影响。
- 对 DNSSEC DO/AD/RRSIG 不得冒充验证结果；需要处理已签名数据时选择“原样传递且不承诺身份闭环”或“严格失败”，避免生成看似完整但无法验证的伪造答案。
- MX/NS 的 additional、PTR（当前已有 Fake-IP IPv4 PTR 路径）、`.local` 本地命名空间也需要用例；不同后续 QNAME/QTYPE 每次重新匹配。

**服务发现网络诊断与 response 修改完全分离**：诊断器只读、不会让 `DNS-OUT` 成为游戏业务出口。

### 17.8 S07：只读 SRV / GeoDNS 诊断器

建议数据结构：

```rust
struct SrvDiagnosticRequest {
    service_qname: String,
    routes: Vec<DnsProbeRoute>,
    repetitions: u8,           // 设置上限；默认 3 次，不能无限探测
    probe_game_endpoint: bool,  // 主动探测需用户触发
}

struct SrvSample {
    queried_at: Timestamp,
    endpoint: String,
    dns_egress: String,
    rcode: String,
    rrset: Vec<SrvRecord>,    // 比较集合，不能按返回顺序判断不同
    ttl: Vec<u32>,
    cnames: Vec<String>,
    additionals: Vec<ResourceRecordSummary>,
    dnssec_status: ValidationStatus,
    elapsed_ms: u64,
}

enum Finding {
    PossiblePollution,
    PossibleGeoDns,
    TargetAddressInconsistency,
    LikelyGamePathIssue,
    Inconclusive,
}
```

**诊断矩阵**（用户主动启动，均为真实 DNS 响应，不使用客户端 Fake-IP 答案替代）：

| 组 | DNS 服务 | 路径 | 控制变量与作用 |
|---|---|---|---|
| A | 当地普通解析器 | DIRECT UDP/TCP | 还原疑似污染或本地转发器故障 |
| B | 同一可信 DoH/DoT | DIRECT（若可达） | 比较直连可信解析 |
| C | 同一可信 DoH/DoT | 代理出口地区 1 | 同服务不同出口 |
| D | 同一可信 DoH/DoT | 代理出口地区 2 | 观察地域/递归器实例影响 |
| E | 授权可达的权威解析器 | 指定网络出口 | 在可能情况下补强真实性证据 |

每组以多次采样、服务端 endpoint、时间窗口、QNAME/QTYPE/QCLASS、完整 SRV RRset（排序归一化，保留 Priority/Weight/Port）、TTL、CNAME、附加地址、rcode、DoH/DoT TLS 证书验证状态、DNSSEC 状态、ECS、网络代际、错误分类为证据。

**结论规则**：

- A 异常而 B/C/D 长期一致且可信：`PossiblePollution` 或“本地 DNS 故障”，**不是确定审查/污染**；只有明确 DNSSEC 验证或更强证据才提高置信度。
- B/C/D 同服务随出口改变返回有效但地区不同的 SRV：`PossibleGeoDns`（亦可能是负载均衡/Anycast 实例差异），不是自动认定污染。
- SRV 一致但 Target 的 A/AAAA 分歧明显：`TargetAddressInconsistency`。
- 所有可信路径同一 Target 且实际游戏延迟高：报告网络路径或服务器位置因素，不能臆造邻近节点。
- 仅 RR 顺序或 TTL 变化不认定 GeoDNS。ECS 测试默认关闭，须用户明确授权，且不保证权威使用 ECS。

游戏延迟探测使用**真实 SRV `target:port`** 而不是 DNS RTT；TCP 可观察握手时间，UDP 仅当游戏协议允许无副作用查询时探测。加入超时、最大节点数、最大并发、固定最小间隔与总体预算；用户可随时取消。诊断记录不得含认证信息和未经脱敏的用户敏感 DNS 历史。

**报告结构**应同时展示 `finding`、`evidence`、`counter-evidence`、`unknowns`、`recommended_next_check`、`policy_mutated: false`，绝不能只给“污染率 XX%”这种无证据数字。

### 17.9 S08：文档与版本化迁移说明

- 提供 `docs/dns-compat-matrix.md`：保留/条件继承/拒绝、当前实际支持程度、弃用理由及迁移路径。
- 提供“传统配置不变”和“使用精细策略”的独立样例；标明新配置最低支持版本。
- 如果最终淘汰 `fallback[-filter]`、`respect-rules` 或特殊旧字段，必须先提交独立 Decision，附自动迁移建议，不能靠 AI 自己判断“代码清爽所以删除”。
- 所有新版行为通过离线与集成测试；没有真实游戏数据时不得宣传诊断能证明 GeoDNS、保证降延迟。

---

## 18. 验收用例清单：AI 不得只汇报“cargo check 成功”

| 测试 ID | 输入/操作 | 必须断言 |
|---|---|---|
| T01 | 已承诺旧字段的 config fixtures | 不启用新策略时，与 golden 行为等价 |
| T02 | Mihomo 尚未支持字段写进新严格对象 | 返回具体字段名、原因和替代示例 |
| T03 | 同域名 A 与 AAAA 分别配置 PROXY/DIRECT | 命中 rule ordinal 正确，outbound 路径正确 |
| T04 | 扩展规则按相反顺序重排 | 结果随用户规则顺序变化，无隐藏“exact 优先” |
| T05 | Fake-IP 客户端 A 请求 | 不访问上游真实 DNS，保留域名映射 |
| T06 | PROXY 域名规则先命中 | 不做业务目标的本地真实 IP 解析 |
| T07 | GEOIP 在 DOMAIN 前（无 no-resolve） | 分类 DNS 按原语义触发；若匹配仍首条命中 |
| T08 | GEOIP `no-resolve` | 不因这个规则新增分类解析 |
| T09 | DNS PROXY + 业务 DIRECT | DNS 通过代理请求，最终业务 DIRECT |
| T10 | 代理 DNS 宕机且 on-failure=fail | DNS 报错，不建立直连 DNS 连接；业务出口不变 |
| T11 | 用相同域名/QTYPE 先查询 local 再 trusted | DNS 缓存互不污染，网络数据与结果可区分 |
| T12 | 同 DoH endpoint 的旧 proxy pool 和 direct pool | 不允许跨出口错误连接复用 |
| T13 | 配置 A→B→A 依赖循环 | 加载失败，有完整链描述 |
| T14 | 配置中未知代理组/解析器 | 加载失败，不能静默重写为 DIRECT |
| T15 | SRV 指向另一个域名 | SRV 与后续 A/AAAA 各自按 QNAME/QTYPE 匹配 |
| T16 | SRV 附加真实 A/AAAA | safe 模式不暴露会绕过 Fake-IP 的地址 |
| T17 | HTTPS/SVCB 有 IP hints | 严格模式 NODATA/安全变换按批准政策执行；默认旧行为不变 |
| T18 | Signed/DNSSEC 应答与 synthetic Fake-IP | 不能把合成结果伪称 AD validated |
| T19 | PTR 对已有 Fake-IP | 本地反查；其他 PTR 走正常策略 |
| T20 | 移动网络/多网卡切换 | 旧连接池失效，DNS 不越权使用旧路径 |
| T21 | 网关多个设备共享 CDN IP | 不用全局真实 IP 最近域名错误归因 |
| T22 | 本地 NXDOMAIN、可信 SRV 不同 | 输出“疑似污染/可能本地故障”，不能断言确证 |
| T23 | 相同 SRV RRset 仅顺序/TTL 不同 | 不报告 GeoDNS 差异 |
| T24 | 所有可信 SRV 相同而目标很慢 | 报告游戏路径问题的可能性，不自动改 SRV |
| T25 | 诊断用户取消 | 没有残留大量任务、连接或系统 DNS 改动 |
| T26 | 相同 query 不同 source-scope / ECS | 命中适当缓存隔离，无跨设备或地域污染 |
| T27 | 新配置部分字段未填 | 未填维度继承旧行为，不能被新默认值悄悄改写 |
| T28 | 已明确选定不兼容的旧配置 | 按批准的 Decision 给出准确警告/错误及迁移建议 |

**测试层级**：单元（纯匹配、策略编译、ResponseGuard）、端到端 Mock（假 DNS/假 proxy 连接器、TUN 离线包）、故障注入（超时、NXDOMAIN、SERVFAIL、代理失联、网络切换）、安全用例（引导循环、泄漏、缓存混用、DNSSEC）、可选隔离环境中的真实网络探测。普通 CI **不访问真实公共 DNS 或真实游戏服务器**。

### 18.1 推荐验证命令（必须以当前 AGENTS.md / Cargo.toml 为准）

```bash
cargo fmt --all -- --check
cargo check -p clash-lib
cargo test -p clash-lib --test dns_config_tests
cargo test -p clash-lib --test tun_fake_ip_real_tests
cargo test -p chimera-dns
# 当跨越路由/Dispatcher/公共 trait 时再扩大范围：
cargo check --workspace
cargo test --workspace
cargo clippy -p clash-lib --all-targets --all-features -- -D warnings
# 如果没有安装前端依赖或平台工具，说明环境阻塞，不能声称 CI 通过。
```

不要无条件运行可能触发系统路由修改、提权或大量真实网络请求的 ignored 测试。定向 `cargo test` 输出若发现 0 tests executed，视为**未验证**，应核对 `#[ignore]`、feature、runner 与目标测试名。

### 18.2 性能门槛

- **正确性高于低微秒级性能**。`policy-rules: []` 的旧解析路径不应比基线出现显著退化；按相同硬件与请求集离线比较吞吐和 p50/p95/p99。
- 新规则匹配先允许 O(N) 顺序扫描；确有证据再做索引。索引必须返回原始规则最小 ordinal，不能改变 user first-match。
- 诊断属于慢路径，不能在每个 DNS 请求或每个 TCP/UDP packet fast path 上做多地区 SRV 探测。

---

## 19. 配置样例（不可复制到当前版本运行，直至对应 Slice 落地）

### 19.1 最小保留配置：老语义完全不变

```yaml
# 现有 Chimera 行为的示意，字段以实际基线支持为准
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [192.168.1.1]
  nameserver-policy:
    "+.corp.internal": 192.168.1.1
  fake-ip-filter:
    - "*.lan"
```

### 19.2 按域名/QTYPE 指定 DNS 出口

```yaml
# 以下 resolver-profiles/policy-rules 为新功能拟议语法
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [192.168.1.1]
  resolver-profiles:
    local:
      servers: [192.168.1.1]
    trusted:
      servers: ["https://cloudflare-dns.com/dns-query"]
  policy-rules:
    - match:
        domain-suffix: suspect.example
        qtype: [A, AAAA]
      action:
        resolver: trusted
        egress: "proxy:DNS-OUT"
        on-failure: fail
    - match:
        domain: _minecraft._tcp.play.example
        qtype: SRV
      action:
        resolver: trusted
        egress: direct
        on-failure: fail
```

说明：所有 `.example` 域名均为演示占位。配置中 `egress` 定义 DNS 查询线路，**业务线路仍由顶层 `rules` 决定**；默认 Fake-IP 对客户端 A 查询不进行上游真实解析。上例 `trusted` 的直连可达性取决于真实网络，不意味着已验证可达。

### 19.3 业务规则顺序示例

```yaml
# A：已优先命中代理域名规则，不需要最终连接目标的本地真实解析
rules:
  - DOMAIN-SUFFIX,video.example,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,DIRECT

# B（不同配置示意，不应与 A 同时放在同一个 YAML 顶层 rules）
# rules:
#   - GEOIP,CN,DIRECT
#   - DOMAIN-SUFFIX,video.example,PROXY
#   - MATCH,DIRECT
```

### 19.4 SRV 安全模式与只读诊断（概念）

```yaml
dns:
  service-discovery-mode: safe  # opt-in；默认 legacy
```

`safe` 只保证依据已批准的 ResponseGuard 方案处理服务发现应答；**不**代表自动把游戏业务流量代理化、或保证找到低延迟节点。诊断建议通过显式 CLI/Controller API 命令触发，不隐式常驻监控。

---

## 20. 错误信息与诊断 Trace 契约

建议至少定义这些错误分类（编码名可调整，意义不可含糊）：

| Code | 触发条件 | 对用户解释 |
|---|---|---|
| `DNS_POLICY_NO_RESOLVER` | 指定 resolver profile 不存在 | 配置引用无效，拒绝加载 |
| `DNS_POLICY_NO_OUTBOUND` | 指定 DNS proxy/group 不存在或不可用 | 不改走 DIRECT，明确失败 |
| `DNS_POLICY_CONFLICT` | 显式 egress 与旧 DNS server URL 强制出口冲突 | 不能猜谁优先，提示迁移方式 |
| `DNS_BOOTSTRAP_CYCLE` | DNS 上游/代理节点间存在强制依赖环 | 报完整依赖链与独立 bootstrap 建议 |
| `DNS_POLICY_STRICT_FAILURE` | 严格路径所有允许的上游尝试失败 | 返回失败，不越界 fallback |
| `DNS_RESPONSE_UNSAFE_HINTS` | Fake-IP 严格模式无法安全处理提示地址 | 按批准的严格策略返回 NODATA 或明确失败 |
| `DNS_DOMAIN_IDENTITY_UNKNOWN` | 真实 IP 连接无可证明域名 | 应用 Business IP 规则，不猜测域名 |
| `DNS_DIAGNOSTIC_INCONCLUSIVE` | 污染/GeoDNS 无法形成区分证据 | 告知缺少哪些证据，不自动切换 |

结构化 trace 示例（请求数据可脱敏）：

```json
{
  "trace_id": "sample-001",
  "qname": "suspect.example",
  "qtype": "A",
  "purpose": "direct_destination",
  "client_answer": "fake_ip",
  "dns_rule_index": 2,
  "resolver_profile": "trusted",
  "dns_egress": "proxy:DNS-OUT",
  "business_rule_index": 8,
  "business_egress": "DIRECT",
  "network_generation": 11,
  "cache_status": "miss",
  "dns_rcode": "NOERROR",
  "duration_ms": 43,
  "fallback_used": false,
  "policy_mutated": false
}
```

诊断日志与标准流量日志要区分采样量，敏感域名/设备信息按用户隐私设置脱敏；不记录 DoH token、代理授权、真实订阅文件。

---

## 21. AI 每轮的工作合同与交付模板

AI 每轮只接受一个 Slice 的范围，在本地仓库先完成最小可验证增量；遇到实际源码变更与本文设计冲突时，优先事实、更新文档并给出权衡，而不是硬套伪代码。若风险/兼容边界尚未批准，不应自行删除已有功能。

### 21.1 每轮步骤

1. **Read**：读本地 `AGENTS.md`、治理规范、目标源码与现有测试；记录 `HEAD/master/origin/master`、dirty state、feature 与平台。
2. **Baseline**：选择已有离线测试先跑；失败项记为“基线已失败”，不得嫁祸于本轮修改。
3. **Plan**：确定当前 Slice 目标、修改文件、保留/不兼容字段、风险、负面测试与 Done 条件。
4. **Implement**：只改本 Slice 的代码，不顺带批量格式化或重命名；新功能默认 opt-in、Legacy 不变。
5. **Test**：先小范围再扩大；必须至少覆盖成功路径、失败路径、旧配置 A/B 和出口隔离。
6. **Review**：执行 `git diff --check`，核对变更范围、用户现有改动、潜在 DNS 泄漏和 log 脱敏。
7. **Commit**：按仓库规定，在可安全操作的本地 `master` 进行**签名提交**并核验；禁止无授权 push/merge/tag/release。
8. **Record**：更新相应 `docs/` 进度与取舍矩阵，给下一次 AI 留下已证实结果及下一最小任务。

### 21.2 每轮输出报告模板

```text
Slice / 目标：
仓库状态：HEAD=... / master=... / origin/master=... / dirty=...
兼容性：本轮保留的配置...；提议弃用的配置...（Decision 编号）
实际修改的文件：
调用链变化（老路径/新路径）：
离线单测：命令、实际执行数量、通过/失败/跳过：
集成测试：命令、实际执行数量、通过/失败/跳过：
需要但未运行的检查、原因：
安全验证：DNS 防泄漏/引导依赖/缓存隔离/身份保留：
性能对比：基线与新值（若已测）：
本地签名提交：commit SHA、verify-commit 结果、%G? 状态：
推送/合并状态：默认未推送、未合并：
已知问题、下一最小 Slice：
```

### 21.3 可直接交给 AI 编码代理的首轮任务指令

> 请先阅读仓库根目录 `AGENTS.md` 和 `docs/ai-development-governance.md`，再以本文 **S00** 为本轮唯一任务。核对本地 HEAD/已有改动与文档基线 SHA，检查当前 DNS 配置、Fake-IP、上游拨号、缓存、DNS 健康和已有测试；建立 `docs/dns-compat-matrix.md`，区分 Mihomo 字段的“当前实现程度”与“本项目是否计划保留”。为被保留的 DNS 配置建立可复现的离线 golden tests，验证 Fake-IP、SRV、`nameserver-policy`、`fallback`、`direct-nameserver`、`respect-rules` 的当前实际行为，包含失败场景。**本轮不得改变任何运行时 DNS 决策或删除旧配置字段**。执行相关测试，按仓库签名提交与审批规则处理本地变更，报告真实测试结果和 S01 的输入依赖；未经授权不得推送代码或开 PR。

后续轮次将任务名称改成 S01、S02……，始终先阅读上一轮记录与当前代码，不允许“一次性实现全部特性”。

---

## 22. 决策门槛与待维护者确认项

只保留真正无法从现有事实自动决定的选项，其余按上述默认方案执行。

| 待确认 | 默认方案 | 何时需要维护者决策 |
|---|---|---|
| Mihomo 哪些字段正式放弃 | 本文 §2 为**候选**，先保留当前已实现行为 | 任何真实删除/更改已有配置语义之前 |
| `policy-rules` 与旧 `#proxy/#RULES` 出口冲突 | **拒绝歧义配置** | 希望开放显式 override 时 |
| SRV 安全模式对签名附加记录的策略 | 无法保证正确时严格失败，保留 legacy 默认 | 要启用“改写响应”策略或改变默认 SRV 行为前 |
| Fake-IPv6 首次公开支持 | 必须先通过双栈和网关隔离测试 | 数据面仍存在未实现分支时 |
| 是否引入应用/设备条件到 DNS Rules | 第一版内部有来源上下文，默认先不暴露 DSL | 完成基础功能且有真实用户案例时 |
| DNSSEC 验证与严格 Fake-IP 转换 | 不伪造验证、不修改签名语义 | 需要建立新的验证链时 |
| 自动 ECS / 自动 SRV 延迟选点 | 默认关闭且不进入 V1 | 已有真实数据、隐私评审及用户 opt-in 后 |

---

## 23. 最终交付判据

下一代 DNS 可以称为“完成基础交付”，当且仅当：

- [ ] 有受维护者批准的**保留/条件继承/放弃**兼容矩阵；放弃已有能力的每项决策都有理由和迁移说明。
- [ ] 被保留旧配置在未开启新策略时通过金标准回归，兼容承诺基于实际测试而非宣传。
- [ ] 同域名不同 QTYPE 可使用不同 DNS 解析器与上游出口；不修改业务出口。
- [ ] Fake-IP 保留域名 → Business Rules 首命中 → DIRECT 真实解析或 PROXY 域名直连出口的链路正确。
- [ ] 前置 GEOIP 需要解析时执行，`no-resolve` 不被破坏；规则引擎无隐式重排。
- [ ] DNS strict proxy 失败无 DNS direct 泄漏，无跨出口缓存与连接池污染，无必然的 bootstrap 递归环。
- [ ] SRV 服务发现既能工作又不会在启用严格 Fake-IP 时从 additional/hints 意外泄漏真实目标；缺口明确报告。
- [ ] 游戏诊断可以重复、可取消、只读、给出证据与不确定性，不自动改用户策略或 SRV 权重。
- [ ] 真实的构建和测试结果、未验证平台/feature、风险、签名提交记录均可追溯。

> **最终原则：只对明确选择保留的旧配置承担强兼容契约；不追求 Mihomo 100% 兼容；对于任何真正破坏性的更改，必须用具体原因、影响面、迁移和测试来换取维护者批准。**
