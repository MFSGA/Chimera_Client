# 下一代 DNS S02：无副作用查询计划器

> 基准：`6ca38499e87b57649e6a4902c73a501ae171cb41`（S01 本地签名提交）。
> 依据：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md) §5、§6.2、§17.3；S00 旧行为依据 [`dns-legacy-golden.md`](dns-legacy-golden.md)。
> **状态：纯数据规划，非执行器。** 非空 `policy-rules` 的运行时仍在 `app/dns/resolver/mod.rs` 明确拒绝启动，直到 S03 真正验证 DIRECT/PROXY DNS 拨号及失败限制。

## 结构和边界

`app/dns/plan.rs` 仅导出以下纯计算结构：

- `DnsQueryContext`：规范化 QNAME、RecordType、DNSClass、DnsPurpose、来源作用域（Host/Gateway namespace）、网络代际、配置代际及 RD/CD/AD/EDNS/DO 标志。请求必须只有一个标准 DNS Question；S02 不自行解析或拆分多问题 DNS 报文。
- `DnsPurpose`：ClientRealAnswer、RouteClassification、DirectDestination、ProxyDestinationLocal、ProxyNodeBootstrap、ResolverBootstrap、Diagnostic。它仅传递调用者已知的**用途**，不能被解释为“自动改变业务出口”。
- `LegacyDnsPlan`：调用者提供的旧路径标识，支持 LocalAnswer、Main、MainWithResponseDependentFallback、FallbackOnly、NameserverPolicy、ProxyServerNameserver、DirectWithMainFallback。**只有现有 legacy runtime 能知道真实命中的配置路径及网络状态**，S02 没有重算旧 DNS 的过滤、缓存、主备选择，也没有据 QTYPE 或 purpose 自作推断。
- `EffectiveDnsPlan`：原样携带 `LegacyDnsPlan`，并对 resolver/egress/failure 分别使用 `InheritLegacy` 或 `Profile/Explicit` 强类型。记录首个匹配规则的原始 ordinal。覆盖的只有规则中显式填写的维度；其他字段仍是 InheritLegacy，不会默认 DIRECT。
- `CompiledDnsPolicy::build_effective_plan(context, legacy)`：纯函数、不访问网络或 Router。按 S01 已通过测试的**规则原始顺序**匹配 QNAME+QTYPE；没有规则/未命中则 3 个维度全部继承旧路径。对 `LocalAnswer` 的 Fake-IP/hosts 和非 IN 查询保守跳过新规则，不主动进行真实解析。

**关键性质**：S02 的 `LegacyDnsPlan` 是旧路径的不透明承诺，而非运行时转发计划。当前旧 DNS 的主 + fallback 可能根据回答是否有可接受 IP 再决定是否采用 fallback，`MainWithResponseDependentFallback` 只保留这个动态策略的身份；它**不是**某个固定 resolver IP。S03 必须由实际旧决策链产生合法的 LegacyDnsPlan，并原样执行继承部分，不能用 S02 描述替代已有执行逻辑。

## 离线验收

```bash
cargo test -p clash-lib --test dns_policy_s02_tests --locked
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
ci/verify-quality-gates.sh --quick
cargo check -p clash-lib --no-default-features --locked
```

- 旧配置无新字段：所有旧路径（含 policy、proxy-server、直接解析及动态 fallback）透传不变，业务规则保持 GEOIP → DOMAIN-SUFFIX → MATCH 顺序。
- 配置了新规则但**未命中**时，已有 nameserver-policy 和动态 fallback 路径保持不变。
- 同域名 A、AAAA、SRV 命中不同规则及不同 DNS 出口规划，TXT 不匹配时仍继承旧值；完全没有真正网络拨号。
- 显式 `on-failure: fail` 只覆盖 failure，legacy fallback 的描述仍保留，必须由 S03 明确阻止不被允许的 fallback 执行。
- exact/suffix 同时匹配时以先写的规则为准。不同 purpose 仅保留调用者传入的不同旧路径，S01 还没有 purpose 条件，不会暗改出站。
- Fake-IP/hosts 本地应答标记不触发新的 DNS 出口覆盖。非 IN QCLASS 不匹配新规则，保留旧行为。
- Gateway 来源及网络/配置代际与 DNSSEC/EDNS 查询上下文不丢失，但 **S04 之前未实现跨来源/代际的缓存、连接池物理隔离**；不能因为结构中有这些字段就宣称隔离已经生效。
- 无效 QNAME、多问题、非查询 DNS 消息明确报错；S01 编译产物缺 profile 的异常情况 fail-closed。

## S03 准入与不可宣称的能力

1. 在真实 `EnhancedResolver`、DNS 入口与 Dispatcher 之间确定如何**由旧代码**传入准确的 legacy path，包括非 A 和 Fake-IP、nameserver-policy、proxy-server-nameserver 与 direct fallback。S02 故意未接线。
2. 真正执行时必须使用清晰的 DNS wire protocol + egress 限制，不得用普通业务 Router 取代显式 DNS egress；`proxy:<name>` 失败不可以猜测 DIRECT；`on-failure: fail` 不能穿越不受信任 fallback。
3. 不同 resolver-profile/egress/网络代际缓存及连接池必须有验证过的隔离键；S02 只保留上下文，不启用新缓存。
4. 对未命中政策/没有政策、Fake-IP、hosts、SRV、旧 fallback 运行 S00 黄金回归并增加运行时出站跟踪计数；用户 Business Rules 顺序与最终业务出口保持原样。
5. DNS Bootstrap 环必须结合运行时实际代理组叶节点和递归深度防护。S01 静态环检查并不足以证明动态情况安全。

**本轮没有修改生产 DNS 查询函数、DNS 缓存、网络拨号、业务路由或系统 TUN；也没有启用下一代 policy-rules 的执行。**
