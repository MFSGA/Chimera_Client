# 下一代 DNS：S01 配置编译器验收记录

> 对应 RFC：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md) §6.1–6.3、§16、§17.2。
> S00 起点：`f62be5fd294ce6daff3fa48971eadb82c86da567`；仅在本地 `master` 工作。
> **当前是 S01 纯编译器，不是可执行的下一代 DNS**。现有 DNS 查询、Fake-IP 和 Business Rules 顺序不改变。

## 配置形态（暂不用于生产 DNS 执行）

```yaml
dns:
  enable: true
  nameserver: [1.1.1.1]
  default-nameserver: [223.5.5.5]
  resolver-profiles:
    trusted:
      servers: ["https://cloudflare-dns.com/dns-query"]
    local:
      servers: ["192.0.2.53"]
  policy-rules:
    - match:
        domain-suffix: game.example
        qtype: [A, AAAA]
      action:
        resolver: trusted
        egress: "proxy:DNS-OUT" # 必须引用配置中的现有代理或组
        on-failure: fail
    - match:
        domain: _minecraft._tcp.game.example
        qtype: SRV
      action:
        resolver: local
        egress: direct
```

以上是**编译器接受的示例**，目前**不能直接作为运行中会执行的功能配置**：S01 对非空 `policy-rules` 的 DNS 运行时启动显式报错（`compiled but not executable yet (S01)`），防止配置了 `on-failure: fail` 却悄悄照旧路径查询 DNS。后续只有完成 S02 查询计划器和 S03 出口执行验证才可以去除这个防护。单独声明 `resolver-profiles` 目前只完成解析校验，并不会改变旧 DNS 解析器的执行。

## 编译产物及严格约束

- `config/def.rs`：增加可选 `resolver-profiles`、`policy-rules` 原始类型；保留所有已实现旧 DNS 字段和值类型；新增对象 `deny_unknown_fields`，不把未来未实现的选项当作有效配置。
- `app/dns/policy.rs`：只读、无拨号的 `CompiledDnsPolicy`；`match_query(QNAME, QTYPE)` 使用 YAML **原始顺序首条命中**，返回 0-based ordinal。精确域名不会自动覆盖排在前面的后缀规则。
- QNAME 大小写、尾点和国际化域名进行 IDNA/Punycode 规范化；域名后缀要求 label 边界，`notexample.com` 不是 `example.com` 的子域；`_minecraft._tcp` 等 SRV 名称允许使用。
- `qtype` 可用标量（`SRV`）或数组（`[A, AAAA]`）；支持现有 Hickory 标准类型、`TYPE1..TYPE65535` 数值扩展；不提供 `qtype` 表示所有类型。空规则条件、冲突 `domain/domain-suffix`、重复/非法 qtype 明确报错。
- `action` 中 `resolver`、`egress`、`on-failure` 都是**可选维度**；未填写的维度仍为 `None`，不得在未来 S02 偷偷填充新默认值。空 action 拒绝。当前 egress 只允许 `direct` 或 `proxy:<存在代理/组>`，明确拒绝未实现的回退模式；`on-failure` 只允许 `fail`。
- 编译时拒绝 DNS 未启用却配置新功能、空/无效 resolver profile、未知 resolver/代理、`respect-rules` 与显式出口冲突、服务器 `#proxy/#interface` 强制路径与显式 egress 冲突。
- 防护可检测显式 proxy / 静态代理组的**明显自我引导循环**（DNS 规则针对代理节点自身域名，并将其引回依赖的同一代理/组），附带规则序号与节点名报错。动态 Provider/Selector、跨 profile 复杂依赖及运行时循环深度守卫**尚未实现**，必须在 S03/S04 继续验证。
- 新产物只存入 `app::dns::Config.compiled_policy`，没有接入 `EnhancedResolver::exchange`、`DnsRuntimeProvider`、业务路由或缓存键。因此 **T03/T04 只有编译器匹配断言**，不能声称 egress 发生了真实的 PROXY/DIRECT 网络行为。

## 离线验收

```bash
cargo test -p clash-lib --test dns_policy_s01_tests --locked
cargo test -p clash-lib --test dns_legacy_golden_tests --locked
ci/verify-quality-gates.sh --quick
cargo check -p clash-lib --no-default-features --locked
```

验收重点：缺省新字段保持 legacy Config 与 Business Rule 顺序，配置解析不产生 DNS 拨号；同域名 A 与 AAAA 按各自 ordinal 匹配；反向规则顺序能改变命中；SRV/HTTPS/SVCB/未知数字 QTYPE 正确解析；非法路径和未知字段失败；运行时严格拒绝未接线的执行策略。

## S02 准入依赖及未完成风险

1. 建立无网络副作用的 `DnsQueryContext` / `LegacyDnsPlan` / `EffectiveDnsPlan`，由显式规则仅覆写已填写维度。
2. 未命中策略或没有新规则时，原样执行旧 resolver、fallback、缓存和 Fake-IP 路径；旧 S00 Golden 必须持续保持通过。
3. 为所有 DNS 用途区分 ClientRealAnswer、RouteClassification、DirectDestination、ProxyNodeBootstrap 等，避免靠 QNAME/QTYPE 偷偷判断业务出口。
4. S03 真实 `proxy:<group>`、`direct` 出口必须具备不越权回退的验证，并按路由/缓存/连接池作用域隔离；完成前不能启动使用 `policy-rules` 的运行时。
5. 显式 `on-failure: fail` 和 bootstrap 的完整多跳循环验证，以及同一 DNS endpoint 的代理/直连隔离，S01 仅构建配置层防护，不是安全证明。

**本轮不触发公网 DNS，不执行系统 TUN，也不修改业务出口。** 质量门禁、签名和 Git 推送状态应以实际运行/提交结果为准。
