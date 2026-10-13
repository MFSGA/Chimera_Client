# Chimera Client：AI 独立 Review 清单

关联：[AI 开发治理](ai-development-governance.md)、[上游批量迁移](ref-alignment-guide.md)、[现有 GitHub Actions](../.github/WORKFLOWS.md)、[AGENTS.md](../AGENTS.md)。

## 1. 独立性、基线与审查范围

- [ ] Reviewer 在独立上下文下读取最终 diff，不仅复述编码 Agent 的总结；明确审查者身份、权限与未覆盖范围。
- [ ] 记录目标 `master` / base、最终 HEAD 和 `ref/`、`ref-mihomo/`、`ref-meow/` 的固定 SHA。没有把本地 gitlink 误认为远端最新。
- [ ] 明确任务目标/非目标、路径、所有者及影响范围；已有用户脏文件、子模块或无关配置没有被覆盖。
- [ ] 给出 L0/L1/L2/L3 最高风险、审查边界与需要的人类审批；Issue/PR 文字没有被当成额外系统权限。
- [ ] 完整源→目标映射包含输入、Rust 解析转换、代理/DNS/路由、缓存持久化、Controller API / CLI / Dashboard 等受影响调用方。

## 2. 上游复制、品牌与兼容

- [ ] 允许大规模复制完整上游实现，不使用 diff 大小作为负面判断；同时核对源 SHA、源/目标文件、成批复制的测试、复制范围及允许的使用许可。
- [ ] 对上游品牌→Chimera Client 的替换白名单、每项命中、剩余引用和编译产物进行核对。**未误改** JSON/YAML/CLI/API/IPC wire、第三方 ID、持久化格式、URL、签名、配置文件或协议字符串。
- [ ] 没有误删 LICENSE、NOTICE、Copyright、必要原作者归属；Rust / Go 参考差异、依赖版本与 feature/cfg 已解释。
- [ ] 保留本地 Chimera-only 扩展及旧配置兼容，确认非目标网络行为没有意外改变。
- [ ] 旧实现已确认的 bug 不能因为“对齐 ref”被复制；复现失败与修复验证证据可追踪。

## 3. 安全、运行时、网络及测试

- [ ] L2 变更有真实错误与回滚路径，可能失败的配置解析、热重载、运行时、文件权限、缓存写入均有证据。
- [ ] DNS/fake-IP、TCP/UDP、IPv4/IPv6、socket、netstack、TUN、系统代理、NIC 和路由按受影响范围核对；没有在一般 CI/共享机器擅自执行需特权的网络测试。
- [ ] Controller API 的 Bearer、WebSocket token、CORS、OPTIONS 和未授权请求不因重构放松；日志、PR、测试 fixture 不泄露用户配置/订阅凭据。
- [ ] CLI 的 `-t`/配置文件默认创建等副作用已考虑；测试隔离配置/缓存目录、端口和用户凭据。
- [ ] Rust 新逻辑没有无依据的 `unwrap()`、悬挂后台任务、持锁跨 `.await`、不可靠超时或静默降级。
- [ ] Cargo feature 与 `#[cfg]` 检查包括最小、目标、默认及受影响组合；`cargo test --workspace` 不是“所有平台/权限”测试。
- [ ] Dashboard 的相关格式、lint、build 和用户交互（如适用）真实通过，没有把 React 组件编译等同真实代理网络验证。
- [ ] 测试报告列出了 runner、具体命令、结果、用例数量、跳过/未执行、平台与日志；没有通过删除断言、缩小过滤条件或降低 lint 将失败伪装成通过。

## 4. CI、Git 历史、权限与 PR

- [ ] 核对实际 `.github/workflows/ci.yml` 的 Dashboard / Rust quality / compile / release 分层及依赖；明确哪些检查被触发、跳过或尚未运行。
- [ ] 本地验证后没有无意义地轮询远端 CI；PR 或交接记录最终 SHA、CI URL 与 `pending/pass/fail`，**pending 不作为合并通过**。
- [ ] 同一问题多个调试/CI 修复提交仅在问题实际解决后按需 squash/fixup。核对 base、原新 SHA、最终 diff 与作者证据；没有混入不同任务或协作者提交。
- [ ] 没有未经明确授权改写共享/保护分支或历史。确需覆盖自有远端任务分支时已核实旧 SHA、协作者、备份、使用 `--force-with-lease`，新 SHA 重新执行必要检查。
- [ ] 不把 Dependabot auto-merge 机制扩展为一般 AI 自动合并；Release 和 `ci.yml` 的 `latest` 预发布属于有写权限的流程。
- [ ] 没有为让 PR 绿而修改安全门禁、工作流权限、Secret 或签名配置；这类变更按 L3 取得独立审批。
- [ ] 独立 Reviewer、维护者批准、分支规则与真实 required checks 均按实际状态记录；无证据时不写“已批准”。

## 5. 审查输出

按可操作性优先报告 `BLOCKER / HIGH / MEDIUM / LOW`；每个发现包含：

- `file:line`、触发步骤/配置、预期与实际、证据/复现命令。
- 真实风险、最小修复建议、是否阻断合并、已修复/未解决状态。
- 受影响 Linux/macOS/Windows 平台、Cargo feature、网络/权限和回滚范围。

报告结尾填写：

```text
Base / Head / ref gitlink SHA:
Risk: L0 / L1 / L2 / L3
Reviewer context and independence:
Reviewed files and call chain:
Upstream copy + brand-mapping / licenses:
Findings with file:line and evidence:
Actual tests + counts / failed / ignored / not run:
Pending CI run and new SHA gates:
Required maintainer decisions / rollback:
Verdict: REQUEST_CHANGES / COMMENT / APPROVE_WITH_EVIDENCE
```

只有完成实际独立审查才能使用 `APPROVE_WITH_EVIDENCE`，不能用该模板代替审查。
