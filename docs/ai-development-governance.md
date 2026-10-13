# Chimera Client：AI 开发治理规范

本规范用于 Codex / AI 编码与独立审查，也适用于维护者组织的手工开发。以仓库实际代码、Cargo feature、GitHub Actions 和当前分支状态为准；**本文只规定行为，不代表 GitHub 已配置自动派单、强制 Reviewer、分支 Ruleset 或 AI 自动合并**。

阅读顺序：[AGENTS.md](../AGENTS.md) → 本文 → [ref 对齐与批量迁移](ref-alignment-guide.md) → [独立审查清单](ai-review-checklist.md) → [实际工作流](../.github/WORKFLOWS.md) → [LESSONS](../LESSONS.md)。

## 1. 任务开始前固定基线

1. 读取用户目标、可观察的验收标准、非目标、允许修改的文件与环境；必要时使用 [AI Issue 模板](../.github/ISSUE_TEMPLATE/ai-task.md)。
2. 记录 `git status --short --branch`、当前 `HEAD`、本地 `master` / `origin/master` 的 SHA、相关分支与 Worktree。**已有未提交内容都视作用户资产**，不自动 reset、stash、覆盖或借机格式化。
3. 上游工作记录 `ref/`（clash-rs）、`ref-mihomo/`、`ref-meow/` 的固定 gitlink SHA 和清洁状态；这些是本地快照，不等于远端最新代码。
4. 沿“配置 YAML → 内部配置 → inbound/outbound → dispatcher/router → DNS/netstack/TUN → Controller API / CLI / Dashboard”确认实际影响范围；特别记录 Cargo feature、平台 cfg、缓存/热重载、用户目录及配置兼容性。
5. 风险按变更涉及的**最高级别**确定，明确授权边界。存在互不相关的工作时优先隔离分支/Worktree；用户指定直接在当前工作区修改且安全可行时，不强制创建 PR/Worktree。

## 2. 风险分级和审批

| 级别   | 典型工作                                                                                                              | 交付要求                                                                      |
| ------ | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| **L0** | 纯说明、注释、普通文档，不修改规范与执行行为                                                                          | 范围审查、格式和链接检查；说明未运行代码测试                                  |
| **L1** | 局部 Dashboard 呈现、已隔离的纯逻辑/低风险代码                                                                        | 相关单元测试、格式、实际 UI 或调用方验证                                      |
| **L2** | 协议/传输、YAML 兼容、DNS/fake-IP、TUN/路由、Controller API 鉴权、CLI 行为、持久化、Rust 公共接口、feature 或依赖变更 | 复现/回归、错误与回滚路径、相关平台和 feature 矩阵、独立 Reviewer、维护者批准 |
| **L3** | `AGENTS.md`/AI 治理、质量门禁/CI、自动合并、GitHub 权限、Secrets、签名、Release、系统级生产操作或审计规则             | 单独说明风险与权限，独立审查，维护者明确批准，不得默认自动执行                |

- Issue 或 PR 的文字不是 Git push、权限提升、发布或修改宿主机网络的授权。
- **自动合并仅以实际工作流为准**：仓库存在 Dependabot 专用 auto-merge，不能将其权限泛化给 Codex 任务。
- 为了让检查变绿而删掉测试、缩小测试过滤器、降低 lint、屏蔽错误、改写 CI 判定，必须视为 L3 并举证说明，不能作为常规故障修复。
- 用户明确授权的仓库写操作仍须校验目标、旧 SHA、工作区及协作者状态；不要把“曾授权过一次”视为永久授权。

## 3. 任务合同、角色与隔离

**编码 Agent**：保存基线、映射完整调用链、选择可验证的实现范围、编写回归测试、执行实际检查、记录剩余风险与未覆盖项。可以大范围迁移一组紧密相关的上游模块，不人为设定 diff 大小上限。

**独立 Reviewer**：在与编码过程分开的上下文里只读查看最终 diff、引用的参考实现、测试和文档。确认非目标未改变、Rust 异步生命周期/feature 组合/系统权限/授权、配置和 wire 协议兼容，输出可复现问题与 `file:line` 证据。编码 Agent 不能把“我检查过”冒充独立审查。

**维护者**：对 L2/L3、共享分支、发布或系统权限给出最终决定。仓库没有自动实现时，状态写 `pending`，而不是声称已通过 AI Reviewer 或 Branch Protection。

- 用户有脏工作区时，只动指定范围；避免在原工作区切换分支、自动 stash、重置他人的内容。高风险或并行任务优先独立 Worktree。
- 使用确定的共同基线；修复一个问题的后续提交应关联同一问题，避免混入另一项任务。
- 不随手更新 submodule、`Cargo.lock` 或脚本工具链；上游参考目录通常只读。必要变更必须记录版本原因。

## 4. 上游大范围复制与品牌统一

**明确允许大范围复制上游完整实现**。当一次迁移需要完整模块、调用链、测试和资源才能保持一致时，可以成批复制 `ref/`、`ref-mihomo/` 或 `ref-meow/` 中**获准使用**的相关文件，再按审核过的映射统一替换上游品牌为 Chimera Client 品牌；不为缩小 diff 而机械拆散一项完整特性。

- 先锁定参考 commit/许可，列出源→目标文件、符号、feature、行为映射；只复制职责完整的相关范围，不等于放任无关全仓复制。
- 替换名称时使用**白名单与作用域**，逐项审查命中；禁止盲目全局替换协议字段、wire/JSON/YAML/CLI 参数、第三方库 ID、下载地址、持久化文件名或外部 API，除非证明有独立的兼容迁移方案。
- 必须保留上游许可证、版权、NOTICE、来源和必要的 attribution；不同 Rust/Go 项目的许可与实现语言不自动相容，不能把 Go 源码当成可直接 Cargo 构建的 Rust 文件。
- 保留 Chimera-only 的 DNS、TUN、网络安全、Controller API、Dashboard、协议与缓存扩展；复核 feature 转发、平台 cfg、出入口、超时/取消、资源清理与配置旧格式。
- 在实际合并前跑相应行为与失败路径回归，检查品牌残留与错替换；在 PR 中列出未覆盖平台和实际复制清单。

执行细则见 [ref 对齐与批量迁移指南](ref-alignment-guide.md)。

## 5. 验证矩阵与交付边界

| 影响范围                   | 首选验证                                                                                                                | 不能由此声称                                 |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| 普通文档                   | 链接、事实、Markdown、`git diff --check`                                                                                | Rust 或网络行为通过                          |
| Rust 局部逻辑              | `cargo fmt --all -- --check`、相关 `cargo test -p <package>`、`cargo check -p <package>`                                | 未测 feature 或跨平台等价                    |
| 公共接口/协议/配置         | `cargo test --workspace`、相关集成测试、`cargo clippy --workspace --all-targets -- -D warnings` 及受影响的 feature 组合 | 真实 TUN、DNS 权限、生产配置安全             |
| Controller API             | 真实请求、鉴权/CORS 与 WebSocket 相关回归、失败/取消路径                                                                | Dashboard 按钮或未执行的平台 E2E             |
| Dashboard                  | `cd clash-dashboard && npm run format:check && npm run lint && npm run build`、相关实际交互验证                         | 代理数据路径与 OS 网络已验证                 |
| Windows/Linux/macOS 和网络 | 运行实际目标 runner 的适用 CI/集成测试；确认 loopback/VM/真实宿主边界                                                   | 未运行平台、实际 NIC/TUN、真实公网或权限操作 |
| CI/Release                 | 校对 YAML 触发器、权限、构建产物与 GitHub run/job URL；更新门禁经 L3 审批                                               | CI 绿等于 Release、tag 和安装成功            |

- 相关命令的前提与 Cargo 特殊配置见 [AGENTS.md](../AGENTS.md)；`cargo test --workspace` 不会覆盖所有 `#[ignore]`、自定义 `docker_test` / `throughput_test` 或未选中的 feature。
- 复现缺陷时优先让旧行为在目标断言上失败，修复后通过；不可用“编译失败”代替目标回归证据。集成测试使用独立配置目录/端口，不改真实用户配置、系统代理、NIC、TUN、路由或安装服务，除非在用户批准的隔离环境执行。
- `ci.yml` 的 Dashboard、Rust quality、compile 和 release 依赖存在不同门禁；按 job 和 runner 实际结果逐项记录 pass / fail / skip / not run，不能把 skipped 当成 pass。
- L2/L3 的最终合并还须核对必要 CI、独立审查与人类批准，不能只凭本地绿色判定发布完成。

## 6. 不空等 CI，但绝不绕过 CI

1. 完成本地相关验证并在获授权的 PR/push 触发远端检查后，记录提交 SHA、实际 PR/run URL 和检查状态 `pending`。
2. 不要为 CI 反复轮询或长时间占用交互；继续推进**已授权、无需依赖 CI** 的审查、文档、隔离任务或额外本地验证。
3. 没有这种独立任务时，交接“本地已验证、CI 待确认、阻断合并的检查、后续动作”，结束当前执行；**不得声称可以无人值守后台持续监控**。
4. 获得失败结果时先诊断日志，区分新测试覆盖、真实产品回归、平台/工具链问题；禁用检查不是修复。
5. **CI pending 并不是 success**。required checks、独立 Review、维护者批准未满足，不得自行合并、打 tag 或发布。

## 7. 同一问题多次修复：验证后再压缩提交

- 同一个 Issue 可能产生“初始提交 → review 修复 → CI 修复”等多个临时 commit。**调试时先保留记录，直到最终行为及相关本地回归得到验证**；远端 CI 未完成时只能说“本地验证通过、远端待确认”。
- 确认问题实际解决、必要检查结果明确后，在**自有、尚未合并的任务分支**本地以 `git rebase -i <base>` 做 `squash`/`fixup`，将同一问题的补丁整理为一个完整可审查的 commit；有独立回滚价值的变化可保留多个逻辑提交。不可混入别的 Issue 或他人提交。
- 改写前记录原/新 SHA 和共同 base，检查远端变化、协作者状态及用户未提交数据；保留可恢复备份。改写后验证 `base..HEAD` 最终 tree/diff、署名、回滚路径和测试。
- **未经本次明确授权，禁止改写已发布的 `master`、其他受保护/共享分支、tag、已合并提交或他人历史。** 若用户明确要求重排共享历史，还需先核对分支保护、协作者和备份；安全可行且获得确切授权才可执行，不是默认的 squash 路径。
- 已获许可覆盖独立远端任务分支时，仅使用与预期旧 SHA 对应的 `--force-with-lease`，不用裸 `--force`。若多人共享或旧 SHA 改变则停止，走新提交/PR 流程。
- squash/rebase 产生新 SHA 后，旧 SHA 的 CI 和审查结论**不能自动继承**；针对最终 SHA 重新经过实际必需门禁。不要删除 Issue/PR 中的失败历史和诊断证据来伪造成功。

## 8. 完成与记录

完成时说明：目标/非目标、修改范围、`master` / `ref` 基线、关联 Issue/PR、实测命令+环境+结果+数量、未执行/跳过、Reviewer 结论、风险/回滚、CI pending 链接与下一步。

真实且已查明根因的事故按 [LESSONS.md](../LESSONS.md) 归档，未确定根因的情况仅标为待核查。**本治理文档不会安装新 CI、提升 GitHub 权限、修改保护规则或自动创建 PR。**
