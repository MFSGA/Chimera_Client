# Chimera Client：GitHub Actions 事实清单与 AI 门禁

> 这份清单以本仓库 `.github/workflows/` 文件为事实来源。**这是说明文档，不是本次自动安装或开启的 GitHub Ruleset、Codex Reviewer、required-check、定时任务或自动发布机制。** 实际运行结果以 GitHub run/job 和仓库设置为准。

参阅：[AGENTS.md](../AGENTS.md)、[AI 治理规范](../docs/ai-development-governance.md)、[独立审查清单](../docs/ai-review-checklist.md)。

## 1. 现有工作流

| 文件                                 | 现有触发器                                                   | 实际重点与限制                                                                                                                                                                                |
| ------------------------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ci.yml` — CI                        | push/PR 到 `master`；`v*` tag push；手工 `workflow_dispatch` | Dashboard 先在 Ubuntu 跑 `npm ci`、lint、format、build；Rust quality 在 Ubuntu/Windows/macOS 跑 clippy 与 LAN proxy；compile 依赖 dashboard+quality，按目标平台交叉编译；release 依赖 compile |
| `coverage.yml`                       | 以 YAML 为准的 push/PR                                       | 覆盖率独立作业；并不等价于全功能/全平台验证                                                                                                                                                   |
| `windows-network-regression.yml`     | `master` 上相关路径 push/PR、手动                            | Windows 上的 TCP/UDP loopback、pool/selector/dispatcher 回归；代码明确不做特权 TUN/NIC 真实变更                                                                                               |
| `proxy-throughput.yml`               | 指定路径 PR/push、手工                                       | 性能/吞吐专用验证；与普通 Rust 单元测试边界不同                                                                                                                                               |
| `proxy-throughput-release.yml`       | PR、手工                                                     | release 优化吞吐测试；不是自动批准发行                                                                                                                                                        |
| `macos-build.yml`                    | 手工                                                         | 独立 macOS 构建入口                                                                                                                                                                           |
| `spell-check.yml`、`email-check.yml` | PR                                                           | 拼写与 Commit 邮箱检查，检查结果不得忽略                                                                                                                                                      |
| `dependabot-automerge.yml`           | CI `workflow_run: completed`                                 | **只处理通过 CI 的 Dependabot PR**；二次核对作者、HEAD SHA、base、所有 PR checks，然后 rebase merge 并手工 dispatch CI                                                                        |
| `release.yml`                        | 手动 `workflow_dispatch`                                     | `contents: write`；版本提升，重试 rebase 并原子推送 `master` 与版本 tag，可能变更共享 Git 历史                                                                                                |

**重要事实**：`ci.yml` 的 `release` job 会在 `master` 构建链通过后处理 **`latest` 预发布/tag**，在 `v*` tag 构建后处理稳定 Release。因此 **push 到 `master` 不应被描述为只有只读测试**；推送和 workflow_dispatch 必须先获得明确授权，发行链按 L3 处理。

仓库没有通用 AI 自动合并入口；Dependabot 专用 workflow 的凭据与权限不能授给未审查的 AI 任务。

## 2. 项目事实与检查范围

- **Dashboard**：当前 `ci.yml` 设有 `npm run lint`、`npm run format:check`、`npm run build`；只代表这些步骤确实在 runner 执行，不能证明与真实 Proxy/TUN 交互。
- **Rust quality**：`cargo fmt --all -- --check`（Linux），`cargo clippy -p clash-lib --all-targets --all-features -- -D warnings`、Linux 的 workspace clippy 默认组合，以及 LAN proxy 集成测试。查 job 时同时确认平台与选中的 feature。
- **Compile**：多个 Linux/Windows/macOS 目标、部分 `cross`/不同 feature，`no-test` 与 PR 条件使某些目标不会运行测试。构建成功不等于真实运行或网卡/TUN 权限验证通过。
- **Windows network**：测试明确使用本地 loopback；不覆盖真实 NIC 修改、安装网络驱动或生产路由权限。
- **Coverage / throughput / spell / email**：是不同独立工作流；PR checks 未完成或按路径跳过时均需说明，不可混为全绿。

## 3. CI 不空等，但仍是合并门禁

- 完成相关本地测试，记录实际命令、平台、运行数量、失败/ignored、最后成功日志或摘要。
- 只有**得到授权**才能 push、创建 PR、触发手工 release/CI 或系统测试。触发后记录本次 SHA、PR、run URL、`pending/pass/fail/skipped/not run`。
- 远端 CI 执行时不要长时间反复轮询或原地等待；继续已授权、相互独立的审查/文档/本地检查。没有其他独立工作时如实交接 pending，不虚构后台监控。
- 合并、打 tag 或发布前，必须针对**当前最终 SHA**核对 required checks、维护者审批及提交的 GitHub **Verified** 状态；L2 默认独立 Reviewer，但仓库所有者可以对具体 SHA 明确豁免独立审查或非强制验证。未 Verified 的 SHA 必须取得所有者单独审核批准或重签名；旧 SHA 的绿色、签名状态和豁免不能继承给改写后的提交。L3 仍需独立审查和明确批准。
- CI 失败先诊断问题是否由扩大测试范围、前置环境、cross feature、Dashboard 等引起；不为变绿而禁用失败测试、改权限或删除审查门禁。

## 4. 同一 Issue 的提交整理与历史改写

1. 调试阶段允许多个修复 commit；保留失败日志、先前尝试和 Review 证据。
2. **确认问题实际解决以后**，仅在自己的未合并任务分支用 `rebase -i`、`squash` 或 `fixup` 整理同一 Issue 的相关提交。避免把不相关改动混入一项修复。
3. 改写前验证干净状态、共同 base、远端旧 SHA、参与协作的人和恢复备份。改写后对照最终 tree/diff、署名、必要测试。
4. 未经单独明确授权不得重写 `master`、发行 tag 或其他人/共享分支历史。需覆盖已获授权的自有任务分支时用带具体预期 SHA 的 `--force-with-lease`，不能裸 `--force`。
5. 更新后的 SHA **重新执行 CI/Review**。对共享/保护分支的特殊历史整理，即使用户明确要求，也须先校验保护规则、协作者、备份与原远端 SHA；不应作为一般修复的默认步骤。

## 5. Codex 自动化：待单独实现

目前本次治理文档不实现以下动作：自动派 Issue 给 Codex、自动创建工作分支或 PR、自动 AI Reviewer、CI 检查后通用自动合并、定时生成经验文档、设置 GitHub Rulesets。

如后续要实现，应另开 L3 任务，列出最小 GitHub token scopes、不可信 PR 内容的隔离策略、自动化失败可追溯性、维护者审批和回滚；不可复用 `release.yml` 或 Dependabot 的写权限作为一般 AI 任务令牌。
