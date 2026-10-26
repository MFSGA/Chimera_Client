# Chimera Client：工程 Lessons / 已验证经验库

用于维护者、编码 Agent 和独立审查 Agent 记录已核实的工程问题及防复发措施。

阅读：[AGENTS.md](AGENTS.md)、[AI 开发治理规范](docs/ai-development-governance.md)、[ref 迁移指南](docs/ref-alignment-guide.md)、[独立审查清单](docs/ai-review-checklist.md)。

## 收录边界

- 只收录有可重复证据、确认的根因以及 Issue/PR/commit/CI 链接的**真实事故**。单次 CI 红灯、尚未复现的怀疑或产品规划不得伪装为已验证教训。
- 把以下类型分开：本地代码回归、上游版本缺陷、Cargo feature/cfg 差异、Rust 并发/生命周期问题、测试隔离或 runner 限制、DNS/TUN/宿主环境问题。
- 记录失败时的 Chimera Client HEAD、`ref/` / `ref-mihomo/` / `ref-meow/` 参考 SHA、OS/toolchain、目标 feature、复现步骤与预期/实际。
- 真正的防复发依据应包括**旧代码在目标断言上失败、新代码通过**的回归测试；注明测试文件、runner 入口和测试是否确实执行。
- **保护用户隐私**：禁止记录真实订阅、凭据、完整代理配置、设备标识和未经脱敏的错误日志。涉及真实网卡/TUN/路由操作，应记录隔离主机及安全恢复。
- 若需要修改 AGENTS、CI、审查门禁或权限，需要独立 L3 审批；经验记录本身不授权改权限、合并或发布。
- 遇到尚无确认根因的失败，先在 Issue 标记“待核实”，不要填入“已确认”。

## 已确认条目

| 编号 | 发现日期 | 模块 | 关联证据                             | 状态 |
| ---- | -------- | ---- | ------------------------------------ | ---- |
| LESSON-20261025-001 | 2026-10-25 | CI / 发布 | [Release run 40272290504](https://github.com/MFSGA/Chimera_Client/actions/runs/40272290504) | 已修工作流；新发布尚未触发 |

### LESSON-20261025-001：Release 版本提升会修改 vendor Cargo 清单

- 日期 / 时区：2026-10-25 / America/Los_Angeles（GitHub Actions 日志为 2026-10-26 UTC）
- 状态：Mitigated；本地工作流修复待维护者批准，未重新触发 Release
- 严重度：Medium
- 模块：CI / 发布
- 本地 HEAD / master：诊断基线 `4fb25ce087c190210c2c869c6de1e7727368fb9e`；失败运行使用旧 HEAD `041de8eca78bf59785510ebdc15806c77535c056`；ref SHA 不适用
- Issue / PR / CI / Commit / 日志（脱敏）：[Release run 40272290504](https://github.com/MFSGA/Chimera_Client/actions/runs/40272290504)，计划版本 `v0.28.0`
- 输入、初始状态与预期：手动运行 `release.yml`，选择 `minor`；预期提升 Cargo 版本、创建版本提交并原子推送 `master` 与版本 tag
- 实际异常与最小复现：`cargo set-version --bump minor` 更新 `vendor/boring-noise/Cargo.toml` 和 `vendor/sock2proc/Cargo.toml`。固定的 `git add` 清单遗漏两者；临时提交 `e043382` 后仍有未暂存改动，`git rebase origin/master` 立即报错。提交和 tag 均未推送。
- 已确认根因与已排除项：根因为发布工作流只暂存列出的 Cargo 文件，没有覆盖版本工具修改的全部 manifest；失败发生在发布原子推送前，与构建、测试或 GitHub 拒绝写入无关。
- 修复文件、回滚条件：`.github/workflows/release.yml` 校验变更范围，只暂存所有修改的 `Cargo.toml` 与 `Cargo.lock`，并在提交后和 rebase 前检查工作区干净；`.github/WORKFLOWS.md` 同步记录。回滚时恢复版本提交步骤和发布事实清单的原版本。
- 旧实现失败 / 新实现通过的真实回归测试与 runner 注册入口：旧流程失败证据为上述 GitHub Actions run；新暂存逻辑在临时 Git fixture 中验证，覆盖 root/vendor manifests、`Cargo.lock` 及提交后工作区清洁。未实际重新运行 Release。
- 验证命令、feature 组合、平台、通过/失败/跳过数量：`actionlint .github/workflows/release.yml` 通过；临时 Git fixture 通过；未运行完整 CI 或真实 Release。
- 受影响的兼容性、系统权限、TUN/网卡恢复检查：仅影响版本发布工作流；未操作 TUN、网卡或生产服务。Release 使用 `contents: write`，新发布仍需单独维护者批准。
- 后续防复发措施：保持 manifest 动态暂存及提交/rebase 前 clean-tree 检查；完成独立审查和维护者批准后，另行授权运行 Release。

## 记录模板

```markdown
### LESSON-YYYYMMDD-001：简短标题

- 日期 / 时区：
- 状态：Open / Mitigated / Verified
- 严重度：Critical / High / Medium / Low
- 模块：CLI / clash-lib / 配置 / DNS / TUN / Proxy / Controller API / Dashboard / CI / 发布
- 本地 HEAD / master / ref 三个 gitlink SHA / toolchain 与 OS：
- Issue / PR / CI / Commit / 日志（脱敏）：
- 输入、初始状态与预期：
- 实际异常与最小复现：
- 已确认根因与已排除项：
- 上游与本地实现的必要差异 / 品牌和许可证：
- 修复文件、最终代码提交和回滚条件：
- 旧实现失败 / 新实现通过的真实回归测试与 runner 注册入口：
- 验证命令、feature 组合、平台、通过/失败/跳过数量：
- 受影响的兼容性、系统权限、TUN/网卡恢复检查：
- 后续防复发措施，若改 CI/治理则附 L3 审批：
```

_本次未把其他仓库的事故或未核实的历史日志自动复制为 Chimera Client 的已确认问题。_
