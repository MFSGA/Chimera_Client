<!--
First of all, thank you for your contribution! 😄
For requesting to pull a new feature or bugfix, please send it from a feature/bugfix branch based on the `master` branch.
Before submitting your pull request, please make sure the checklist below is confirmed.
Your pull requests will be merged after one of the collaborators approve.
Thank you!
-->

### 🤔 This is a ...

- [ ] New feature
- [ ] Bug fix
- [ ] Performance optimization
- [ ] Enhancement feature
- [ ] Refactoring
- [ ] Code style optimization
- [ ] Test Case
- [ ] Branch merge
- [ ] Workflow
- [ ] Other (about what?)

### 🔗 Related issue link

<!--
1. Put the related issue or discussion links here.
2. close #xxxx or fix #xxxx for instance.
-->

### 💡 Background and solution

<!--
1. Describe the problem and the scenario.
2. Provider a sample config if you can.
3. How to fix the problem, and list the final implementation and usage sample if that is a new feature.
-->

### 📝 Changelog

<!--
Describe changes from the user side, and list all potential break changes or other risks.
--->


### ☑️ Self-Check before Merge

⚠️ Please check all items below before requesting a reviewing. ⚠️

- [ ] Doc is updated/provided or not needed
- [ ] Changelog is provided or not needed

### 🧭 AI / Codex governance and upstream alignment

<!-- 与 docs/ai-development-governance.md、docs/ref-alignment-guide.md 和 docs/ai-review-checklist.md 对齐；不要求普通 PR 使用 AI。 -->

- 任务目标与非目标；关联 Issue：
- Risk（取最高级别）：L0 / L1 / L2 / L3；风险原因及维护者批准：
- 目标 `master` / 当前任务分支 / `origin/master` SHA；原有用户未提交改动如何保护：
- `ref/`、`ref-mihomo/`、`ref-meow/` gitlink SHA 和实际参考文件：
- 上游 → Chimera Client 路径/符号与调用链；需要保留的本地扩展和旧配置/协议/API 兼容：
- 如批量复制上游：源/目标文件列表、品牌替换白名单与命中审核、许可证/版权、未完成调用方：
- Cargo feature / `#[cfg]` / Rust/Go 差异与平台风险：

### 🧪 Actual verification evidence

| Check / command | OS + feature / environment | Pass / Fail / Skip / Not run | Test count / run URL / limitation |
| --- | --- | --- | --- |
| Rust fmt / clippy / target unit or integration |  |  |  |
| Cargo feature combinations / workspace / cross-platform |  |  |  |
| Dashboard lint / format / build / interaction |  |  |  |
| Controller / DNS / TUN / network / permission regression (as applicable) |  |  |  |
| GitHub CI / Windows network / coverage / throughput (when triggered) |  |  |  |

### 🔄 CI handoff and commit-history hygiene

- 当前 PR / CI / job 链接与最终 HEAD SHA：
- Required checks 的真实状态：pending / pass / fail / skipped / not run：
- 本地验证完成后，不空等 CI 的独立工作或交接事项：
- CI 失败的复现/根因、是否已在最终代码上解决：
- 同一问题多个临时提交（如适用）：旧 SHA、最终 squash/fixup 与完整 diff/署名核验：
- 覆盖远端任务分支的明确授权、旧/新 SHA、备份及 `--force-with-lease` 记录（如适用）：
- **新 SHA 的 CI/Reviewer/人工审批状态**；旧 SHA 的通过记录不可继承：
- [ ] 在全部必要检查、独立审查、维护者审批完成前不合并或发布

### 🔒 Security, rollback and independent review

- 真实用户配置/订阅/凭据/个人信息是否脱敏；网络、系统代理、DNS、TUN、NIC 的真实权限与隔离：
- 回滚/恢复方案，是否涉及 `ci.yml` 在 `master` 上的 `latest` 预发布：
- Reviewer 身份及独立上下文、审查发现（含 `file:line`）和最终决定：
- 未运行的测试、未覆盖平台与剩余风险：
