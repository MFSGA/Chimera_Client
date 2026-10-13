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
| —    | —        | —    | 本次建立规范，尚未收录经核实的新事故 | —    |

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
