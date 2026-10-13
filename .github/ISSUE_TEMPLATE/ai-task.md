---
name: AI / Codex engineering task
about: 可验证的 Chimera Client 任务；本 Issue 不授权推送、合并、系统网络操作或发布
title: "[AI Task] "
labels: []
assignees: []
---

## 目标与可观察验收标准

<!-- 具体输入、预期行为、失败时如何发现；不要只写“与上游一致”。 -->

## 非目标与改动范围

<!-- CLI / clash-lib / clash-dns / clash-netstack / Dashboard / feature / 平台；明确不碰哪些用户工作。 -->

## Git 基线与上游映射

- 本地 `master` / `origin/master` / 工作分支 SHA：
- 用户未提交改动与隔离方式：
- `ref/`、`ref-mihomo/`、`ref-meow/` gitlink SHA：
- 参考源路径/符号及目标路径/符号：
- 必须保留的 Chimera-only 行为、协议字段与旧格式：
- 若批量复制：复制的完整模块、品牌映射白名单、每项命中和 License/NOTICE 审查：
- 上游已知缺陷及必要本地偏离：

## 影响链和 feature

<!-- 配置 YAML → 内部配置 → Proxy/DNS/TUN/Route → Controller API/CLI/Dashboard；受影响 feature / cfg / 依赖和平台。 -->

## 风险等级与授权

- [ ] L0 普通非治理文档
- [ ] L1 局部低风险代码/界面
- [ ] L2 Rust 网络/协议/配置/API/feature/数据/权限
- [ ] L3 AGENTS/CI/自动合并/权限/Secrets/签名/发布/治理规则

- 取最高级别的原因：
- 审查者与必要维护者：
- 是否明确允许 Git push / PR / release / 系统网络副作用：

## 测试合同

<!-- 初始状态、一次被测操作、独立结果来源、回归反例、失败/取消/回滚；测试文件、命令、feature、OS、实际用例数。 -->

## CI 与交付

<!-- 新 SHA 的检查、run URL、pending/失败、独立 reviewer、回滚。CI 未完成不自动授权合并。 -->

## Git 整理计划（如适用）

<!-- 同一问题的多个修复 commit，确认问题解决后的 squash/fixup；旧/新 SHA、用户明确授权、--force-with-lease 与重新验证。 -->
