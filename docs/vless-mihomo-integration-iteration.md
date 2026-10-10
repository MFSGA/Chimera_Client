# VLESS / Mihomo 分阶段集成记录

## 基线与原则

- 集成分支：`integration/vless-mihomo-next`，初始基线为 `master` 的 `229218a073b3275b83080dc2940b407ae9656b14`。
- 历史参考分支：`integration/vless-mihomo-full-v0256`（`b93bf8efc72fe5f9a7beda3b034b391a6313d7a4`）。只读参考，不整体合并其旧代码。
- 保留现有 XHTTP、gRPC、VLESS native 1-RTT、Reality、网络路径恢复和连接池隔离；优先移植实质缺失的能力。
- 每个切片单独测试并推送集成分支；只有完整回归与必要的真实服务端互操作检查通过，才考虑对 `master` 做 rebase + fast-forward 合并。
- 有意保持 Netstack 既有详细调试日志，本集成不引入日志脱敏改动。

## 迭代 1：VLESS client-fingerprint 显式校验

### 差异与影响

主线对部分 `client-fingerprint` 配置只输出 warning 后忽略，旧参考分支采取 fail-closed 配置校验。首轮在**不添加 uTLS/浏览器指纹模拟**的前提下修复静默忽略：

- Reality 仅接受 `chrome`（及省略该字段）；不把 `none` 伪装成可选 Reality 指纹。
- 非 Reality 接受 `none`（及省略字段）；`firefox`、普通 TLS 的 `chrome` 等不支持值在转换阶段明确报错。
- XHTTP 的上传和下载端点各自按**最终实际使用的安全模式**校验指纹：允许 Reality+Chrome；允许普通 TLS+none；对继承的 Chrome 指纹若下载端点改用 TLS 则报错。上传端点显式配置的安全模式可覆盖顶层配置，不能仅靠顶层 `reality-opts` 判断。
- 这是兼容性行为变化：过去只警告但忽略的配置现在可能拒绝加载；请删除不生效的 `client-fingerprint` 或使用受支持的配置。

### 测试与完成标准

- 先新增反向回归测试，确认未修改旧行为时 `vless_reality_rejects_unsupported_client_fingerprint` 失败。
- 验证命令：
  - `cargo fmt --all -- --check`
  - `cargo test -p clash-lib --lib --locked proxy::converters::vless::tests -- --test-threads=1`
  - `cargo test -p clash-lib --test vless_transport_contract_tests --locked`
  - `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`
- **实际结果（2026-10-11）**：原有代码对新增拒绝案例未报错，确认回归测试可复现问题；默认配置 VLESS converter 测试 88/88 通过，全功能 100/100 通过，transport contract 3/3 通过，严格 all-targets/all-features Clippy 通过，Rustfmt 通过。
- **既有最小 feature 阻塞**：`cargo check -p clash-lib --no-default-features --features tls --locked` 在 DNS / 网络模块出现 7 个 dead-code 错误；在未修改的 `master`（`229218a`）隔离工作区复验，也出现**完全相同的 7 个错误**，不是本轮引入。后续单独修复，不放宽检查。
- 完整 CI 和真实服务端互操作尚不能由本地单元测试代替，需在分支推送后验证。

## 待办路线（按可验证的切片推进）

1. **P1 Reality X25519MLKEM768**：提取混合密钥交换，保留普通 X25519 语义，复用并更新 Xray 互操作脚本。
2. **P1 VLESS Encryption**：分开评审 0-RTT ticket/replay 风险及 `xorpub`/`random` 外观模式，不替换现有 1-RTT 实现。
3. **P2 ECH / ShadowTLS**：按真实兼容性需求决定是否继续移植；不默认扩张所有理论组合。
4. **独立于 VLESS 的 Netstack 优化**：公平出站队列不混入上述协议提交。
5. **验收**：主要 feature 组合、跨平台构建、旧配置负面校验和真实 Xray/Mihomo E2E。

## 后续每小时检查记录

每次运行应注明：源/目标 SHA、本轮修改、实际测试结果、CI 状态、阻塞项和下一可交付切片；不得把尚未验证的工作标为完成。完成验收前保留集成分支，不更改 `master`。
