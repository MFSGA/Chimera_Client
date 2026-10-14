# Reality X25519MLKEM768 完整握手（PR #58 拆分第 3 批）

## 基线和依赖

- 原先直接基于 **PR #63**（`pr58-split/02-reality-keyshare`，`2045b4c24754f64a9237eff5217b3a3770478abe`）构建；PR #63 已合并至 `master`，其 squash 提交为 `4958023b09a4a6415a4215f293f81568bd5c50f4`。本批保留独立增量，并合并远端 `master` 以校准 PR 审查基线。
- 完整代码来源：原始 Draft PR #58 的连续实现提交 `046ffdd`、`ac1486c`、`abc97e6`、`08c9505` 和测试提交 `9203815`、`520ec45`；独立摘取所需代码，不导入 VLESS encryption 或无关上游更新。
- 本批 PR 目标应调整为 `master`，确保完整跨平台工作流对最终提交自动运行；此前以 PR #63 为 base 时只触发了 Spelling 和 Commit Email Check，不能将未执行的 CI 视为通过。

## 协议行为和配置兼容性

- 现有 Reality X25519（TLS group `0x001d`）仍为默认值，不改变旧 YAML 的握手行为。
- 只有显式 `reality-opts.support-x25519mlkem768: true`（或别名 `supportX25519MLKEM768`）才启用 X25519MLKEM768 group `0x11ec`。
- 新增 Hybrid ClientHello KeyShare 与 ServerHello group/长度验证、ML-KEM768/X25519 组合密钥交换、TLS 1.3 完整 64 字节 hybrid shared secret 派生。协商 group 不匹配、长度错误等必须失败关闭，不静默回退为 X25519。
- XHTTP 使用独立端点 Reality 配置，并转发显式 opt-in 开关；该配置不能无意扩张到非 Reality 端点。
- 本批 **不包括** VLESS Native Encryption xorpub/random/0-RTT、加密 UDP、ECH 或 ShadowTLS。

## 验证范围（需对本批最终 SHA 执行）

- `cargo fmt --all -- --check`
- `cargo test -p clash-lib --lib --all-features --locked reality -- --test-threads=1`
- `cargo test -p clash-lib --lib --all-features --locked proxy::converters::vless::tests -- --test-threads=1`
- `cargo test -p clash-lib --test vless_transport_contract_tests --all-features --locked`
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`
- 可用独立 Xray 及 Mihomo 二进制、隔离本机回环环境时，手动执行 `clash-lib/tests/reality_hybrid_xray_interop.sh` 和 `clash-lib/tests/reality_hybrid_mihomo_interop.py`；脚本存在及语法检查**不等于**实际互操作通过。禁止使用真实用户代理凭据或生产配置。
- 必需 CI 成功、独立 **L2 协议/密码学安全审查**及维护者批准，缺一不得合并；禁止删除/降低测试或质量门禁。

## 本轮实际验证与环境限制

- 在同步 PR #63 已合并的 `master` 后，于 macOS arm64 执行 `cargo test -p clash-lib --lib --locked reality -- --test-threads=1`：**149 passed，0 failed，0 ignored**，包括 Reality Hybrid 配置/密钥交换回归。
- `cargo fmt --all -- --check`、`git diff --check` 均通过。Xray Shell 与 Mihomo Python 测试脚本此前仅做语法检查，**未进行实际服务端互操作**。
- 尚未在本轮运行 `--all-features` 测试、完整严格 Clippy 和真实 Xray/Mihomo 互操作，也未取得独立 L2 密码学审查与维护者批准；CI 只认可最终提交对应的检查。
- 初始编码工作区磁盘仅剩约 800 MB，同步最新 `master` 前约 8 GB，本地默认 Reality 单元测试后约 5 GB。不能清理其它工作区或用户已有的约 73 GB 编译缓存；未执行的验证必须如实保留为 `not run`。
