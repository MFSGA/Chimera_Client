# Reality X25519MLKEM768 完整握手（PR #58 拆分第 3 批）

## 基线和依赖

- 直接基于 **PR #63**（`pr58-split/02-reality-keyshare`，`2045b4c24754f64a9237eff5217b3a3770478abe`）构建本批；该前置 PR 尚处于 Draft，未合并 `master`。
- 完整代码来源：原始 Draft PR #58 的连续实现提交 `046ffdd`、`ac1486c`、`abc97e6`、`08c9505` 和测试提交 `9203815`、`520ec45`；独立摘取所需代码，不导入 VLESS encryption 或无关上游更新。
- 本批 PR 在 PR #63 合并前 **以 PR #63 分支为 base**，只审查增量。前置 PR 合并后，核对最终 SHA、差异和 CI，再把目标调整到新 `master`；不会提前合并。

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

## 本轮环境限制

- 编码工作区所在磁盘余量约 800 MB，无法安全运行新的 Cargo 全功能构建；不清理其它工作区或用户已有的约 73 GB 编译缓存。未运行项应如实保留为 `not run`。
