# VLESS client-fingerprint 显式校验（PR #58 拆分第 1 批）

## 范围和来源

- 基线：远端 `master` `406b0e01d37694af5999f2e038c93cd5453ac411`。
- 来源：Draft PR #58 `130ef1f71b1c69d09011b3cf37aa845b6f431d41`，主要提取历史提交 `a66b6a6` 中的配置校验逻辑与回归测试。
- 仅修改 VLESS 的 `client-fingerprint` 配置校验，**不**加入 uTLS 指纹伪装、Reality X25519MLKEM768、xorpub/random 运行时、0-RTT 或 UDP 功能。

## 兼容性影响

- 不再只记录 warning 并忽略不受支持的指纹；配置转换阶段明确拒绝。
- Reality 允许省略指纹或显式 `chrome`；显式 `none` 与其他未支持值返回错误。
- 非 Reality 允许省略指纹或显式 `none`；`chrome`、`firefox` 等不能实现的浏览器指纹返回错误。
- XHTTP 上传和下载端点分别按其实际安全模式校验；上传端点显式安全模式覆盖顶层设置时，延迟到端点做最终判断。
- 对于过去依赖“仅警告、继续运行”的配置，需要删除无效字段或更换受支持的指纹值。

## 验证要求

- `cargo fmt --all -- --check`
- `cargo test -p clash-lib --lib --locked proxy::converters::vless::tests -- --test-threads=1`
- `cargo test -p clash-lib --test vless_transport_contract_tests --locked`
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`
- 检查最新提交的适用 CI 和独立 L2 协议/配置安全审查；维护者批准之前保持 Draft，不合并。

以上列出的是目标验收命令，实际执行结果应以 PR 检查和本次交付记录为准。
