# Reality ServerHello KeyShare 解析（PR #58 拆分第 2 批）

## 基线与边界

- 基线：远端 `master` 的 `20d6b2743033ff4fc85fdc8f4f8373a4cbbb7b47`（包含已合并的 PR #62）。
- 来源：Draft PR #58 的 `53b811ffee0879b5a46752d666e41f9837193106`，仅提取 `reality_util.rs` 的 ServerHello KeyShare 解析与测试；不复原整份历史集成记录。
- 本批只识别 TLS 1.3 ServerHello 的 X25519（`0x001d`）和 X25519MLKEM768（`0x11ec`）KeyShare 格式。
- **不启用 Hybrid 握手**，不生成客户端 Hybrid KeyShare、不执行 ML-KEM 运算、不改变现有 Runtime 对 TLS 共享密钥的派生。

## 行为与安全性

- 解析结果包含 group 和完整服务端 KeyShare 字节，并验证各自的固定长度：X25519 32 字节；X25519MLKEM768 1088 + 32 字节。
- 未知 group、错误声明长度、截断及附加尾部数据必须返回错误。
- 原有 `extract_server_public_key()` 只接受 X25519；面对 Hybrid 必须明确报错，禁止误把 Hybrid 中的 X25519 分量当作完整共享密钥。
- 经典 X25519 的正常网络行为保持不变。能解析 Hybrid **不代表客户端已经支持 Hybrid Runtime 或通过真实服务端互操作**。

## 验收与治理

- 定向执行 Reality 解析单元测试、已有 Reality 回归、VLESS transport contract、Rustfmt 和严格 Clippy；实际执行结果以本批交付及最终 SHA 的 GitHub CI 为准。
- 这是 L2 协议解析修改；必须完成独立 Reviewer 审查、维护者批准和最终 SHA 的 required checks 才能合并。此阶段新 PR 保持 Draft，不改动 `master` 或原 PR #58。
