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

## 迭代 2：Reality 混合密钥交换的 ServerHello KeyShare 解析基础

### 范围与行为

- 源分支 `integration/vless-mihomo-full-v0256` 的 Reality 混合密钥交换代码不能直接替换主线握手；先提取 `0x11ec`（X25519MLKEM768）ServerHello key share 的长度校验和结构化解析。
- 保留现有普通 X25519（`0x001d`）握手行为。当前实际 TLS secret derivation **仍然只支持 X25519**：即使能解析 hybrid ServerHello，现有 `extract_server_public_key` 也必须明确拒绝 hybrid，不能把其中的 32 字节 X25519 分量误当完整共享密钥。
- 对 X25519（32 字节）、X25519MLKEM768（1088 字节密文 + 32 字节公钥）、未知 group、长度错误、截断和多余数据新增解析测试。
- 后续切片再移植 ClientHello hybrid key share、ML-KEM 封装/解封装、TLS 1.3 共享密钥派生和 Reality 真实 Xray 互操作；**本切片不表示 hybrid runtime 已可用**。

### CI 观察（2026-10-10）

- PR #58 的首轮提交 `a66b6a6`：Windows 网络回归、Proxy Throughput Tests、Spelling、Commit Email Check 通过；完整 CI 检查期间 `i686-unknown-linux-musl` 的 `shadowsocks_multiuser_tests::ss2022_tcp_attributes_traffic_to_authenticated_user` 失败，报 `UnexpectedEof`。该用例属于 Shadowsocks 2022，与本轮 Reality 解析修改无直接代码关联；尚未证明是偶发问题，需复跑确认。
- 其余 CI 和真实 Xray 互操作状态以 GitHub Actions 最终结果为准，不将进行中的任务写作通过。

### 验证

- `cargo test -p clash-lib --lib --all-features --locked reality_util::tests -- --test-threads=1`：5/5 通过（含 2 个新增用例）。
- `cargo test -p clash-lib --lib --locked reality -- --test-threads=1`：136/136 通过。
- `cargo test -p clash-lib --test vless_transport_contract_tests --locked`：3/3 通过。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`：通过。
- `cargo test -p clash-lib --lib --all-features --locked reality -- --test-threads=1`：136 通过、1 失败。失败项 `crypto_handshake::tests::test_connection_has_required_methods` 因 rustls 同时启用 ring / aws-lc-rs 后未显式安装默认 CryptoProvider 而 panic；在**未修改 master** 的隔离 worktree 上用同一 `--all-features` 组合单独执行该用例，也得到完全相同的失败。此问题为既有测试/feature 组合缺陷，不将其计为本轮引入，也不通过放宽 lint 掩盖。
- 真实 Xray hybrid 互操作：尚未运行；需要后续完整握手切片。

## 迭代 3：Reality Hybrid ClientHello KeyShare 构造基础

### 范围与行为

- 继续沿用 `master` 的 Reality ClientHello 结构，在不启用 Hybrid runtime 的前提下新增可指定密钥交换组的 ClientHello 构造器。
- 仅接受 `X25519 (0x001d)` 的 32 字节 key share，或 `X25519MLKEM768 (0x11ec)` 的 1216 字节 key share（1184 字节 ML-KEM 公钥 + 32 字节 X25519 公钥）。未知组或长度错误在序列化之前直接返回 `InvalidInput`，不生成不完整握手。
- `supported_groups` 与 `key_share` 必须使用同一个协商组；测试断言两处字段、长度和 TLS handshake 长度一致。
- 既有 `construct_client_hello` 调用保持原样，委托新构造器生成 X25519 格式；默认 Reality 客户端仍仅使用经典 X25519，不会错误协商未实现的 Hybrid TLS secret。
- 本切片**不包含** ML-KEM 私钥生成/封装、混合共享密钥派生、配置开关或 Xray 互操作；这些仍是后续待办，不能将此切片标为完整 Hybrid 支持。

### 验证（2026-10-10）

- `cargo test -p clash-lib --lib --all-features --locked reality_tls13_messages::tests -- --test-threads=1`：8/8 通过，含 3 项新增回归测试。
- `cargo test -p clash-lib --lib --locked reality -- --test-threads=1`：139/139 通过。
- `cargo test -p clash-lib --test vless_transport_contract_tests --locked`：3/3 通过。
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- CI：前一提交 `53b811f` 的 GitHub CI 截至检查时仍在运行；Windows 网络回归、吞吐测试、拼写及提交邮箱检查通过，尚未宣称全绿。

## 迭代 4：Reality Hybrid TLS 1.3 共享密钥输入

- 在不改变现有 X25519 默认握手的前提下，TLS 1.3 `derive_handshake_keys` 接受 32 字节 X25519 密钥或 64 字节混合密钥（ML-KEM-768 32 字节在前，X25519 32 字节在后），其余长度一律拒绝。
- 不截断或预先哈希混合共享密钥，交由现有 TLS 1.3 HKDF-Extract 消费完整输入。
- 增加 SHA-256 与 SHA-384 回归覆盖：验证混合密钥与单纯 X25519 的结果不同、顺序不能互换、结果可重复、无效长度拒绝。
- 本轮仍未启用 Reality Hybrid 运行时；ML-KEM 客户端密钥生成、解封装、完整握手与真实 Xray 互操作仍待实现。
- 恢复工作区后复验：TLS keys 9/9、Reality 默认 140/140、VLESS transport contract 3/3、严格 Clippy、fmt 全通过；已提交为 `ac1486c` 并与此前 `046ffdd` 一同正常推送到 `integration/vless-mihomo-next`。该远程提交的完整 CI 仍需等待最终结果。

## 迭代 5：Reality X25519MLKEM768 客户端密钥材料与解封装（未启用运行时）

- 使用仓库现有 `aws-lc-rs`（不新增依赖）生成每连接 ML-KEM-768 解封装密钥与 X25519 私钥；按 TLS 组 `0x11ec` 的规范构造 ClientHello 公钥部分：ML-KEM 1184 字节在前，X25519 32 字节在后。
- 从解析后的 ServerHello hybrid key share 取 1088 字节 ML-KEM ciphertext 与 32 字节 X25519 服务端公钥，分别解封装与 ECDH，再按 ML-KEM|X25519 拼接 64 字节 HKDF 输入。严格拒绝不匹配的组、长度或协商失败；密钥不写日志。
- 4 项新增回归测试覆盖独立模拟服务端 KEM 封装/X25519 协商所得共享密钥一致、SHA-256/SHA-384 TLS 派生、错误 group/长度、无效 X25519 对端公钥及新鲜密钥。
- 关键边界：新增 `reality_hybrid.rs` 目前为独立组件，默认 Reality 握手仍只使用普通 X25519。**这不是实际 Hybrid ClientHello/ServerHello 联机握手**；下一切片需将所提供 key share、与之绑定的私钥状态及协商校验接入 `RealityClientConnection`，完成真实 Xray 互操作后才可宣称 Hybrid 功能就绪。
- **本地验证（2026-10-10）**：`cargo test -p clash-lib --lib --locked reality_hybrid::tests -- --test-threads=1` 4/4；`cargo test -p clash-lib --lib --locked reality -- --test-threads=1` 144/144；`cargo test -p clash-lib --test vless_transport_contract_tests --locked` 3/3；`cargo test -p clash-lib --lib --all-features --locked reality_hybrid::tests -- --test-threads=1` 4/4；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。本地测试不能代替真实服务端互操作或跨平台 CI。

## 迭代 6：Reality Hybrid 握手接入（本地未提交）

- 基于已推送的 `abc97e6`，把 Hybrid 密钥状态接入 `RealityClientConnection`：只有显式设置 `support-x25519mlkem768` / `supportX25519MLKEM768: true` 才发送 `0x11ec`；默认仍发送经典 X25519。XHTTP Reality 上传和下载端点均传递该开关。
- REALITY 会话认证与 TLS Hybrid key share 共用同一 ephemeral X25519 私钥；ML-KEM 私钥与该 key share 状态绑定。ServerHello 必须与所提供组匹配，否则以无效数据失败，不静默降级。该处理对齐仓库 Mihomo 参考实现 `ref-mihomo/component/tls/reality.go` 中从 handshake key-share 状态导出 REALITY ECDHE key 的路径。
- 新增默认关闭/配置别名测试、模拟 ServerHello Hybrid key-share 与握手 HKDF secret 一致性测试、两种模式下 group mismatch 拒绝测试，以及验证 Hybrid X25519 share 与 REALITY auth 私钥一致的测试。
- **验证（2026-10-10，本地当前树）**：Reality Hybrid 握手定向测试 1/1、group mismatch 定向测试 1/1、Hybrid 密钥模块测试 5/5、`cargo test -p clash-lib --test vless_transport_contract_tests --locked` 3/3 通过；严格命令 `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过。
- `cargo test -p clash-lib --lib --locked reality -- --test-threads=1` 在 `--all-features` 编译配置中 149 项通过、1 项失败：既有 `crypto_handshake::tests::test_connection_has_required_methods` 因同时启用 rustls ring/aws-lc-rs、未安装默认 CryptoProvider 而 panic；Hybrid 新增测试均通过。尝试用 `--no-default-features --features 'reality tls'` 隔离运行时，编译被该 feature 组合中两处网络模块 dead-code deny 阻断，因此该替代组合未能执行。
- PR #58 检查时仍为 Draft，head `abc97e6`；GitHub workflow runs 查询没有返回与该 SHA 关联的 PR workflow。本地改动尚未提交或推送。
- **尚未验收**：当前测试只在本地模拟服务端 KEM/X25519 行为，未证明真实 Xray 互操作；本机没有 Xray 可执行文件或 Docker，无法运行现有 Xray interop harness，跨平台 CI 也未运行。下一步新增 Reality Hybrid Xray E2E 覆盖并运行，随后检查远端 CI；未完成这些验证前，不将 Reality Hybrid 标为验收完成。

## 待办路线（按可验证的切片推进）

1. **P1 Reality X25519MLKEM768**：完成运行时接入审查，更新并运行真实 Xray 互操作脚本；再覆盖跨平台 CI。
2. **P1 VLESS Encryption**：分开评审 0-RTT ticket/replay 风险及 `xorpub`/`random` 外观模式，不替换现有 1-RTT 实现。
3. **P2 ECH / ShadowTLS**：按真实兼容性需求决定是否继续移植；不默认扩张所有理论组合。
4. **独立于 VLESS 的 Netstack 优化**：公平出站队列不混入上述协议提交。
5. **验收**：主要 feature 组合、跨平台构建、旧配置负面校验和真实 Xray/Mihomo E2E。

## 后续迭代记录

每次运行应注明：源/目标 SHA、本轮修改、实际测试结果、CI 状态、阻塞项和下一可交付切片；不得把尚未验证的工作标为完成。完成验收前保留集成分支，不更改 `master`。
