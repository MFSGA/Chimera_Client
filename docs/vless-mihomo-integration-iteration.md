# VLESS / Mihomo 分阶段集成记录

## 基线与原则

- 集成分支：`integration/vless-mihomo-next`，初始基线为 `master` 的 `229218a073b3275b83080dc2940b407ae9656b14`。
- 历史参考分支：`integration/vless-mihomo-full-v0256`（`b93bf8efc72fe5f9a7beda3b034b391a6313d7a4`）。只读参考，不整体合并其旧代码。
- 保留现有 XHTTP、gRPC、VLESS native 1-RTT、Reality、网络路径恢复和连接池隔离；优先移植实质缺失的能力。
- 每个切片单独测试并仅推送集成分支；PR #58 始终保持 Draft，本任务不修改 `master`、不强推、不合并 PR。完整回归和真实服务端互操作仍是最终验收前提。
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

## 迭代 6：Reality Hybrid 握手接入与 Xray 回环互操作（已提交）

- 基于已推送的 `abc97e6`，把 Hybrid 密钥状态接入 `RealityClientConnection`：只有显式设置 `support-x25519mlkem768` / `supportX25519MLKEM768: true` 才发送 `0x11ec`；默认仍发送经典 X25519。XHTTP Reality 上传和下载端点均传递该开关。
- REALITY 会话认证与 TLS Hybrid key share 共用同一 ephemeral X25519 私钥；ML-KEM 私钥与该 key share 状态绑定。ServerHello 必须与所提供组匹配，否则以无效数据失败，不静默降级。该处理对齐仓库 Mihomo 参考实现 `ref-mihomo/component/tls/reality.go` 中从 handshake key-share 状态导出 REALITY ECDHE key 的路径。
- 新增默认关闭/配置别名测试、模拟 ServerHello Hybrid key-share 与握手 HKDF secret 一致性测试、两种模式下 group mismatch 拒绝测试，以及验证 Hybrid X25519 share 与 REALITY auth 私钥一致的测试。
- **验证（2026-10-10，本地当前树）**：Reality Hybrid 握手定向测试 1/1、group mismatch 定向测试 1/1、Hybrid 密钥模块测试 5/5、`cargo test -p clash-lib --test vless_transport_contract_tests --locked` 3/3 通过；严格命令 `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过。
- `cargo test -p clash-lib --lib --locked reality -- --test-threads=1` 在 `--all-features` 编译配置中 149 项通过、1 项失败：既有 `crypto_handshake::tests::test_connection_has_required_methods` 因同时启用 rustls ring/aws-lc-rs、未安装默认 CryptoProvider 而 panic；Hybrid 新增测试均通过。尝试用 `--no-default-features --features 'reality tls'` 隔离运行时，编译被该 feature 组合中两处网络模块 dead-code deny 阻断，因此该替代组合未能执行。
- 新增 `clash-lib/tests/reality_hybrid_xray_interop.sh`：使用临时生成的 REALITY key，在回环地址启动 Xray VLESS/REALITY 服务端、Chimera 和 echo listener，通过 SOCKS5 发送校验 payload，并检查 Xray 明确报告正在使用 `X25519MLKEM768`。脚本为 Xray freedom outbound 配置只允许 `127.0.0.1` 的 TCP `finalRules`，避免较新服务端默认安全策略拦截回环 echo。运行方式：`XRAY_BIN=/path/to/xray CLASH_BIN=/path/to/clash-rs clash-lib/tests/reality_hybrid_xray_interop.sh`。
- **真实互操作（2026-10-10）**：Xray 26.3.27（macOS arm64）通过；官方发布页当前最新条目为预发布版 Xray 26.9.30，使用同平台官方二进制复测也通过。两版输出 `PASS REALITY X25519MLKEM768 VLESS interop against Xray`，日志确认 `is using X25519MLKEM768 for TLS' communication: true`，VLESS 请求成功转发到本机 echo，响应 payload 完全一致。Xray 测试密钥和临时配置均为本机生成。最初 26.9.30 测试在 TLS Hybrid 握手完成后因服务端默认阻止私网目标而 echo 超时；加入仅限回环测试地址的 freedom `finalRules` 后通过。26.3.27 最初被选中是沿用既有 VLESS interop 脚本默认版本，没有先核查最新发布项；后续已补测较新预发布版。
- 当时 PR #58 仍为 Draft，head `08c9505`；随后真实 Xray 回环互操作脚本以提交 `9203815` 推送，PR head 已更新。该切片的跨平台 CI 按后续迭代记录持续跟踪。
- **尚未验收**：Reality Hybrid 已通过本地真实 Xray 回环互操作，但跨平台 CI 尚未确认；后续仍需复核各平台 CI，并继续推进 VLESS Native Encryption、ECH/ShadowTLS 需求评估及总体回归验收。

## 迭代 7：VLESS Native Encryption xorpub 1-RTT（2026-10-10—11，本地及 Xray 互操作通过）

- **起点**：本地/远端集成分支 `920381555dde3885d491171ddd816432821a6dde`，`master` / `origin/master` 均为 `229218a073b3275b83080dc2940b407ae9656b14`，工作区起始干净，PR #58 仍 Open / Draft。
- **实现**：在现有 `Config::prepare_nfs_relays` 已实现的 AES-CTR 公钥掩码基础上，允许 `mlkem768x25519plus.xorpub.1rtt` 进入 VLESS converter 和 `EncryptionStream`。`xorpub` 只对 ClientHello 的 NFS relay 做可逆掩码，后续 AEAD record 不额外掩码；`random` 需要双向 record header 掩码，继续显式拒绝；`0rtt` ticket 缓存/重放风险处理尚未实现，继续拒绝。经典 `native.1rtt` 不变。
- **测试**：为 `native` 与 `xorpub` 共用 1-RTT duplex 握手和 ping/pong AEAD record 测试；模拟服务端从**实际收到的 ClientHello** 恢复（必要时解掩码）X25519 relay，独立 ECDH 验证 NFS shared secret，而非只复用客户端预计算值。VLESS converter 同时验证两种 1-RTT 模式建构成功、`random`/`0rtt` 仍 fail-closed。
- **互操作脚本**：`clash-lib/tests/vless_native_encryption_xray_interop.sh` 新增 `VLESS_ENCRYPTION_APPEARANCE=native|xorpub`，同一 Xray `vlessenc` 输出为两端生成匹配的 appearance；测试 freedom outbound 仅允许回环 TCP 目标，以兼容新版本服务端的私网默认限制。回环 echo 断言端到端 payload 完全一致。脚本显式设置 `mmdb: null` 并以 `--compatibility false` 启动 CLI，避免 CLI 兼容模式覆盖禁用项并触发无关数据库下载。
- **验证**：`cargo test -p clash-lib --lib --all-features --locked proxy::vless::encryption::tests -- --test-threads=1` 28/28；all-features VLESS converter 101/101；all-features VLESS transport contract 4/4；默认 VLESS converter 89/89、默认 encryption 28/28、默认 transport contract 3/3；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check`、`bash -n clash-lib/tests/vless_native_encryption_xray_interop.sh` 均通过。最初一次错误的测试过滤器只匹配非测试 helper，结果 0/0；随后改用 `encryption_stream_` 过滤器，2/2 真实测试通过。
- **CI（2026-10-11 检查 `9203815`）**：Windows Network Regression、Proxy Throughput Tests、Spelling、Commit Email Check 和 Throughput Release #38115990546 均成功；CI #38115988366 仍在进行中。Rust quality Ubuntu/macOS/Windows 和已完成的主要构建作业通过，但不可宣称整套 CI 已通过。
- **2026-10-11 复验**：从本地 `9203815`、五个未提交文件出发，重新执行 all-features encryption 28/28、VLESS converter 101/101、transport contract 4/4，默认 encryption 28/28、converter 89/89、transport contract 3/3；严格 `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 和互操作脚本 `bash -n` 全部通过。
- **真实 Xray 互操作（2026-10-11）**：Xray 26.9.30 macOS arm64 上 `native.1rtt` 与 `xorpub.1rtt` 均通过；Xray 26.3.27 上 `xorpub.1rtt` 也通过。每次均由真实 Xray `vlessenc` 生成匹配密钥参数，建立 Xray VLESS inbound、Chimera outbound 与本机 echo 回环，并校验完整 payload 往返。第一次尝试因 CLI 默认兼容模式将 `mmdb: null` 恢复为 `Country.mmdb` 并尝试下载而未启动监听器；关闭 CLI 兼容模式后重跑成功。此修正仅作用于互操作 harness。
- **后续**：复核最新提交的 GitHub 跨平台 CI，再分别推进 `random` 双向 record header 掩码、`0rtt` ticket 生命周期/重放边界与 Mihomo 互操作。真实 Xray 通过不代表 Mihomo 或跨平台 CI 已通过。

## 待办路线（按可验证的切片推进）

1. **P1 Reality X25519MLKEM768**：运行时和 Xray 26.3.27 / 26.9.30 回环互操作通过；等待/复核跨平台 CI，并在 Mihomo 当前参考版本上追加互操作覆盖。
2. **P1 VLESS Encryption**：`native.1rtt` 与 `xorpub.1rtt` 本地测试、Xray 26.3.27/26.9.30 回环互操作通过；`random` 的双向 record header 掩码与 `0rtt` ticket/replay 风险分开推进，不替换现有 `native.1rtt` 实现。
3. **P2 ECH / ShadowTLS**：按真实兼容性需求决定是否继续移植；不默认扩张所有理论组合。
4. **独立于 VLESS 的 Netstack 优化**：公平出站队列不混入上述协议提交。
5. **验收**：主要 feature 组合、跨平台构建、旧配置负面校验和真实 Xray/Mihomo E2E。

## 后续迭代记录

每次运行应注明：源/目标 SHA、本轮修改、实际测试结果、CI 状态、阻塞项和下一可交付切片；不得把尚未验证的工作标为完成。完成验收前保留集成分支，不更改 `master`。

## 迭代 8：VLESS Native Encryption UDP（2026-10-11，本地及 Xray 互操作通过）

- **基线**：`5fea5a3cb622e56e43bb6cb1cb055b77fd55fe99`；工作区干净，集成分支与远端一致。参考已有 VLESS UDP length+payload framing 和历史切片 `4fef70b`，按当前代码最小移植。
- **实现**：允许已有 Native Encryption 1-RTT 加密流承载现有 TCP-carried VLESS UDP framing，移除 handler 对加密 UDP 的拒绝；`support_udp()` 恢复以配置的 `udp` 字段为准。未改变 UDP transport 或 packet encoding 行为。
- **回归测试**：新增 handler 能力测试，确保配置 `udp: true` 且选择 `native.1rtt` 时代理公开 UDP 支持。
- **真实 Xray 互操作**：运行 `clash-lib/tests/vless_native_encryption_udp_xray_interop.sh` 对 Xray 26.9.30 macOS arm64；SOCKS5 UDP ASSOCIATE 经 Chimera 加密 VLESS UDP 到 Xray，再转发本机 UDP echo，完整 datagram 往返断言通过。脚本显式禁用 MMDB/CLI compatibility，并仅允许 Xray freedom outbound 访问本机 UDP echo。
- **验证**：`cargo test -p clash-lib --features vless-encryption --lib encrypted_vless_supports_udp -- --nocapture` 1/1；现有 VLESS datagram framing 测试 2/2；`cargo build -p clash-rs --features vless-encryption --locked` 通过；严格命令 `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、脚本 `bash -n`、`git diff --check` 通过。CI 待新提交触发并检查。
- **边界与下一步**：本切片只覆盖 1-RTT Native Encryption 的现有 TCP-carried UDP 数据报；不覆盖 0-RTT UDP、`network: udp` 或 XUDP。后续优先评估能复用现有 UDP packet framing 的低成本兼容缺口，再考虑 random 混淆或 ticket 重放机制。


## 迭代 9：VLESS Native Encryption random 1-RTT（2026-10-11）

- **分支与保护**：以 `d8e3d84e32c293bea2085df2c762e5a6c85c7180` 为集成分支基线；检查时 `origin/master` 为 `cc8549c`，主工作树正检出 master 且有用户 README/图片改动。为保留这些修改，单独创建 `/private/tmp/chimera-vless-integration-20261011` worktree，仅在 `integration/vless-mihomo-next` 分支开发。PR #58 继续保持 Draft，不改动 master。
- **协议实现**：参考 Xray-core `proxy/vless/encryption/xor.go` / `client.go` 的随机外观流程，开放 `mlkem768x25519plus.random.1rtt` 的显式配置。NFS 公钥仍使用既有 xorpub 掩码；1-RTT 握手与服务端 padding 不改变。握手完成后仅以独立 AES-CTR 流掩码双向每条 TLS-shaped 加密 record 的前 5 字节：发送侧使用 `BLAKE3 derive_key("VLESS", united_key)` 与 ClientHello IV，接收侧使用同一 united key 与解密后的服务端 16 字节 ticket。CTR 连续跨记录/16 字节分组计数器边界，正文不掩码，AEAD 仍以解掩码后的原始 record header 为 AAD。
- **回归测试**：将已有 native/xorpub 模拟 Xray 1-RTT 握手和 AEAD ping/pong 验证扩展至 random，三种外观各进行五轮连续往返；模拟服务端从实际收到的 ClientHello 独立恢复 NFS，且用与运行时不同的整流 AES-CTR 掩码生成方式复核双向 header。五条记录覆盖 CTR 16 字节块边界。converter 验证三种 1-RTT 模式可建构，`native.0rtt` / `random.0rtt` 仍 fail-closed。
- **已完成检查**：`cargo test -p clash-lib --lib --all-features --locked proxy::vless::encryption::tests -- --test-threads=1` 29/29；all-features VLESS converter 101/101；all-features VLESS transport contract 4/4；`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check`、`bash -n clash-lib/tests/vless_native_encryption_xray_interop.sh` 均通过，`cargo build -p clash-rs --features vless-encryption --locked` 通过。
- **真实 Xray 互操作**：Xray **26.3.27**（macOS arm64，工作区现有测试二进制），用现有 `vless_native_encryption_xray_interop.sh` 生成随机临时密钥、服务端/客户端配置，在 127.0.0.1 回环 echo 验证 `random.1rtt` 全程加密 ping/pong 成功；同一新建 CLI 上复测 `native.1rtt` 和 `xorpub.1rtt` 均通过。输出分别为 `PASS random/native/xorpub VLESS 1-RTT interop against Xray`。测试仅限回环地址、无外部代理目的地。
- **默认配置回归**：`cargo test -p clash-lib --lib --locked proxy::vless::encryption::tests -- --test-threads=1` 29/29；默认 VLESS converter 89/89；默认 VLESS transport contract 3/3，通过。
- **第二版本真实互操作**：同一 Chimera CLI 在 Xray **26.9.30**（macOS arm64）下执行 `VLESS_ENCRYPTION_APPEARANCE=random`，回环数据往返同样通过，输出 `PASS random VLESS 1-RTT interop against Xray`。两版 Xray 均为工作区已保存的测试程序，无新下载。
- **尚未验收**：需检查新提交触发的跨平台完整 CI、Mihomo 的实际端到端互操作，并扩大异常/压力场景覆盖。0-RTT ticket 生命周期、过期/重放与回退仍未实现，继续明确拒绝，不扩大到 ECH/ShadowTLS 或其它未经测试组合。

## 迭代 10：VLESS AEAD nonce 耗尽安全边界（2026-10-11）

- **基线与工作目录**：从已推送的 `df88dc509121db61f7114a9446d0b52f1a2b4ca7` 开始，直接使用 `/Users/adam/src/Chimera_Client` 上的 `integration/vless-mihomo-next`；保留且不暂存原有 `README.md`、`README_en.md` 与 `README_logo.png` 用户改动，不使用独立 worktree。
- **问题与修复**：现有 `EncryptionAead::next_nonce` 将 96 位 AES-GCM nonce 视作大端计数器，遇到全 `0xff` 时使用 `wrapping_add` 回绕为全零；可能导致相同流量密钥下重复 nonce。改为先在副本上递增，仅在进位成功结束后更新状态；全部字节溢出时返回 `InvalidInput` 错误 `VLESS AEAD nonce exhausted`，且保留原计数器，让后续所有调用持续拒绝。既有 nonce 派生与正常记录格式不变。
- **回归验证**：新增测试将客户端与模拟服务端 nonce 设置为 `ff:..:fe`，双方可使用最后一个合法 `ff:..:ff` 完成加解密；此后重复执行 `seal` 与 `open` 均必须报错且 nonce 保持全 `ff`。新测试默认 1/1、all-features 1/1，VLESS Encryption all-features 全组 30/30 均通过。
- **功能边界**：这是现有 1-RTT 加密通道的 nonce 唯一性安全修复，**不等同于** 0-RTT ticket 缓存、过期/单次使用、抗重放或失败回退；`0rtt` 配置仍 fail-closed。后续继续跟踪 CI 和真实 Mihomo 互操作，再推进完整 0-RTT 状态机。
