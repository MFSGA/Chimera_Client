# Chimera Client dependency change review and follow-up validation

Date: 2026-10-20 (America/Los_Angeles).
Branch: `fix/git-dependency-hardening-20261019`.
Initial commits reviewed: `35ba8f5e01f5b1030d2c0b90157efc968b555ee3`,
`d666e2a95365f6fda704bbdf65bb007897ba8b37`.

**Scope:** a developer-side review and regression hardening pass. It is
**not** the independent review required by project governance. No Git push,
PR, remote CI execution, history rewriting or host TUN/route manipulation.

## Findings from this review

### 1. WireGuard framing: MTU-bound padding (fixed locally)

Original change correctly zero-padded encrypted inner packets to the nearest
16-byte boundary (WireGuard whitepaper §5.4.6,
https://www.wireguard.com/papers/wireguard.pdf). However, it did not cap
padding by the configured inner MTU, so a packet already near the tunnel's
MTU could grow beyond it. The original `Tunn::encapsulate` also relied on
an internal panic for short destination buffers. Both issues matter to
Chimera's `panic = "abort"` release configuration.

Review fix: a dedicated `transport_plaintext_len` helper supports
`set_padding_mtu` on the local Noise tunnel; Chimera passes the same configured
MTU (default 1420) to the encryption layer and smoltcp virtual IP device.
Valid padding is added whenever the aligned length fits; when it does not,
the original inner length is retained rather than increasing the datagram.
Established-session encryption fails with
`WireGuardError::DestinationBufferTooSmall` before calling the lower-level
formatting helper if a destination buffer cannot hold the message. Receive,
replay and AEAD logic were not changed.

Unit regressions: exact padding round-trip, no-growth-at-MTU round-trip,
buffer-too-small error without panic; both AWS-LC and ring configurations.

Residual risk: configured tunnel inner MTU does not prove the real path MTU
of arbitrary chained UDP proxy paths. A real peer/interoperability and
fragmentation test is still required. Also, the library's other
pre-existing internal short-buffer panics were not comprehensively audited.

### 2. Linux process attribution: dump response misidentification (fixed locally)

The original `sock2proc` asked SOCK_DIAG for an `NLM_F_DUMP` and assumed the
**first** `InetResponse` was the target socket. Per Linux sock_diag(7)
(https://man7.org/linux/man-pages/man7/sock_diag.7.html), socket-list
queries primarily filter by state; they cannot be assumed to return only
the provided socket ID.

Review fix: explicitly match source/destination IP addresses and ports in
the returned SocketId (with a constrained wildcard-bind allowance on the
local side) before resolving uid/inode. Iterate Netlink multi-message
datagrams using 4-byte-aligned offsets. Unit tests cover mismatches,
wildcard local bind, truncated input and alignment overflow.

Residual risk: compile-only Linux validation does not prove correct live
kernel behavior, latency, cancellation under pathological socket lists,
or process attribution through NAT/TUN configurations. Failing closed may
cause some prior fuzzy matches to return no process rather than an
incorrect process. This needs Linux namespace / live TCP and UDP tests.

### 3. Windows native-table parsing (reviewed, execution still blocked)

The vendored IP Helper table parser uses `offset_of!` and validated sizes
before `read_unaligned` rows, consistent with Microsoft's warning that
padding can occur in `MIB_TCPTABLE_OWNER_PID`:
https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid

Windows cross-target compilation is not Windows execution. Requires an
independent FFI/unsafe audit and Windows live process attribution tests.
The older `MAX_PATH = 260` limitation is still present.

### 4. Shadowsocks and LWIP

`shadowsocks = =1.25.0` from crates.io resolves a newer crypto dependency
graph than the prior Git source at the same package version; passing a
local pair test is not independent implementation interoperability.

Original Shadowsocks UDP integration failures were reproduced on the
pre-migration Git-source baseline with local port-collision errors;
the migration's UDP behavior is not proven by those failures.
The isolated lwIP comparison compiles but still needs its own privileged,
non-production benchmark host.

## Evidence and acceptance checklist

- [x] macOS arm64: `cargo test -p sock2proc --lib --locked`:
  4/4 passed in prior hardening pass (live loopback TCP/UDP lookup).
- [x] macOS arm64: WireGuard local AWS-LC and ring test configurations:
  13 passed, 0 failed each, including new MTU and buffer tests.
- [x] macOS arm64: `cargo check -p clash-rs --locked` — PASS.
- [x] macOS arm64: `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` — PASS.
- [x] macOS arm64: `cargo test -p clash-lib --lib --all-features --locked` — 934 passed, 0 failed, 12 ignored.
- [x] macOS arm64: `cargo test -p clash-lib --no-default-features --features shadowsocks,aws-lc-rs --test shadowsocks_integration_tests integration_test_shadowsocks_tcp --locked -- --exact --test-threads=1` — 1 passed, 0 failed; local same-implementation loopback only.
- [x] Linux x86_64: `cargo check -p sock2proc --tests --target x86_64-unknown-linux-gnu --locked`
  (compile only).
- [x] Windows x86_64: prior `sock2proc` compile/test-target checks
  (compile only; Linux/Windows binaries have not been executed).
- [ ] Linux x86_64 live socket-diag and process match/denied Netlink test.
- [ ] Windows live TCP/UDP process lookup and FFI review.
- [ ] WireGuard external peer interoperability, rekey/keepalive, fragmentation
  and configured MTU tests under real transport.
- [ ] Shadowsocks independent server TCP/UDP multi-user interoperability,
  legacy cipher policy review and crypto compatibility confirmation.
- [ ] Independent reviewer + maintainer approval for L2 changes.
- [ ] Remote GitHub CI and Verified status.

## 2026-10-20 本地 CI 预检和独立 Reviewer 交接

本节是对**最新代码提交 `911097fa94f2258865408210de3140a8029e574a`**
的只读 CI 预检记录；本节只增加审查文档，未修改源代码、CI YAML、远端分支或任何审批设置。
文档提交后应以该任务分支最新 HEAD 为最终 PR 审查 SHA。

### Git 与远端状态

- 分支：`fix/git-dependency-hardening-20261019`，工作区干净。
- 共同基线：`f0f52f458a34c89f588ac04e3a6229337e6d2095`。
- 当前任务三个独立逻辑提交：
  `35ba8f5e01f5b1030d2c0b90157efc968b555ee3`、
  `d666e2a95365f6fda704bbdf65bb007897ba8b37`、
  `911097fa94f2258865408210de3140a8029e574a`。
- 本地 `master`：`f0f52f4`；本地 `origin/master`：
  `aa39d1d3`，历史相差 67/67，但上一轮确认提交树相同。
  未同步，也未重写两者的提交历史。
- `ref` gitlink：`39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`；
  `ref-mihomo`：`63bd52ec794b7051569b76ede2f6cdbf4c091fda`；
  `ref-meow`：`3bf59376708809386c20b648c4d709148a077a79`。
- 三个本地提交均已在先前交付中核对 GPG 签名；本轮复验
  `git verify-commit HEAD` 返回 0，本机 `%G? = U`
  （签名密码学有效、密钥信任未认证）。
- GitHub 只读查询 `MFSGA/Chimera_Client` 未发现该任务分支；
  读取 `911097f` 返回 `No commit found`。因此
  **没有针对当前 SHA 的远端 Actions 结果、Verified 判断或 PR Reviewer**。
- 主 `Cargo.lock` 中 `git+` 来源为 0；
  隔离 `bench/netstack-lwip/Cargo.lock` 仍固定其测试专用 Git SHA。
  无推送、PR、merge、tag 或 release。

### 在 macOS arm64 上执行的检查

| 检查命令 | 本机实际结果 | 解释 |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | Rust 格式 |
| `cargo test -p clash-lib --test lan_proxy_tests --all-features --locked -- --test-threads=1` | PASS：3/3 | 对应 `ci.yml` 的 LAN Proxy 检查 |
| `cargo test -p clash-lib --test direct_udp_integration_tests --locked -- --test-threads=1` | PASS：3/3 | Loopback DIRECT UDP；不是物理 NIC 切换 |
| `cargo check -p sock2proc --tests --target x86_64-unknown-linux-gnu --locked` | PASS：仅编译 | 不能代替 Linux 运行 |
| `cargo check -p sock2proc --tests --target x86_64-pc-windows-gnu --locked` | PASS：仅编译 | 不能代替 Windows 运行 |
| `cargo check -p boring-noise --tests --target x86_64-unknown-linux-gnu --locked` | 环境阻塞，exit 101 | AWS-LC 构建缺失 `x86_64-linux-gnu-gcc` |
| `cargo check -p boring-noise --tests --target x86_64-pc-windows-gnu --locked` | 环境阻塞，exit 101 | AWS-LC 构建缺失 `x86_64-w64-mingw32-gcc` |

因平台 C 交叉编译器缺失，**不能**把两项 `boring-noise`
标记为代码 FAIL，也不能标记为通过。保留日志：
`/tmp/chimera-boring-noise-x86_64-unknown-linux-gnu.log`、
`/tmp/chimera-boring-noise-x86_64-pc-windows-gnu.log`；
本地临时日志不随 Git 分发。

上文记录的 macOS 核心库 934/0/12、WireGuard 双加密后端
13/0、Shadowsocks TCP 1/0 等测试来自此前同一最终代码版本。
没有 Linux/Windows 实机权限测试或真实 TUN 操作。
当时本机磁盘剩余空间约 12 GiB，建议把剩余较大矩阵放在
GitHub 平台 runner 完成，避免挤占开发机空间。

### 独立审查需求及门禁

正式独立 Reviewer 应基于 `f0f52f4..911097f` 的**完整代码 diff**，
以及本次交接文档提交，针对 PR 最终 HEAD 自行审查，而不是采用编码 Agent 的判断作为审批结论。
最高风险为 **L2：密码学、WireGuard、跨平台 socket/进程归属**。

- **BLOCKER（验证门禁）**：没有该 SHA 的 GitHub Checks /
  GitHub Verified / 独立 Reviewer / 维护者批准证据。
  不能执行合并和 release。
- **HIGH（待行为验证）**：Linux Netlink 多响应源/目的 socket
  选择（`vendor/sock2proc/src/platform/linux.rs`）、Windows
  native-table unsafe FFI 和 PID 路径（`platform/windows.rs`）；
  需要 Linux/Windows 平台运行并注入失败路径。
- **HIGH（协议互操作）**：WireGuard 加密填充和 MTU 上限
  （`vendor/boring-noise/src/noise/{mod,session}.rs` 及
  `clash-lib/src/proxy/wg`）尚无真实服务端/路径 MTU 证据。
- **MEDIUM（兼容与维护）**：Shadowsocks Registry 1.25.0
  传递 crypto 依赖变化、UDP 测试原始端口冲突以及旧流加密策略。
- **MEDIUM（CI 漏覆盖）**：
  `.github/workflows/windows-network-regression.yml` 的按路径触发
  当前未包括 `vendor/**`；这批提交同时改变 `Cargo.lock`、
  `clash-lib`，因此若将来正常提出 PR 会触发，但未来只有
  `vendor/` 修改时可能跳过专用 Windows 网络回归。
  修改 CI 本身属于 L3，须独立审核，未在本轮修改。
- **LICENSE（待审）**：核对 upstream `sock2proc` 快照没有独立
  LICENSE 的情况下各源文件的授权/归属（尤其 macOS 文件），
  以及 `boring-noise` 的 BSD-3-Clause 版权和许可证义务。

需要在允许远端操作后，由维护者先核对 GitHub `master` 实时 SHA、
分支保护和 PR 目标，再授权**推送独立任务分支、创建 Draft PR**
让仓库实际工作流运行；绝不为测试直接推送 `master`
（`ci.yml` 的主分支构建可能运行 `latest` 发布逻辑）。
在 PR 确认每个 SHA 的 GitHub Verified、所有 required checks、
独立 Reviewer 结论和 L2 审批后才可讨论合入。

**审查状态：`NOT_REVIEWED_INDEPENDENTLY`。**
这份开发侧报告仅提供可复验的事实与风险，不代表
`APPROVE_WITH_EVIDENCE` 或 Owner waiver。
