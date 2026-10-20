# Chimera Client Git 依赖整治记录（2026-10-19）

本次修改仅位于隔离 Worktree / `fix/git-dependency-hardening-20261019`。
起点为本地 `master` 的 `f0f52f458a34c89f588ac04e3a6229337e6d2095`；
原主工作区存在未提交的 `clash-lib/src/proxy/vless/datagram.rs` 修改，
没有将其带入此隔离分支或覆盖它。原 `master` 与 `origin/master`
提交历史分叉（67/67），双方已提交的树相同；本次不解决该历史问题。

## 审计范围与变更

| 依赖 | 原来源 | 当前处理 | 风险与验收 |
| --- | --- | --- | --- |
| `shadowsocks` | Git `c4d8d18527289d12470cad1ce718754c908a75fe`，manifest 1.24，解析为 1.25.0 | 固定 crates.io `=1.25.0`，暂保留原 feature，保持原配置兼容；Cargo.lock 中 crypto 传递依赖同时变化 | 必须复验 TCP/UDP、多用户、加密和插件；非同构来源迁移不能视为零行为变化 |
| `boring-noise` | Git `9ddf1b54d0c9679e7bc50e9151f72d526190db1a` | 放入 `vendor/boring-noise`，保留 BSD-3-Clause 和上游文件头；在封装数据时补 16 字节零填充后再 AEAD 加密。移除与运行时无关的上游 benchmark 及 cdylib/staticlib 产物 | 密码学/协议 L2，需独立审查；传输长度、解密和重协商实际互操作仍需补测 |
| `netstack-lwip` | Git `f434fefd6c227c9dfbec84c364452ba6c1532779`，生产 workspace 的 dev-dependency | 移到单独的 `bench/netstack-lwip` Cargo workspace，正式 `Cargo.lock` 不再包含该 Git 依赖 | 原对比程序会修改 TUN/路由；仅静态迁移，未执行或验证真实 TUN |
| `sock2proc` | Git `9f9e6304d62285115b2e4fa632527ae563bf0fcc` | **尚未替换**。Linux/macOS 系统调用错误仍可能触发 panic，release 为 `panic=abort` | 必须有不会 abort 的跨平台错误路径、原规则匹配兼容和性能证据后再迁移 |

## 验证和当前结论

- `cargo check -p clash-lib --no-default-features --features shadowsocks,aws-lc-rs --locked`：
  通过（迁移后的 crates.io 版本）。
- `cargo check -p watfaq-netstack --offline`：通过（移除 LWIP 后）。
- `cargo check -p clash-lib --no-default-features --features wireguard,aws-lc-rs`：
  通过（本地 WireGuard fork）。
- `cargo check -p clash-rs`：通过；包含默认 CLI 的 Shadowsocks/WireGuard/Reality/TUN/Dashboard feature 组合。
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`：
  通过。为适应当前 Clippy，仅整理 vendored fork 中一段文档注释。
- `cargo test -p clash-lib --lib --all-features --locked`：
  **934 passed / 0 failed / 12 ignored**（macOS arm64，本轮改动代码）。
- `cargo test -p boring-noise --lib`（AWS-LC 默认）和
  `cargo test -p boring-noise --lib --no-default-features --features ring --locked`：
  **各 11 passed / 0 failed**。新增
  `transport_padding_roundtrip_preserves_inner_ipv4_length` 证明
  非 16 对齐的 IPv4 内层数据包经加密、解密后原样回传；单测不是
  真实 WireGuard 服务端互操作测试。
- `cargo check --manifest-path bench/netstack-lwip/Cargo.toml --locked`：
  **PASS**。基准项目独立生成 Cargo.lock（保留 LWIP Git pin），
  没有启动测试程序或修改系统路由。
- Shadowsocks 集成测试初次出现 `Address already in use (os error 48)`。
  使用未迁移的 Git 依赖在原始工作区上重跑
  `integration_test_shadowsocks_udp -- --exact` 也复现了失败，
  因此不得把这项失败直接归因于 registry 迁移；亦不得宣称 UDP 已验证通过。
  为排查而尝试的临时端口分配改动已经从隔离工作区撤销。
- `cargo fmt --all -- --check` 和 `git diff --check`：通过（包含 vendored crate）。

## 为什么暂不强行替换 `sock2proc`

`clash-lib/src/session.rs` 的现有 Linux preflight 与
`catch_unwind` 不能防护 release `panic=abort`。
当前 Git 源码还包含 macOS `sysctl` 和 Linux Netlink 反序列化上的
`unwrap`；替换时必须保证 PROCESS-NAME / PROCESS-PATH 规则行为和
完整路径保留。已审计公开候选 `netstat2 0.11.2`，
它在 Linux `/proc` 读取上仍含 `expect`，并引入 bindgen/native 依赖；
因此不能把更换 crate 名称当作稳定性修复。
下一步应以受审查的跨平台可恢复错误处理实现或许可明确的补丁为目标，
建立目标平台上的失败用例后再移除最后一个生产 Git 依赖。

## 交付门槛

此分支存在 L2 依赖、跨平台协议和密码学变更，未经独立 Reviewer 和
维护者审批，不代表可合并或发布。GitHub `Verified` 与 CI 尚未确认。
未运行：Windows/Linux 编译与实机、Docker 真正协议服务端、
真实 TUN/路由操作、WireGuard 外部互操作及性能基准。
不自动推送、强推、改写 `master` 或自动合并。需要按独立逻辑变更
审查与签名本地提交，之后在适当时机取得远端检查证据。

## 后续专项：`sock2proc` panic=abort 稳定性修复（2026-10-19）

以上“尚未替换”与“未运行 Windows/Linux 编译”的叙述，是首轮提交
`35ba8f5e01f5b1030d2c0b90157efc968b555ee3` 的历史快照。
后续同一隔离分支已继续实施以下修复：

- 将 `sock2proc` 的固定 Git 源 `9f9e6304d62285115b2e4fa632527ae563bf0fcc`
  移至 `vendor/sock2proc`，保留原公开 API 和平台实现；
  `clash-lib` 使用相对路径依赖，因此正式 `Cargo.lock` 中
  **不再存在任何 `git+` 来源**（LWIP 独立 benchmark 仍固定 Git SHA）。
- Linux：Netlink 创建/绑定/连接与接收、畸形报文解析均改为
  `Option` 失败路径。用 `std::fs::read_link` 代替原有将
  非 NUL 终止路径指针传给 `libc::readlink` 的不安全调用；
  跳过竞争期间消失的 procfs 项。添加长度异常 Netlink 报文测试。
- macOS：`sysctl` 失败、未知 PCB 布局、截断列表与无效
  进程路径均恢复为正常失败；保留 `proc_info` 返回 0
  仍可能成功的既有语义，避免识别回归；新增 PCB 合成测试。
- Windows：使用长度验证和未对齐读取解析 IP Helper 表格，
  校验进程路径长度；新增畸形表格检查。
- `clash-lib/src/session.rs` 删除 Linux 的一次性预探测和
  `catch_unwind`：release `panic = "abort"` 下后者无法阻止
  abort；错误由已修复的依赖返回 `None`，进程匹配缺失时
  遵循原有路由行为。删除依赖中未使用的 `rtnetlink`、
  `byteorder`、旧 benchmark 依赖。

**后续实际验证（macOS arm64，Rust 1.99.0）：**

| 命令 | 结果 |
| --- | --- |
| `cargo test -p sock2proc --lib --locked` | PASS：4 passed / 0 failed（含本机 TCP、UDP 活体识别） |
| `cargo check -p sock2proc --target x86_64-pc-windows-gnu --locked` | PASS：仅交叉编译 |
| `cargo check -p sock2proc --target x86_64-unknown-linux-gnu --locked` | PASS：仅交叉编译 |
| `cargo check -p sock2proc --tests --target x86_64-pc-windows-gnu --locked` | PASS：测试代码编译，**未执行** |
| `cargo check -p sock2proc --tests --target x86_64-unknown-linux-gnu --locked` | PASS：测试代码编译，**未执行** |
| `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` | PASS |
| `cargo check -p clash-rs --locked` | PASS |
| `cargo test -p clash-lib --lib --all-features --locked` | PASS：934 passed / 0 failed / 12 ignored |
| `cargo fmt --all -- --check`、`git diff --check` | PASS |

Linux 标准库编译目标于本轮安装以执行交叉编译；
**不等于在 Linux 上运行通过**。无法据此证明 Windows FFI
所有不安全内存访问都已覆盖。macOS/Linux 的故障返回路径经过了
针对性静态与单元检查，但尚无 `panic=abort` 下真实多进程和
跨平台故障注入实验。还需独立 Reviewer、许可证归属复核、
维护者批准、真实 CI、性能/进程归属一致性及外部协议互操作。

原主工作区 `master`、原有未提交 VLESS 改动、子模块和远端分支
均未受本轮专项影响。无 push、无历史重写、无 PR 或合并。
