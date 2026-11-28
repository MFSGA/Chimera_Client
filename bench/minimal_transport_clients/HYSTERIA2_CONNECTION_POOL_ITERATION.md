# Hysteria 2 可配置 QUIC 连接池迭代

## 目标与基线

在生产 Hysteria 2 outbound 中支持可配置的 QUIC 连接数，复用精简 HY2 core 的共享 Endpoint/UDP socket 路径，并以同一请求负载验证正确性、吞吐、资源占用及网络重置行为。配置缺省时必须维持一条连接，避免改变现有节点行为。

本轮开始时，Client 位于 `隔离候选分支`，HEAD 为 `[源码快照已省略]`；候选源码快照包含本地修改。`master` 与本地 `origin/master` 都为 `[源码快照已省略]`。不切换分支、不重置或暂存既有改动。

Server 使用 `隔离候选分支`，HEAD 与本地 `origin/master` 同为 `[源码快照已省略]`；候选源码快照包含本地修改。Server 仅提供互通和性能测量端点，不在本迭代修改。

前一轮本机回环基线：同一共享 Endpoint 下，8 路 TCP 并发时，Chimera Server 的 1/4/8 条 QUIC 连接分别为 4.682/5.273、12.651/9.872、11.813/9.556 Gbit/s；官方 Hysteria 2.14.0 Server 分别为 3.471/6.370、8.253/8.320、9.377/8.624 Gbit/s。每个配置 20 个样本。由此只验证了 benchmark core 中连接分片的收益，尚未验证生产 Handler 的连接池实现。

`ref/`、`ref-mihomo/`、`ref-meow/` 在本 worktree 中没有可用的检出内容；本迭代不复制上游代码，因此不以它们推断行为或接口。

## 范围与非目标

- 配置字段为 `quic-connections`，允许 1–8，缺省为 1；0 和大于 8 的值必须明确报配置错误。
- 一个配置值对应同一 Endpoint 和受 connector 选择的 UDP socket 上的多条独立、完成认证的 QUIC 连接。建立池失败时关闭已建立的部分连接，不发布不完整池。
- 新建 TCP 流在池内轮询连接；每个 UDP session 固定使用所选连接及其 UDP session map。
- 检查所有池成员的网络路径上下文。网络变化或任一 QUIC 连接失效时，整池退休并在新路径重新建立；reset 返回实际退休的连接数。
- 保持缺省 1 条连接时的认证、拥塞控制、UDP、端口跳跃、Salamander、网络重置和连接复用语义。
- 不在本迭代启用 Brutal、自动调整连接数、改变缺省连接数、修改 Server、改 Quinn/GSO/GRO 或调整其他传输协议。

## 代码调用链

`OutboundHysteria2` YAML 反序列化 → `converters::hysteria2::Handler::try_from` → `HystOption` → `Handler` 的认证连接池 → `connect_stream` / `connect_datagram`。本轮之前 Handler 使用 `Mutex<Option<Arc<HysteriaConnection>>>`；抽出的 `HysteriaClient::new_endpoint` 和 `connect_on_endpoint` 提供共享 Endpoint 的 core API。

## 验收标准

1. 配置转换测试覆盖缺省、1、4、8、0、9；兼容旧 YAML。
2. Handler 的连接池只在所有连接认证成功且所有网络路径检查通过后发布。建立中途失败、取消、网络变化、连接失效和 reset 都不会泄漏 QUIC/H3 驱动任务、UDP session 或旧路径连接。
3. 增加可以在本机运行的生产 Handler 验证：Chimera Server 与官方 Hysteria 2.14.0 Server 都完成全内容 TCP smoke；有条件时覆盖 UDP 与网络重置。
4. 生产 Handler 与精简 protocol-core 客户端使用相同的本地 TLS payload target、c8 负载、CPU 亲和性和 BBR 配置，比较连接数 1/4/8。至少两组反向顺序，每个组合至少 10 个正式样本；记录吞吐 CV、客户端/服务端 CPU、CPU/GiB、RSS/HWM。默认 1 条连接的结果须与上一轮基线在测量波动范围内。
5. 运行目标 Rust 单测、格式和相关 feature 编译；L2 改动由独立 Reviewer 检查最终 diff。真实网络/丢包及 Brutal 不在本轮验收中，单独记录为待验证项。

## 当前状态

实现和本机回环验证完成，第一轮 L2 审查发现的两个清理阻断已修复；独立 Reviewer 针对最终 diff 复审为 **PASS**。主要结果和完整吞吐表见 [HY2 交叉与连接数测试记录](RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md)。

- 已加入 `quic-connections`，允许 1–8，缺省仍为 1；拒绝 0 和大于 8。旧 YAML 可省略该字段。
- Handler 在一个 Endpoint 和 connector 选定的 UDP socket 上建立所有 QUIC/H3 会话，全部认证和路径检查成功后才发布完整池；TCP 新流和 UDP session 通过原子轮询选择连接。任一成员失效或网络路径改变时整池退休；reset 返回并清理实际退休数量。
- 配置/默认值/轮询/路径测试 20 项通过；`cargo check -p clash-lib --features hysteria,transport-bench-api` 与最小 `--no-default-features --features hysteria,ring` 编译通过。核心 crate 测试 12 项通过，其中用本地 QUIC/H3 服务端分别复现“第二条连接认证等待时取消”和“第二条连接返回 403”；两种情况下都确认第一条已认证连接和第二条处理中连接关闭，pending H3 driver 被 abort。
- 更新后的 q4 Docker reset E2E 先向 echo 端发送 40 个 UDP 包，确认生产容量为 32 的接收队列填满，再要求 reset 在 2 秒内返回；验证四条 QUIC 会话都关闭、旧 session map 清空、旧 UDP stream 排空并结束，且新池重新认证成功。单独的满队列单测也验证等待投递时 map 锁可取得，并在连接关闭信号到达后退出。
- 按当前 feature 配置重建了独立 protocol-client：HY2 + AWS-LC release 二进制为 3,231,552 bytes；REALITY/VLESS 不带 Vision 为 1,987,504 bytes，启用 Vision 为 2,023,072 bytes。`cargo tree` 的 host-target normal-dependency 唯一 package/version 节点数分别为 HY2 62、REALITY/Vision 57；两个独立客户端均不依赖 `clash-lib`、DNS、netstack、Hyper 或 Hickory。Vision 的两种构建和 HY2 产品加密后端构建均通过。
- 生产 Handler 连接池在 Chimera Server 与官方 Hysteria 2.14.0 Server 上通过 1/4/8 连接共六组 1 MiB 双向全内容校验 smoke。吞吐矩阵使用 8 个并发 TCP 流、每流 128 MiB 上下行、3 次预热、10 次正式样本；每个服务端/连接数做两组反向顺序，client/server CPU 分开采样。
- 修复取消清理和 UDP 满队列锁等待后，重新构建的 Handler 二进制（4,268,016 bytes，BLAKE3 `22fc65f0e606d26a9909c1a3e66bf06ee71c995348b6ae75949a4cd52f1c0d7c`）再次通过六组 q1/q4/q8 双向全内容 smoke。本文吞吐表来自此前二进制（BLAKE3 `8c437794c2f5e7791cd89df4d331ba6756dd93d64dca82fef0e906fd0c531b9a`）；修复涉及取消清理和 UDP 接收路径，没有为新二进制重跑大流量矩阵，因此不要将旧矩阵当作新二进制的精确吞吐测量。
- 吞吐矩阵在 Linux `CPU 0–7` 亲和性下运行，两个监控矩阵均 12/12 完成，所有单格 CV 低于 12%。生产 Handler 对 Chimera Server 的 q1/q4/q8 吞吐为 4.484/5.308、11.956/9.995、11.974/9.381 Gbit/s；对官方服务端为 3.509/6.148、8.369/8.223、9.252/8.509 Gbit/s。完整 CV、CPU/GiB 和 RSS/HWM 表见结果记录。未固定 CPU 亲和性的早期尝试不计入结果。
- 2026-11-27 又对当前 feature-minimal 生产 Handler 二进制完成了固定核 bulk 复测，关闭了上条记录留下的新版吞吐缺口。Client 用 `bench/minimal_transport_clients/hy2_core_client` 的 `--locked --no-default-features --features hy2-core` 构建（5,298,872 bytes，BLAKE3 `fd2b60d28555103a36814aee4f2b78ac07a9ec891db0c97dfa1c4636142a6678`）；此入口直接构造生产 `Handler`，不启动完整客户端 runtime，也不发起 DNS 解析。Server 使用 feature-minimal production server（16,316,408 bytes，BLAKE3 `80eb242bee533b533524f5b6c46a7617ad0c1137df19784154e234a006c5ed4a`）。两套 CPU 监控矩阵都由 `taskset -c 0-7` 启动，确认 runner、client、server、target、generator 都继承 0–7 核；每格 16 次预热、10 次正式测量，两个监控矩阵均 12/12 通过 12% CV 门槛，q1/q4/q8 对两个服务端的 1 MiB 全内容 smoke 为 6/6 通过。最新数值表见 [交叉与连接数结果](RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md) 的 “Post-review production Handler pinned bulk rerun”。之前未 pin 的 16 预热诊断数据已明确排除。
- 最新固定核结果中，Chimera Server 的 q1/q4/q8 为 4.688/5.285、12.280/9.467、12.352/9.337 Gbit/s；官方 Hysteria 2.14.0 Server 为 3.539/6.338、8.375/8.292、9.199/8.392 Gbit/s。Chimera Server 上 q4 与 q8 上行仅差 0.6%，但 q8 下行低 1.4%，q4 是更均衡的本机配置；官方 Server 上 q8 比 q4 上行高 9.8%、下行高 1.2%。结果依赖服务端实现，缺省仍为 q1；WAN 和公平性数据出来前不建议改默认值。
- 和此前同机同负载的精简 protocol-core 对照相比，生产 Handler 的各方向差异约为 -5.5% 至 +1.8%；目前没有证据表明生产 Handler 适配层造成稳定的大幅吞吐损失。q4 是 Chimera Server 上较均衡的本机回环配置；q8 在该服务端没有继续提高吞吐。配置缺省仍为 1，不能从回环结果推断 WAN 下最佳值。
- 本轮仍是同机回环和 BBR；不代表 WAN、丢包、Brutal、UDP 实时流量或与竞争流共存的结果。默认连接数维持 1；是否在真实 VPS/网络上采用 4 或 8，要等远端复核。
- 故障注入覆盖了第二条连接的认证拒绝、认证等待期间的取消，以及满队列时的 q4 reset。其他网络组合（例如端口跳跃与 obfs 联用）仍未纳入本轮验证。
- 独立 Reviewer 最终结论为 PASS。非阻断后续覆盖项：单个池成员独立掉线后的即时 sibling 退役、reset future 超时后的重试、q>1 与 port hopping/obfs/链式 connector 组合。Reviewer 确认这些不是当前阻断；q1 默认保持不变。
- 本轮执行的相关命令：

  ```sh
  cargo fmt --all -- --check
  cargo test -p chimera-hysteria2-core --features aws-lc-rs
  cargo test -p clash-lib --lib hysteria --features hysteria
  cargo test -p clash-lib --lib blocked_udp_delivery_releases_map_and_stops_after_connection_close --features hysteria
  cargo check -p clash-lib --features hysteria,transport-bench-api
  cargo check -p clash-lib --no-default-features --features hysteria,ring
  RUSTFLAGS='--cfg tokio_unstable --cfg docker_test --cfg throughput_test' RUSTC_BOOTSTRAP=1 cargo test -p clash-lib --lib e2e_network_reset_reauthenticates_hysteria2 --features hysteria,ws
  ```
- 保留 Client/Server 既有脏工作区；未切分、暂存、提交或推送。独立 Reviewer 完成后再决定本地下一步。

## 2026-11-28：生产 Handler 的 UDP 接收缓冲瓶颈

- 在不修改生产代码和系统 sysctl 的前提下，用进程级 preload shim 在生产 HY2 Handler 创建 UDP socket 时设置 `SO_RCVBUF`，完成 q4、c8、15 秒的两组 ABBA。默认缓冲约 9.96–10.01 Gbit/s；请求 1 MiB（实测 2 MiB）平均 13.157 Gbit/s，增幅 32.7%；请求 4 MiB（实测 8 MiB）平均 14.119 Gbit/s，增幅 41.0%。1 MiB 达到 4 MiB 吞吐的 93.2%。CV 2.6%–4.3%。系统 `Udp.RcvbufErrors` 平均约从 547k 降到 155k / 6.8k 每 15 秒。独立 1 MiB 双向 `--full-verify` smoke 通过。
- 生产 Handler 默认路径的本机 q4 瓶颈已明确定位到 Client OS UDP receive queue 容量，不是 Handler 与协议核心适配层的稳定吞吐损失。系统 `RcvbufErrors` 是全局计数，本次逐 socket 采样未取到 inode 计数；前一次 Handler q4 动态采样直接观察到 Client socket 增加 561,068 drops/15 秒、服务端为 0。
- 未将 4 MiB 写入产品默认值：旧协议核心 q1 矩阵里 4 MiB 对吞吐只提升约 1.7%，且尚无网页/API 延迟、RSS 和真实网络验证。原始表格及运行边界记录在 [HY2 接收缓冲结果](RESULTS_HY2_RCVBUF_2026-11-28.md)。
- 独立 Reviewer 建议不改通用 socket 默认值，增加 HY2 专属 opt-in 字节数配置；明确校验非零和 `c_int` 范围；配置值要传入 DirectConnector、UDP fallback 以及端口跳跃的初始和轮换 socket。链式 connector 无法应用时必须显式报错，不能静默忽略。Reviewer 还指出本机回环不足以支持全局 4 MiB 默认值。
- 当时的下一步计划是实现并验证 HY2 专属 opt-in 配置；完成情况与实际配置测试见下节。
- 本轮未修改 Client/Server 生产代码；未提交或推送。工作树现有其他未提交改动保留。

## 2026-11-28：HY2 接收缓冲 opt-in 实现与生产配置 q4 复测

- Client 已新增 HY2 专属可选 `udp-recv-buffer-size`（字节）；缺省仍不设置 socket 缓冲，旧 YAML 继续可解析。转换层拒绝 0 与大于 `i32::MAX` 的值，并把设置值传给 DirectConnector 的 Quinn socket 与 UDP fallback。端口跳跃的首个及轮换 UDP socket 也携带该值；不支持设置的 connector 在显式请求时返回 `Unsupported`，不会静默忽略。没有修改通用 socket 默认值、系统 sysctl 或 Server。
- 相关测试与编译已通过：配置/旧 YAML/socket 设置/Handler 选项共 4 个定向测试，UdpHop 状态与轮换测试 6 个、DirectConnector 原生 Quinn loopback 1 个；`cargo check -p clash-lib --features hysteria,transport-bench-api`；`cargo check -p clash-lib --no-default-features --features hysteria,ring`；`cargo fmt --all -- --check`。端口跳跃显式设置缓冲的真实轮换、默认 `Unsupported` 的 connector 集成行为和非 Linux 交叉编译仍未覆盖。
- 最终兼容版 feature-minimal 生产 Handler 二进制（SHA-256 `d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`）通过 q4 六格 ABBA：默认 10.126 Gbit/s、1 MiB 13.349、4 MiB 14.036；相对默认分别 +31.8%、+38.6%。1 MiB 达到 4 MiB 的 95.1%，drops 均值从 542,390 降至 153,643 / 15 秒和 8,180 / 15 秒。格内 CV 4.9%–6.2%。六格中 `ss -m` 的 Client socket `d` 均与全局 `Udp.RcvbufErrors` 增量完全相等。
- q1/q8 最终二进制各三档单格 15 秒筛查。q1 默认/1 MiB/4 MiB 为 5.552/5.532/5.536 Gbit/s，socket drops 为 12,941/203/0；q8 为 9.480/11.861/12.843 Gbit/s，drops 为 802,497/541,506/106,940。此处为单格筛查，后续重复 ABBA 结果见下。
- 同一 TLS 源站直连控制，两格下载均值为 23.690 Gbit/s、上传 24.862 Gbit/s，CV 1.4%–2.8%；目标源站有高于 q4 + 4 MiB 的本机交付余量。该值是 loopback 直连控制，不是 NIC/WAN 结果，也不当作严格代理效率比。
- 三档配置均通过双向 1 MiB `--full-verify`。`ss -m` 实际 socket `rb` 读回为默认 212,992、1 MiB 请求时 2,097,152、4 MiB 请求时 8,388,608 bytes；这是本机 Linux 对该进程 socket 的观测，不代表其他 OS 或不同 `rmem_max` 设置。1 MiB 已接近 4 MiB 吞吐，但其内存、时延和 WAN 成本尚未充分验证，生产默认仍不变。
- q4 ABBA 的 Client CPU 约 1.85/2.09/2.15 核，VmHWM 约 20.8–21.3 / 28.0–31.0 / 29.0–31.4 MiB；峰值 RSS 不等价于 socket buffer 分配归因。本矩阵 Server 与 Client 来自固定文件名/哈希；Server release SHA-256 为 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`，未从当前 Server checkout 重建。详细逐格数据和实验边界见 [HY2 接收缓冲结果](RESULTS_HY2_RCVBUF_2026-11-28.md)。
- 随后完成 q1/q8 各三档两格的 counterbalanced 重复矩阵。q1 默认/1 MiB/4 MiB 平均为 5.426/5.464/5.514 Gbit/s；4 MiB 清除了 drops，但相对默认只快 1.6%，差异不高于两格波动。q8 为 9.353/12.042/12.832 Gbit/s，1 MiB 和 4 MiB 分别比默认快 28.7%/37.2%；4 MiB 仍有约 107.5k Client socket drops/15 秒。Client socket drops 与系统 `Udp.RcvbufErrors` 逐格相等，Server socket drops 均为 0。
- 随后用 q1 + 4 MiB 缓冲、源码可确认的同一生产 Server，对 1/2/4/8 条 TCP 流运行 1→2→4→8→8→4→2→1 两格。均值为 4.914/4.846/4.779/5.475 Gbit/s；8 流比 1 流高 11.4%，1/2/4 流均值在 2.8% 范围内变化。所有格 socket drops 为 0，单格 CV 0.96%–6.41%。Server 来自本地 checkout `[源码快照已省略]`，release binary SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`，与 q4 主矩阵一致。
- 用同一生产 Server 完成 q4 下载期间 HTTP/API 延迟 ABBA；4 条持久前台连接共 40 请求/秒，每格 604 请求无失败。默认/1 MiB/4 MiB 后台吞吐均值 9.736/12.576/13.047 Gbit/s，p95 17.829/10.426/11.649 ms，p99 28.006/13.620/15.748 ms；平均 Client drops 535,052/166,848/7,399 每 15 秒。直连 TLS 下载约 24.3 Gbit/s 时 API p99 约 0.71 ms。详细矩阵及局限见 [HY2 接收缓冲结果](RESULTS_HY2_RCVBUF_2026-11-28.md)。
- 下一步：测同一生产 Server 上的全双工上下行下载加前台 API，再做至少 60 秒 soak，确认吞吐、尾延迟、drops 是否随时间变化；本机阶段完成后，按一致二进制与源站校验方法复跑 remote node。端口跳跃的实际轮换 socket、TUN/系统运行时路径、受控丢包网络和 Brutal 仍未由本轮验证覆盖。
- 独立 Reviewer 对最终 L2 diff 复审为 PASS、无阻断；其指出的剩余覆盖缺口见上。保留 Client 工作区其他已有改动，未暂存、提交或推送。

## 2026-11-28：全双工本机基线与 Server receive-buffer 核验

- 用 feature-minimal production Handler Client、Chimera Server 本机 release binary、同机 TLS 源站，完成 q4 Client 缓冲默认/1 MiB/4 MiB 的 15 秒全双工 ABBA。8 条 SOCKS TCP 流每条双向各传 64 MiB；前台 4 条持久 HTTP/1.1 会话共 40 请求/秒，每格 604 个请求均成功。下载均值为 10.140/13.220/13.545 Gbit/s，上传为 13.247/13.159/13.154 Gbit/s；Client drops 为 308.7k/74.4k/3.5k，Server drops 为 6.7k/6.0k/5.5k 每 15 秒。全双工 API p99 为 32.4/37.4/35.1 ms，未随 Client 缓冲增大而稳定下降；此前单向下载 p99 改善不能外推到双向繁忙场景。
- q4 + Client 4 MiB 在 90 秒全双工 soak 中下载/上传为 13.914/13.148 Gbit/s；API 3,604/3,604 成功，p95/p99 为 22.155/35.040 ms。首、中、末三分之一没有持续速率衰退。Client/Server drops 为 18,944/45,539，说明长测中 Server 侧仍有显著 UDP drops。
- 90 秒同机直连 TLS 对照（同样全双工八流及 API 40 请求/秒）为下载/上传 23.955/24.413 Gbit/s，API p95/p99 为 0.808/0.865 ms，零失败。两组不是物理网卡或 WAN 成绩；直连 harness 在写完指标后因清理钩子漏导入 `os` 以状态码 1 退出，payload 进程已手动停止且确认无测试进程残留。
- 将 Client 固定在 q4/4 MiB，仅对 Server listener socket 做进程级 `SO_RCVBUF` ABBA。读回确认 Server 默认 `rb=8 MiB`，请求 4 MiB 仍为 8 MiB；请求 1 MiB 后实际 `rb=2 MiB`。Server drops 均值约 10.1k / 79.7k / 9.0k 每 15 秒，Server 上行吞吐约 13.364 / 12.915 / 13.344 Gbit/s。降低 Server buffer 令 drops 约增 7.9 倍；当前系统 `net.core.rmem_max=4 MiB` 已把 Server socket 显示值上限限制在 8 MiB，不能从这组数据推断扩大系统上限会有收益。
- Server Hysteria2 listener 的 Shoes profile 源码请求 8,625,000 字节的 UDP 收发缓冲；本轮运行 Server checkout 为本地 `master` `[源码快照已省略]`，release binary SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`。此处不同于更早记录的 `隔离候选分支` / `[源码快照已省略]` candidate；本轮实际产物按上述 SHA 标识，Server 本地 master 当时比其 `origin/master` ref `[源码快照已省略]` 落后一提交。
- 原始矩阵见 [本机回环与直连基线结果](RESULTS_HY2_RCVBUF_2026-11-28.md)；JSON 数据在 `本机临时目录`、`本机临时目录`、`本机临时目录`、`本机临时目录`。
- 本轮没有修改生产 Client/Server 代码、系统 sysctl 或提交/推送；保留既有脏工作区。下一步先对 Server 8 MiB socket 下的收包/软中断处理做 profile，再进入 remote node 远端交叉复测。
