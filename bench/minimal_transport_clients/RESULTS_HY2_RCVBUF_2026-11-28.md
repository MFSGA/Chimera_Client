# HY2 本机回环与直连基线报告

日期：2026-11-28

## 结论

- 本机纯 TCP 回环基线约 **161.8–162.7 Gbit/s**（iperf3，8 并发）。这是同机 loopback 上限参照，不含 TLS、QUIC、代理和应用数据源，不能当作真实网卡吞吐。
- HY2 协议核心客户端 + Chimera Server 的本机回环下载最高测得 **14.082 Gbit/s**（q4，4 MiB 请求缓冲）。后续生产 Handler 的 q4 ABBA 平均为 **14.119 Gbit/s**；通过测试进程级 shim 临时调节 socket，没有修改生产默认值。
- 用最终兼容版 Client 二进制复跑后，生产 Handler 的 q4 配置级 ABBA 为默认 **10.126**、请求 1 MiB **13.349**、请求 4 MiB **14.036 Gbit/s**；相对默认分别提升 **31.8%** 和 **38.6%**。逐 socket readback 显示 `SO_RCVBUF` 为 212,992 / 2,097,152 / 8,388,608 bytes，三档全内容 smoke 均通过。
- 同一个 TLS 源站绕过代理的 8 流、每流上下行 64 MiB 直连控制，两格下载均值 **23.690 Gbit/s**、上传 **24.862 Gbit/s**；q4 + 4 MiB 结果为直连下载控制的 59.2%。这是同机源站控制，不是物理网卡或公网线路成绩。
- 同机直接 TLS 下载在 24 Gbit/s 负载下，前台 HTTP API p99 仍约 **0.71 ms**；生产 HY2 q4 的默认缓冲 p99 升到 **26–29 ms**，请求 1 MiB / 4 MiB 后降到 **12–15 ms**。这是**单向下载**矩阵，每格 604 个请求均成功；相同负载改为上下行全双工后，各档 p99 都在约 **30–40 ms**，所以单向下载的延迟收益不能外推到双向繁忙场景。
- 本机测试确认了多条限制：q4/q8 多 QUIC 连接时，Client UDP 接收队列会限制吞吐；q1 即使把 Client drops 清零，增加 TCP 流数到 8 也只提高约 11%。全双工时 Server UDP socket 也出现 drops；测得 Server 当前已请求大缓冲，Linux socket 实际为 8 MiB。还没有证明生产 Client 应直接采用固定 4 MiB 默认值。真实网络与长期内存代价仍待验证。
- Chimera 与官方服务端的相对结果依赖 QUIC 连接数：q4 下 Chimera 高约 17.5%；q8 + 4 MiB 下两者相差约 1.3%。目前不能据此宣布一个服务端实现整体更快。

## 本机纯 TCP 直连基线

iperf3 3.20 在 `127.0.0.1` 上以 8 条 TCP 流运行，每方向 3 次、每次 15 秒，方向交错。接收端报告的应用速率如下：

| 方向 | 中位数 | 平均值 | CV | 范围 |
| --- | ---: | ---: | ---: | ---: |
| 上传（客户端到服务端） | 162.708 Gbit/s | 162.444 Gbit/s | 1.22% | 159.901–164.723 Gbit/s |
| 下载（反向） | 161.782 Gbit/s | 161.898 Gbit/s | 0.44% | 161.080–162.830 Gbit/s |

此项是裸 TCP 的 loopback 上限控制；与含 TLS、QUIC、Hysteria framing、SOCKS 及测试源站的 HY2 成绩不是同一负载，不计算效率百分比。原始记录：`本机临时目录`。

## HY2 接收缓冲 A/B

### q1：先隔离 socket 默认值

客户端 8 条 TCP 流复用 1 条 QUIC 连接，单格 15 秒；每种设置重复两次。速率为两次单格中位数的平均，socket drop 为每格丢包数的平均。

| 客户端 UDP socket | 下载 | 客户端 socket drop / 15 秒 | 服务端 socket drop |
| --- | ---: | ---: | ---: |
| 原生 Quinn 默认 | 5.490 Gbit/s | 14,328 | 0 |
| socket2 默认（请求 212,992 B） | 5.429 Gbit/s | 13,600 | 0 |
| socket2 请求 1 MiB（实际 getsockopt 2 MiB） | 5.565 Gbit/s | 232 | 0 |
| socket2 请求 4 MiB（实际 getsockopt 8 MiB） | 5.585 Gbit/s | 0 | 0 |

q1 下吞吐提升只有约 1.7%，但 4 MiB 请求完全消除了采样到的客户端 socket drop。说明 q1 的吞吐还受别的因素限制；仅调缓冲并不能解释全部上限。

### q4/q8：同一客户端交叉测服务端

客户端使用同一个独立 HY2 协议核心二进制，依次连接 Chimera Server 与官方 Hysteria 2.14.0 Server。8 条 TCP 下载流按轮询方式分配到 4 或 8 条已认证 QUIC 连接；共享一个 Endpoint 和 UDP socket。每格运行 15 秒，缓冲条件各有两格重复。下载量计应用层交付字节；每格 CV 为 2.1%–5.7%。

| 服务端 | QUIC 连接 | 默认缓冲 | 请求 1 MiB | 请求 4 MiB | 客户端 UDP drops / 15 秒：默认 → 1 MiB → 4 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chimera | 4 | 9.909 Gbit/s | 13.516 Gbit/s | **14.025 Gbit/s** | 548,828 → 161,584 → 7,790 |
| Chimera | 8 | 9.466 Gbit/s | 12.112 Gbit/s | 12.696 Gbit/s | 825,214 → 526,214 → 117,860 |
| 官方 Hysteria 2.14.0 | 4 | 8.465 Gbit/s | 11.898 Gbit/s | 11.932 Gbit/s | 112,333 → 95 → 0 |
| 官方 Hysteria 2.14.0 | 8 | 8.815 Gbit/s | 12.230 Gbit/s | 12.538 Gbit/s | 177,664 → 14,394 → 0 |

“默认/1 MiB/4 MiB”里的请求值是 `SO_RCVBUF` 设置值。该主机 `net.core.rmem_default=212,992`、`net.core.rmem_max=4,194,304`；Linux 的 `getsockopt(SO_RCVBUF)` 显示值为请求值的两倍。

- 接收缓冲 4 MiB 请求相对默认值：Chimera q4 **+41.5%**、q8 **+34.1%**；官方 q4 **+41.0%**、q8 **+42.2%**。
- 同一缓冲条件下，Chimera 相对官方：q4 +17.1%（默认）/ +17.5%（4 MiB）；q8 +7.4%（默认）/ +1.3%（4 MiB）。
- Chimera 4 MiB 下仍出现客户端 socket drops，尤其 q8；官方服务端在同缓冲条件下没有观测到 socket drop。QUIC 可能恢复丢失的数据报，但恢复会增加开销；本测试没有把 socket drop 一一映射到应用层重传。
- 所有对应服务端 UDP socket drop 均为 0。系统 UDP `RcvbufErrors` 与客户端 socket 丢包计数吻合，支持丢包发生在本机接收队列的判断。

原始交叉结果：

- `本机临时目录`
- `本机临时目录`
- `本机临时目录`
- `本机临时目录`

## 基线、构建与边界

- 主机：AMD Ryzen 7 5800，Linux 6.18.35，CPU 0–7。
- Chimera Client 源码基线：`f599e19a08dd302132dcc860443fd2dc690effe1`，工作区包含未提交改动。协议核心客户端 SHA-256：`c5032295a6ada352606ce237b36a19b6cdf8ac7c8168a3b2d4ef7dd5cfea5836`。
- Chimera Server 源码基线：`8381de5bfe4ca0d6756fbecccabbd51ef757df67`，工作区包含未提交改动；测量二进制 SHA-256：`e73b74d176bd50913c1d49240458cff308a3be361b0fdb1b87a817cff8421a7c`。
- 官方服务端：Hysteria 2.14.0，SHA-256：`244242b0aa9aed0cd404c5e44034efc4043c5c464bd67a1bd2c05472e2e81c64`。
- 协议核心客户端、服务端、生成器和 TLS 源站都在同一台主机；HY2 矩阵跑的是 loopback，非物理 NIC、非 remote node/WAN。Bulk 矩阵未开完整 payload 校验；它按成功交付字节计吞吐，不能替代单独的完整内容校验 smoke。
- 本轮只在**未提交的 benchmark 客户端**增加 `--udp-recv-buffer-bytes`，供 socket2 实验端点调节接收缓冲；没有修改生产 Client/Server 默认行为。
- 已完成的 benchmark 工具检查：`cargo fmt -p chimera-hy2-protocol-perf-client -- --check` 通过；该包定向测试 7 项通过；release 构建通过。完整生产 Client 路径、其他 Linux 内核、Windows/macOS、Brutal 和 WAN 还没有用这项缓冲调整验证。

## 真实出口控制（既有记录）

此前 remote node 主机到公网 OVH 测试源的直接 100 MiB HTTPS 下载，3 次均完整收到 104,857,600 字节且 TLS 校验成功；中位数 157.62 Mbit/s，范围 128.43–160.15 Mbit/s。它只测 **remote node → 源站出口**，不是客户端到 remote node 的链路，也没有经过代理，因此不能拿来除以本机回环吞吐计算代理效率。详细记录见 Client 工作区的 `bench/minimal_transport_clients/RESULTS_REMOTE_DIRECT_EGRESS_2026-11-28.md`。

## 生产 Handler q4 接收缓冲 ABBA 补测

本节补上生产 `clash-lib` Hysteria2 Handler 的 socket 接收缓冲验证。没有改生产代码或系统 sysctl；用仅作用于测试客户端进程的临时 `LD_PRELOAD` shim，在创建 UDP socket 时调用 `setsockopt(SO_RCVBUF)`。4 MiB 请求在当前 Linux 上通过 `getsockopt` 实测为 8 MiB。

固定条件为本机 loopback、生产 Handler、Chimera Server 二进制、BBR、q4、8 条 SOCKS TCP 流、每流 64 MiB 下载、内层 TLS、CPU 0–7。四个 15 秒单元按 default → 4 MiB → 4 MiB → default 顺序运行；每格 generator CV 为 2.6%–4.1%。本轮另做 q4、4 条流、上下行各 1 MiB 的 `--full-verify` smoke，通过。

| Client UDP `SO_RCVBUF` | 下载中位数（每格） | ABBA 均值 | 单格 CV | 系统 `Udp.RcvbufErrors` 均值 / 15 秒 |
| --- | ---: | ---: | ---: | ---: |
| 系统默认 212,992 B（4 个相邻基线格） | 10.204 / 9.821 / 10.233 / 9.596 Gbit/s | 9.963 Gbit/s | 2.6%–4.3% | 546,816 |
| 请求 1 MiB，实测 2 MiB | 13.200 / 13.115 Gbit/s | 13.157 Gbit/s | 2.7% / 3.5% | 155,165 |
| 请求 4 MiB，实测 8 MiB | 14.169 / 14.070 Gbit/s | 14.119 Gbit/s | 2.9% / 2.6% | 6,832 |

1 MiB ABBA 的相邻默认格均值为 9.915 Gbit/s，1 MiB 使其提升 **32.7%**、系统错误计数降低 **71.8%**；4 MiB ABBA 的相邻默认格均值为 10.012 Gbit/s，4 MiB 使其提升 **41.0%**、系统错误计数降低 **98.7%**。两个 ABBA 的默认格均值相差约 1.0%。1 MiB 档达到 4 MiB 档均值的 **93.2%**，Linux 报告的接收缓冲为其四分之一，是值得继续验证的较小配置候选。

`/proc/net/snmp` 的 `RcvbufErrors` 是系统级计数；本 ABBA 脚本本身没有拿到逐 socket inode 计数，不能将该计数单独当作某个 Client socket 的精确丢包数。前一组生产 Handler 动态采样中，q4 默认缓冲的 Client socket 在 15.4 秒内增加 561,068 drops，而服务端 UDP socket 为 0；该证据与本次 ABBA 的系统计数变化方向一致。

此结果说明默认 212 KiB receive buffer 会限制当前本机 q4 突发吞吐；不代表真实 WAN、短连接、网页/API 延迟或 q1 默认连接配置也能得到相同提升。此前精简 protocol-core 的 q1 测试中，4 MiB 请求对吞吐只提升约 1.7%，因此不应据 q4 回环结果把 4 MiB 写成所有 HY2 节点的硬编码默认值。当时计划实现 HY2 专属 opt-in 字段并重跑生产路径，后续配置级结果见下一节。

本次产物身份：Client 源码 HEAD `f599e19a08dd302132dcc860443fd2dc690effe1`（工作区有未提交改动），直接 Handler release 二进制 SHA-256 `af7467711fdd72f91e3808fd75bd63771a9566a6b2c8fe021f27b47741d731f3`；Server release 二进制 SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`；generator SHA-256 `7989d7f5302cfef4ab954474025839b4bfabfcb1d1c53fd323ffc7b50d1b6e5f`。Server 二进制在本轮复用、没有重新构建，因此以二进制 SHA-256 标识该对照端，不把当前 Server checkout SHA 当作该二进制的重新构建证明。完整原始 ABBA JSONL、smoke 和临时 shim 均在 `本机临时目录`，未复制凭据或私有配置进仓库。

## 生产配置 q4 接收缓冲 ABBA（已加入 opt-in 配置）

随后将 `udp-recv-buffer-size` 接入生产 HY2 配置，并用新构建的直接 Handler 客户端运行六格 ABBA。配置值仅改变 socket receive buffer；同一 q4 配置、BBR、8 条 SOCKS TCP 流、每流 64 MiB 下载、内层 TLS、TCP_NODELAY、65536-byte relay buffer、CPU 0–7、固定 Server、源站、generator 与目标地址。每格至少 15 秒，按默认 → 1 MiB → 4 MiB → 4 MiB → 1 MiB → 默认顺序。表中吞吐为每格多次交付量测量的中位数，CV 是格内运行波动。

| 请求 `udp-recv-buffer-size` | 两格下载 Gbit/s（CV） | 均值 | Client CPU（平均核心数） | Client VmHWM | Client socket drops = 全局 `Udp.RcvbufErrors` / 15 秒 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 未设置 | 10.301 (5.5%) / 9.950 (5.1%) | 10.126 | 1.85 | 20.8–21.3 MiB | 542,390 |
| 1 MiB | 13.367 (5.1%) / 13.331 (4.9%) | 13.349 | 2.09 | 28.0–31.0 MiB | 153,643 |
| 4 MiB | 13.982 (5.3%) / 14.089 (6.2%) | 14.036 | 2.15 | 29.0–31.4 MiB | 8,180 |

1 MiB 档达到 4 MiB 档吞吐均值的 **95.1%**。1 MiB 和 4 MiB 相对默认分别快 **31.8%**、**38.6%**；平均 drops 分别下降 **71.7%**、**98.5%**。此最终 ABBA 的六格中，`ss -m` 的 Client socket `d` 与系统 `/proc/net/snmp` `Udp.RcvbufErrors` 增量逐格完全相等，定位证据比此前 preload 试验更直接。独立完整内容 smoke 又确认三档实际 `rb` 分别为 212,992、2,097,152、8,388,608 bytes，三档均完成双向各 1 MiB 的 `--full-verify`。

客户端进程 CPU 随吞吐升高（约 1.85 → 2.09 → 2.15 核），VmHWM 读数约增加 7–10 MiB。VmHWM 是整个 benchmark 进程的峰值，未对用户态堆与内核 socket 内存做归因，不能视为精确的缓冲区内存成本。Server 与目标进程也固定在 CPU 0–7，但本表只记录 Client CPU。单格 CV 为 4.9%–6.2%，默认两格相差 3.5%，1 MiB 两格相差 0.3%，4 MiB 两格相差 0.8%。

### q1/q8 缓冲档位重复 ABBA

使用相同的 production Handler Client、固定 Server、target、generator、8 条 TCP 流、每流 64 MiB 下载、BBR、内层 TLS 和 CPU 0–7。q1/q8 各自按 counterbalanced 顺序重复两格，每格约 15 秒。表中速率为两格单格中位数的平均，CV 为各格内部 CV；socket drops 由 `ss -m` 采样，且逐格与系统 `Udp.RcvbufErrors` 增量相等。所有 Server UDP socket drops 均为 0。

| QUIC pool | Client UDP 缓冲请求 | 下载 Gbit/s（两格） | 均值 | Client socket drops / 15 秒（两格） | Client / Server CPU（核） |
| ---: | ---: | ---: | ---: | ---: | ---: |
| q1 | 默认 | 5.530 / 5.322 | 5.426 | 12,287 / 12,877 | 1.57 / 1.12 |
| q1 | 1 MiB | 5.477 / 5.450 | 5.464 | 86 / 282 | 1.60 / 1.13 |
| q1 | 4 MiB | 5.510 / 5.518 | 5.514 | 0 / 0 | 1.60 / 1.12 |
| q8 | 默认 | 9.453 / 9.253 | 9.353 | 775,579 / 795,951 | 1.68 / 2.61 |
| q8 | 1 MiB | 12.034 / 12.049 | 12.042 | 487,665 / 502,483 | 1.88 / 2.69 |
| q8 | 4 MiB | 12.948 / 12.715 | 12.832 | 107,337 / 107,701 | 2.00 / 2.51 |

q1 的平均速率从默认到 4 MiB 只提高 **1.6%**，两格差异和格内波动相近；4 MiB 清除了接收队列丢包，但没有证据表明它提高了 q1 吞吐。q8 的 1 MiB 和 4 MiB 相对默认分别提高 **28.7%**、**37.2%**，1 MiB 达到 4 MiB 平均速率的 **93.8%**；drops 分别减少 **37.0%**、**86.3%**，但 4 MiB 下仍约 10.8 万/15 秒。这支持接收队列是 q8 多连接吞吐瓶颈之一，但不解释剩余丢包。

### q1 单 QUIC 连接的 TCP 流并发

固定 q1、请求 4 MiB `SO_RCVBUF`（本机实际 `rb=8 MiB`）、BBR、生产 Handler、64 MiB/流下载，TCP 流数按 1→2→4→8→8→4→2→1 运行，每格约 15 秒。Client、Server、target 和 generator 固定在 CPU 0–7。Server 使用本地 checkout 的生产 release binary；另有 q1 双向各 1 MiB 的完整内容 smoke。

| TCP 流数 | 下载 Gbit/s（两格） | 均值 | Client CPU（核） | Server CPU（核） | Client / Server socket drops |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 4.791 / 5.037 | 4.914 | 0.57 | 0.91 | 0 / 0 |
| 2 | 4.585 / 5.107 | 4.846 | 1.21 | 1.15 | 0 / 0 |
| 4 | 4.445 / 5.113 | 4.779 | 1.38 | 1.24 | 0 / 0 |
| 8 | 5.448 / 5.502 | 5.475 | 1.52 | 1.08 | 0 / 0 |

8 条流比 1 条流高约 **11.4%**；1/2/4 流的均值只在 2.8% 范围内变化。全矩阵 Client 和 Server socket drops、系统 `Udp.RcvbufErrors` 均为 0。1–4 流的前后测量存在顺序漂移，单格 CV 为 0.96%–6.41%，所以 11.4% 作为流并发收益的估计，不能视为精确系数。多 TCP 流不能解释 q1 与 q4 的主要差距；更明显的本机提升来自增加独立 QUIC 会话。

产物身份：Client release SHA-256 `d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`；Server source HEAD `52d0108c9f6044532bdaade81d26583f0a551797`，本地工作区干净，`cargo build --locked --release -p chimera_server_app` 返回 Fresh，测试 binary SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`；generator SHA-256 `8195e43c63e967cb25181b865acf9d23c7837746aefb3648ff056555e83782be`；TLS target SHA-256 `dfeab347492d4c7db84bb97397e6cb251a9072892c83dec56a100fce21a265d8`。原始 JSONL 和进程日志在 `本机临时目录`。

### q4 下载期间的前台 HTTP/API 延迟

同机 HTTP 源站返回 256 字节，使用 4 条持久 HTTP/1.1 连接，每连接每秒 10 个请求；后台使用 8 条 SOCKS TCP 流，每流下载 64 MiB TLS payload。每格 15 秒，q4 连接池，BBR；缓冲顺序为默认→1 MiB→4 MiB→4 MiB→1 MiB→默认。每格各收到 **604 个前台请求且错误为 0**。HTTP 前台是明文小响应，用于测代理排队，不代表浏览器完整页面、HTTPS 握手或公网 RTT。所有 q4 buffer 配置的双向 1 MiB `--full-verify` smoke 均通过。

| Client UDP 接收缓冲 | 后台下载 Gbit/s（两格） | 均值 | 前台 API p95 ms（两格） | 前台 API p99 ms（两格） | Client drops / 15 秒（两格） |
| --- | ---: | ---: | ---: | ---: | ---: |
| 默认 | 10.258 / 9.215 | 9.736 | 19.742 / 15.917 | 29.103 / 26.908 | 529,342 / 540,762 |
| 1 MiB（实际 `rb=2 MiB`） | 12.782 / 12.371 | 12.576 | 10.812 / 10.039 | 14.624 / 12.615 | 169,011 / 164,684 |
| 4 MiB（实际 `rb=8 MiB`） | 13.045 / 13.048 | 13.047 | 12.056 / 11.242 | 16.830 / 14.665 | 7,752 / 7,046 |

直连控制没有 Client/Server：同一个 TLS payload target 在相同 8 流下载负载下交付 24.571/23.955 Gbit/s；前台 API p95 为 0.662/0.665 ms、p99 为 0.722/0.706 ms，604/604 请求成功。仅 q4 代理空载时，API p95/p99 为 0.871/0.940 ms。由此可见，源站、loopback 和 40 请求/秒的 HTTP 生成器不是造成几十毫秒尾延迟的瓶颈。

在这组生产 Server 矩阵中，1 MiB 达到 4 MiB 后台吞吐的 **96.4%**，且两格 p95/p99 均低于 4 MiB；4 MiB 把 drops 再降约 95.6%，但吞吐只多约 3.7%，尾延迟反而高约 2–3 ms。1 MiB 是当前本机下载场景下更好的吞吐/尾延迟折中候选，但是否成为默认仍需更长时段、上行/双向负载、内存与真实链路复核。

产物身份：Client 同上；Server 使用源码 HEAD `52d0108c9f6044532bdaade81d26583f0a551797` 和相同生产 binary SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`；generator SHA-256 `8195e43c63e967cb25181b865acf9d23c7837746aefb3648ff056555e83782be`；payload target SHA-256 `dfeab347492d4c7db84bb97397e6cb251a9072892c83dec56a100fce21a265d8`。Server 配置通过 `chimera_server_app --check --config … --format json`；原始记录在 `本机临时目录`，直连控制在 `本机临时目录`。

产物身份：Client 源码 HEAD `f599e19a08dd302132dcc860443fd2dc690effe1`，工作区包含既有未提交改动；最终 feature-minimal 生产 Handler 客户端 SHA-256 `d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`。复用的 Chimera Server release 二进制 SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`；本地 Server checkout 为 `52d0108c9f6044532bdaade81d26583f0a551797`，干净但比 `origin/master` 的 `8381de5bfe4ca0d6756fbecccabbd51ef757df67` 落后一提交。后续在该 checkout 执行 `cargo build --locked --release -p chimera_server_app` 返回 Fresh，生成目标与该 SHA 完全一致；因此复用 binary 与当前本地源码构建状态对应，但不对应远端领先的一提交。generator SHA-256 `7989d7f5302cfef4ab954474025839b4bfabfcb1d1c53fd323ffc7b50d1b6e5f`；TLS target SHA-256 `dfeab347492d4c7db84bb97397e6cb251a9072892c83dec56a100fce21a265d8`。原始单格 JSONL、socket readback、进程日志均保存在 `本机临时目录`，不含入仓的私有配置。

### 全双工上传/下载时的前台 API 与持续负载

负载使用相同的同机 TLS payload 与 HTTP 源站：8 条 SOCKS TCP 流，每条流双向各传 64 MiB TLS payload；同时 4 条持久 HTTP/1.1 连接各发 10 请求/秒，返回 256 字节。Client 固定 q4 / BBR；每个 15 秒单元收到 604 个 API 请求且 0 失败。缓冲顺序为默认→1 MiB→4 MiB→4 MiB→1 MiB→默认。每种 Client 缓冲有两次样本：

| Client `SO_RCVBUF` | 下载均值 Gbit/s | 上传均值 Gbit/s | API p95 均值 ms | API p99 均值 ms | Client drops / 15 秒 | Server drops / 15 秒 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 默认（212,992 B） | 10.140 | 13.247 | 23.239 | 32.393 | 308,749 | 6,661 |
| 请求 1 MiB（实际 `rb=2 MiB`） | 13.220 | 13.159 | 23.913 | 37.384 | 74,435 | 5,998 |
| 请求 4 MiB（实际 `rb=8 MiB`） | 13.545 | 13.154 | 23.583 | 35.076 | 3,472 | 5,453 |

Client 增大接收缓冲后，双向负载的下载吞吐提高，Client drops 显著下降；但 API p95/p99 没有随缓冲增大而稳定下降，且 Server drops 仍在每格约 5–7k。两个样本不足以把 p99 几毫秒的变化归因于某一项。此处说明 receive queue 容量是吞吐因素之一，但全双工网页/API 尾延迟还受 Server 收包、QUIC 调度和 CPU 排队影响。

随后用 Client q4 / 4 MiB 缓冲跑 90 秒持续全双工负载；3,604 个前台 API 请求全部成功。后台下载/上传中位吞吐为 **13.914 / 13.148 Gbit/s**，格内 CV 为 **4.84% / 7.44%**；API p95/p99 为 **22.155 / 35.040 ms**。按首、中、末三分之一切分，下载中位数为 14.191 / 13.819 / 13.832 Gbit/s，上传为 13.353 / 12.931 / 13.167 Gbit/s，没有持续下降趋势。90 秒累计 Client drops 为 18,944、Server drops 为 45,539、系统 `Udp.RcvbufErrors` 为 64,483；该全局错误增量与两端 socket drops 之和一致。

同样的 90 秒双向 TLS 下载/上传和 API 负载直连源站（不经过 Client/Server）得到 **23.955 / 24.413 Gbit/s**；3,604 个 API 请求均成功，p95/p99 为 **0.808 / 0.865 ms**。这仍是 loopback 对照，不是物理网卡或 WAN 结果。直连 harness 在写完所有指标后，清理钩子因缺少 `os` 导入而以状态码 1 退出；payload 进程随后已手动停止，并确认无 benchmark 进程残留。因此数据来自完整 90 秒样本，但该 harness 的退出状态不能记作成功。

原始记录：HY2 15 秒矩阵 `本机临时目录`；q4 90 秒 soak `本机临时目录`；90 秒直连对照 `本机临时目录`。

### Server UDP 接收缓冲 ABBA

为了确认双向负载下 Server socket drops 的来源，Client 固定 q4 / 请求 4 MiB（实测 `rb=8 MiB`），仅通过测试进程的 `LD_PRELOAD` shim 改变 Server `SO_RCVBUF`。顺序为默认→1 MiB→4 MiB→4 MiB→1 MiB→默认；每格 15 秒，其他负载与前台 API 节奏不变。Shim 拦截 `setsockopt`，并在每格用 `ss` 确认实际 socket 值；没有改生产代码或系统 sysctl。

| Server `SO_RCVBUF` 请求 | 实际 `rb` | 下载均值 Gbit/s | 上传均值 Gbit/s | API p95/p99 均值 ms | Client drops / 15 秒 | Server drops / 15 秒 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Server 默认 | 8 MiB | 14.304 | 13.364 | 22.004 / 34.776 | 3,026 | 10,100 |
| 1 MiB | 2 MiB | 14.094 | 12.915 | 17.337 / 26.196 | 3,882 | 79,737 |
| 4 MiB | 8 MiB | 14.133 | 13.344 | 21.931 / 34.512 | 4,637 | 9,025 |

本机 `net.core.rmem_max=4,194,304`，Linux `ss` 将最大请求显示为 `rb=8,388,608`。Chimera Server Hysteria2 listener 在 Shoes 模式请求 8,625,000 字节；实现位于 Chimera_Server 仓库的 `chimera_server_lib/src/handler/hysteria2/mod.rs:34`。因此 4 MiB 请求与 Server 当前有效配置相同，没有产生额外余量；把它降到 1 MiB（实际 2 MiB）后，Server drops 增至约 **7.9 倍**，上行中位吞吐低约 **3.4%**。这证明较小 Server 接收缓冲会损害当前双向场景，不能据此宣称 8 MiB 下仍有可调缓冲空间。Server 已接近系统 socket 上限，剩余 drops 需进一步检查收包调度/QUIC 处理路径；若要测更大的 socket queue，需要另行设计隔离的系统级实验。

原始记录 `本机临时目录`。Client release SHA-256 `d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`；Server 源码 HEAD `52d0108c9f6044532bdaade81d26583f0a551797`、release binary SHA-256 `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982`；generator 和 payload target 与上文一致。

### 同一 TLS 源站直连控制

停掉代理 Client/Server 后，仍使用同一 TLS payload target、generator、8 并发、每流上传/下载 64 MiB、TLS、TCP_NODELAY、64 KiB buffer 和 CPU 0–7；直接连接 target，不经 SOCKS 或 HY2。每格至少 15 秒。

| 直连单元 | 上传 Gbit/s (CV) | 下载 Gbit/s (CV) |
| --- | ---: | ---: |
| 1 | 25.114 (2.8%) | 23.837 (1.5%) |
| 2 | 24.610 (2.6%) | 23.544 (1.4%) |
| 均值 | 24.862 | 23.690 |

这表明目标和明文到 TLS 源站的本机回环链路至少可以交付约 23.7 Gbit/s 下载，高于本次 q4 + 4 MiB 的 14.0 Gbit/s；目标不是这组代理结果的直接吞吐上限。59.2% 只描述本机同负载的两个独立矩阵之比，代理测试多了 Client/Server 进程并共享 CPU 0–7，不能解释为跨平台代理效率。

这组结果验证了生产配置到 DirectConnector UDP socket 的设置路径，并确认 q4 本机回环下 1 MiB 已接近 4 MiB 的吞吐。它仍不能证明 WAN、q1 默认连接、短连接、前台延迟、长时间运行或端口跳跃链路的收益；因此配置仍为 opt-in，默认行为不变。

## Server 收包丢失归因与 CPU profile

为定位 Server 在当前 8 MiB socket 下的剩余丢包，基于 Server master `5f01a8af96952f81bc80fcf8a42bfa5ca6fb0f67` 构建了独立 profile binary：`minimal-hysteria`、release 优化、debug symbols、frame pointers；profile binary SHA-256 为 `02509609c88896e8d4356439c32414f66aaa36af4949829f1467ce4080b0b15f`。它只用于采样，吞吐结果不与普通 release binary 比较。

35 秒本机 loopback q4 全双工采样使用 8 条 TCP TLS 流、每流双向 64 MiB、Client 请求 4 MiB receive buffer、CPU 0–7。Server profile 记录约 4,000 个 `cycles:u` 样本，丢样为 0。自采样占比如下：

| Server 自身采样热点 | 样本占比 | 观察到的调用路径 |
| --- | ---: | --- |
| AWS-LC AES-GCM (`_aesni_ctr32_ghash_6x`) | 19.44% | QUIC packet decrypt；其中 AES-GCM decrypt 路径约占总样本 10.76% |
| `__memmove_avx_unaligned_erms` | 18.98% | 包含 Quinn `drive_transmit → poll_transmit` 的数据复制路径，约占总样本 4.21% |
| `aws_lc_0_47_0_aes_hw_encrypt` | 3.49% | AES-GCM 加密子路径 |
| Quinn `Connection::populate_packet` | 3.45% | QUIC packet 组装 |
| Quinn `PacketBuilder::finish_and_track` | 2.34% | QUIC packet 完成与跟踪 |
| Quinn `Connection::poll_transmit` | 1.72% | 发送调度 |
| Quinn `Connection::process_payload` | 1.61% | 收到解密 payload 后的处理 |
| H3 `RecvStream::poll_data` | 1.46% | 应用读取入站 stream 数据 |

Server vendored Quinn 的 `quinn-proto/src/connection/streams/state.rs` 在 `write_stream_frames` 中通过 `buf.put_slice(data)` 把 stream 数据复制进 QUIC packet buffer。它与 profile 中的 `poll_transmit`/`memmove` 热点吻合。这里证实了 AEAD 和 packet buffer copy 是主要 CPU 消耗；profile 不能单独说明哪一处改动能净提升吞吐。

另用相同 q4/8 路双向工作负载运行 15.13 秒 socket 归因复测，启用 `ss -a` 读取两端实际 UDP socket。两端 `SO_RCVBUF` 均为 8,388,608 bytes：

| UDP socket | 测前 drops | 测后 drops | 本格新增 drops |
| --- | ---: | ---: | ---: |
| Client | 0 | 5,051 | 5,051 |
| Server | 0 | 11,893 | 11,893 |
| 合计 | — | — | 16,944 |

本格系统 `/proc/net/snmp` 的 `Udp.RcvbufErrors` 也增加 **16,944**，与两端 socket drop 增量精确相等；Server 占本格丢包约 **70.2%**，约为 Client 的 **2.35 倍**。同一时段 `NET_RX` softirq 在 CPU 0–7 共增加 2,856,407 次，在 CPU 8–15 共增加 840 次。测试进程都绑定 CPU 0–7，因此这与 loopback 接收处理集中在测试核相符；softirq 计数是系统级关联证据，不是按进程归因。

上述 profile run 的业务速率中位数为下行 12.714、上行 11.878 Gbit/s；socket 归因复测为 13.089 / 12.222 Gbit/s。它们启用了 profiler，**只用于说明负载规模，不作为性能表中的正式吞吐结果**。没有启用 API 前台请求。

### Ring 与 AWS-LC Client crypto backend ABBA

随后使用普通 release Client 做四格 `Ring → AWS-LC → AWS-LC → Ring` 对照；Server、TLS 源站、generator、CPU 亲和性、q4、共享 Endpoint、8 条全双工 TCP/TLS 流、每流双向 64 MiB、Client 请求 4 MiB UDP 接收缓冲和 15 秒单格均固定。各格前都通过 1 MiB 双向全内容校验。Server 固定普通 release binary SHA-256 `7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d`。

| Client backend | 下行单格中位数 | 下行格中位数的中位数 | 上行单格中位数 | 上行格中位数的中位数 | Client CPU 平均 | Client CPU / 双向 GiB | 二进制大小 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ring | 14.599 / 14.124 Gbit/s | 14.361 Gbit/s | 13.780 / 13.433 Gbit/s | 13.606 Gbit/s | 2.487 核 | 0.764 秒/GiB | 2.39 MB |
| AWS-LC | 14.235 / 14.097 Gbit/s | 14.166 Gbit/s | 13.398 / 13.415 Gbit/s | 13.406 Gbit/s | 2.657 核 | 0.828 秒/GiB | 3.24 MB |

Ring 的吞吐点估计分别高 **1.38% / 1.49%**，低于各格 **4.32%–7.73%** 的 CV；本轮不足以证明 Ring 吞吐更高。Ring 的 Client CPU 点估计低约 **6.4%**，按双向业务量归一后低约 **7.7%**，值得在生产 Handler 与 API 混合负载下复核。两种 Client 的完整内容校验均通过。这个测试没有 API/p99 请求，不能据此直接改变生产 crypto provider 默认值。

Ring Client SHA-256 `78bba91a65ebbdabf9601eef6dfb422b4f04f430319df5446def51bb56e56fa7`；AWS-LC Client SHA-256 `c5032295a6ada352606ce237b36a19b6cdf8ac7c8168a3b2d4ef7dd5cfea5836`。原始数据在 `本机临时目录` 和各格 `*-bulk.jsonl`；Server profile 原始数据位于 `本机临时目录` 与 `本机临时目录`。没有修改生产 Client、Server 或系统 sysctl。

## 当前下一步

1. Server profile 和逐 socket drops 归因已完成。当前主要本机 CPU 成本是 AES-GCM 与 Quinn packet buffer copy；本次负载没有使用 GSO/GRO，已有 `recvmmsg` 批量收包。先在隔离环境分别 ablate copy 路径与 crypto backend，保留协议互通、全内容校验和 p99 回归。
2. Ring 的 CPU/GiB 点估计较低，但吞吐差异小于格内 CV；下一步先用生产 Handler 和前台 API 混合负载复核 Ring/AWS-LC，再决定是否增加 HY2 专属 provider 选择。
3. 当前主机 `net.core.rmem_max=4,194,304`，普通进程没有 `CAP_NET_ADMIN`，因此未测试超过实际 8 MiB 的 socket buffer，也未改全局 sysctl。需要更大接收队列时应在独立、有管理员授权的机器上测。
4. 完成本机代码路径对照后，再用相同 Client、Server 和负载复跑 Client → remote node；直连出口与经代理下载分开记录，并对下载内容做完整校验。此前 **remote node → OVH** 直连出口结果不作为 Client → remote node 代理成绩。
