# HY2 protocol-core client 与 Handler 本机回环对照（2026-11-28）

## 目的

固定 Chimera HY2 服务端、协议、负载发生器和请求节奏，只切换客户端实现形态，测量独立 `chimera-hysteria2-core` crate 是否提高数据面吞吐。Handler 端使用 direct-handler benchmark API，跳过完整 `start_scaffold`、DNS 服务、规则、路由和 Controller；因此这组实验比较 Handler/stream wrapper 与裸协议核心，不测完整产品启动路径。该测试对应本机回环能力，不代表物理网卡或公网成绩。

## 固定条件

- 服务端：Chimera Server Hysteria-only optimized release，BBR；二进制 SHA-256 `7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d`。构建源为 Server `[源码快照已省略]` 加本地 `minimal-hysteria` feature 差异；该能力后来进入 Server master。
- Handler 客户端：`chimera-hy2-core-perf-client`，SHA-256 `d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`，5,306,320 bytes。
- 协议核心客户端：`chimera-hy2-protocol-perf-client`，SHA-256 `c5032295a6ada352606ce237b36a19b6cdf8ac7c8168a3b2d4ef7dd5cfea5836`，3,243,872 bytes；Cargo normal dependency graph 含 `chimera-hysteria2-core`、Quinn、H3，不含 `clash-lib`、DNS 或 netstack。
- 两个客户端均使用 AWS-LC、4 个共享一个 Endpoint/socket 的 QUIC 连接、socket2 UDP 路径、请求 `SO_RCVBUF=4 MiB`。协议核心客户端启动时读回有效值为 8 MiB；产品配置使用相同请求值。
- 每格运行 30 秒，ABBA 顺序为 Handler、协议核心、协议核心、Handler。负载为 8 条 TCP 流全双工传输，每轮每流上传和下载各 64 MiB，64 KiB 缓冲，内部 TLS 与 TCP_NODELAY；同时保持 4 条 HTTP/1.1 连接，每条每秒发 10 个请求，响应 256 bytes。
- 客户端、服务端、payload 源站和发生器固定在 CPU 0–7。服务端和 payload 源站均为本机回环。

## 结果

表中吞吐为每种客户端两格的中位数；CPU 为两格均值；API 分位数为两格分位数的中位数。

| 客户端形态 | 下载中位数 | 上传中位数 | Client CPU | API p50 | API p95 | API p99 | API 成功 | 二进制大小 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 生产 HY2 Handler | 13.720 Gbit/s | 13.202 Gbit/s | 2.629 核 | 7.143 ms | 21.700 ms | 34.350 ms | 1204/1204 每格 | 5.31 MB |
| 独立 HY2 protocol-core | 13.752 Gbit/s | 13.244 Gbit/s | 2.613 核 | 7.089 ms | 22.799 ms | 37.743 ms | 1204/1204 每格 | 3.24 MB |
| protocol-core 相对 Handler | +0.23% | +0.31% | -0.61% | — | — | — | — | -38.87% |

| ABBA 格 | 客户端 | 下载 | 下载 CV | 上传 | 上传 CV | API p99 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| A1 | Handler | 13.696 Gbit/s | 3.85% | 13.235 Gbit/s | 6.97% | 34.495 ms |
| B1 | protocol-core | 13.684 Gbit/s | 4.57% | 13.176 Gbit/s | 6.88% | 42.437 ms |
| B2 | protocol-core | 13.819 Gbit/s | 5.22% | 13.311 Gbit/s | 6.70% | 33.048 ms |
| A2 | Handler | 13.743 Gbit/s | 5.04% | 13.169 Gbit/s | 6.77% | 34.204 ms |

每格 API 均为 1204/1204 成功。协议核心客户端在两格前均通过 1 MiB 双向全内容校验。各格吞吐波动为 3.85%–5.22%（下载）和 6.70%–6.97%（上传），远大于两形态的中位数差异；因此这组数据支持“吞吐相同”，不支持“精简 crate 提高吞吐”。协议核心版把发布二进制缩小约 39%，但没有 measurable data-plane gain。

压测期间 Linux UDP socket drop 计数非零，系统 `Udp RcvbufErrors` 每格增加约 1.46 万–2.40 万。完整校验 smoke 与 HTTP 请求均成功，但这些队列丢弃说明该结果受本机回环和 UDP 接收队列压力影响；不能把它解释成公网丢包率。

## 客户端热点采样

另用带 debug symbols 和 frame pointers 的 optimized build 单独采样 45 秒。该构建只用于 perf，不用于上表吞吐。49 Hz `cycles:u` 采样约 7K 个样本，丢失 0 个：

| 自身采样符号/调用路径 | 样本占比 | 说明 |
| --- | ---: | --- |
| `__memmove_avx_unaligned_erms` | 18.35% | 最大客户端热点；含 Quinn 包数据复制路径 |
| `_aesni_ctr32_ghash_6x` | 18.08% | AWS-LC AES-GCM 硬件路径 |
| `aws_lc_0_47_0_aes_hw_encrypt` | 3.30% | AWS-LC AES 子路径 |
| `aws_lc_0_47_0_gcm_gmult_clmul` | 2.42% | AWS-LC GHASH 子路径 |
| Quinn `Connection::populate_packet` | 2.42% | QUIC 组包自身采样 |
| Quinn `Connection::poll_transmit` | 1.44% | QUIC 发送调度自身采样 |

memmove 的调用链中，Quinn `StreamsState::write_stream_frames` 占总样本约 5.7%。锁定的 Quinn 0.11.19 源码在 `src/connection/streams/state.rs` 中从 stream send buffer 取数据后调用 `buf.put_slice(data)`，把 stream payload 复制到待加密的 QUIC packet buffer。AWS-LC AEAD 和 Quinn 组包也出现在服务端先前独立采样中；这说明优先级应放在 QUIC/加密/包缓冲路径，而不是 DNS、规则或启动配置。

## Linux GSO/GRO 实际调用检查

在同一台机器的 Client、Server 实际进程上各做一次 `strace`，过滤 `setsockopt`、`sendmsg`、`recvmmsg`。固定 loopback HY2 Server，4 个共享 Endpoint 的 QUIC 连接，8 路并发 TCP 全双工和完整内容校验。该短跑仅检查内核调用路径，启用 `strace` 会改变时序，因此不用于吞吐对比。

| 端点 | `UDP_GRO` setsockopt 成功 | `UDP_SEGMENT` 能力探测成功 | 被跟踪的发送调用 | 发送 GSO cmsg | 被跟踪的 `recvmmsg` | 接收 GRO cmsg |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chimera Client | 2/2 | 1/1 | 10,237 `sendmsg` | 0 | 6,007 | 0 |
| Chimera Server | 2/2 | 1/1 | 9,399 `sendmsg` | 0 | 4,707 | 0 |

两端的 `UDP_GRO` 和 `UDP_SEGMENT` socket-option 调用均返回 0，说明内核接受了选项/能力探测；不过两端发送都没有带 `UDP_SEGMENT` 控制消息，接收也没有 `UDP_GRO` 控制消息。因此本轮观察到“GSO/GRO 能力可用”，没有观察到实际分段卸载或接收合并。`recvmmsg` 本身仍在批量收包：Client 成功调用平均每次取回 1.68 个 UDP 数据报（最大 15），Server 平均 2.10 个（最大 24）。这与 GRO 不同，是一次系统调用返回多个独立数据报。

当前 Quinn Linux transport 会尝试开启 UDP_GRO；`quinn-proto` 的 `poll_transmit` 只有在一次待发内容包含多个 MTU 段时才设置 `Transmit.segment_size`，`quinn-udp` 随后才会带 `UDP_SEGMENT` cmsg。现有回环工作负载在抓取期间每次 Transmit 都没有形成这种合批。由此不能推断远端线路或更长的批量发送永远不会触发 GSO/GRO，但也不能把它们列为当前本机测试已用上的吞吐优化。

本轮完整校验成功 7 条；原始 trace 在 `本机临时目录`。失败的初次跟踪尝试由于 TCP 端口仍在 TIME_WAIT，未纳入统计。

## 判断与下一步

1. 精简 crate 已经实现了依赖隔离：其 normal dependency graph 不含 `clash-lib`、DNS 或 netstack，发布二进制缩小约 39%；这不等于吞吐优化本身。
2. direct Handler 与裸协议核心吞吐在本轮分辨率内相同，暂不把 `ChainedStream`、SOCKS bridge 或 Handler 层认定为主要吞吐瓶颈。由于 Handler harness 没有启动完整 runtime，本实验不能判断 DNS/规则/Controller 的启动开销，也不能把它们作为已验证的无影响项。
3. 下一轮应分别验证 Quinn `put_slice` 包复制和 AWS-LC AEAD 的成本。GSO/GRO 的 socket capability 已确认，但这组负载没有触发 GSO/GRO cmsg；若要优化它，应先找出能稳定产生多段 Transmit 的调度/批量条件，再做隔离 ablation。对 Quinn 传输源码做改动前，先在隔离副本验证；协议/传输属于 L2，需要独立审查及回归/互通证据。
4. API p99 的两次协议核心结果为 42.437/33.048 ms，Handler 为 34.495/34.204 ms；只有两格，不能据此认定核心版尾延迟更差。

## 可复查原始产物

- ABBA 逐格记录：`本机临时目录`
- 逐轮业务速率：同目录 `*-bulk.jsonl`
- Client perf 数据：`本机临时目录`
- Client perf 计数器：`本机临时目录`
- 采样客户端 SHA-256：`72a5a49ee58461deb0eafb7714096b89cb9cc156c378d30d158a745d2e9dcf7d`

## 生产 Handler 的 Ring 与 AWS-LC 混合负载复测

为确认 protocol-core 的加密后端差异能否在生产 HY2 Handler 和网页/API 小请求中复现，使用同一 direct-handler benchmark binary 分别以 `ring` 和 `aws-lc-rs` feature 构建。两者都从当前 Client 工作区 HEAD `[源码快照已省略]` 加本地未提交改动构建；Ring 二进制 SHA-256 为 `fa7f48f7694dd8aafb7fa654b178bf240507b18749087c8a23f9a3c7e6fa99ec`，大小 4,450,032 bytes；AWS-LC 二进制 SHA-256 为 `ab9d9cd9b12de05dfaf1d6548d8d44f993200e40f4b2573444c4b94dac71df2e`，大小 5,306,320 bytes。Cargo feature graph 确认 Ring 构建不含 `aws-lc-rs`；AWS-LC 构建由 Chimera 显式安装 AWS-LC provider。

固定 Chimera Server loopback binary、payload 源站、证书、发生器和 Handler 配置。Server 当前 master 为 `[源码快照已省略]`；该二进制由 `[源码快照已省略]` 加 `minimal-hysteria` feature 差异构建，SHA-256 为 `7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d`。Client、Server、源站和负载发生器均限制在 CPU 0–7。

每格先跑 4 路各上传/下载 1 MiB 的完整内容校验，再运行 15 秒混合负载：HY2 使用 4 个 QUIC 连接；后台有 8 条 TCP/TLS 全双工流，每流配置上传和下载各 64 MiB；前台有 4 条持久 TLS 连接，每条按 10 requests/s 请求 256-byte 响应。API 证书校验关闭，因为本地测试证书已过期；数据加密仍由 TLS 执行。此 direct Handler harness 使用生产 HY2 出站 Handler，但跳过完整 runtime、DNS 服务、规则/路由和 Controller 启动。

四格 Ring → AWS-LC → AWS-LC → Ring 完成两轮，各后端有效样本 4 格。表中每格吞吐为发生器测量记录的中位数；下方后端汇总为 4 个格中位数的中位数，CPU 和延迟同样按格取中位数。

| 后端 | 下载 Gbit/s | 上传 Gbit/s | API p50 | API p95 | API p99 | Client CPU | Server CPU | API 成功数 | 平均系统 UDP `RcvbufErrors`/格 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ring | 14.493 | 13.501 | 6.499 ms | 22.837 ms | 36.598 ms | 2.492 核 | 2.531 核 | 2400/2400 | 19,015 |
| AWS-LC | 14.049 | 13.238 | 6.473 ms | 22.133 ms | 33.273 ms | 2.621 核 | 2.465 核 | 2400/2400 | 10,599 |
| Ring 相对 AWS-LC | **+3.16%** | **+1.99%** | +0.40% | 慢 3.18% | 慢 9.99% | **少 4.90%** | 多 2.66% | — | 多 79.4% |

| 格 | 后端 | 下载 Gbit/s | 上传 Gbit/s | API p95 | API p99 | Client CPU | 系统 UDP 接收错误增量 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1 | Ring | 15.011 | 13.721 | 22.09 ms | 31.28 ms | 2.460 核 | 21,401 |
| B1 | AWS-LC | 13.849 | 13.272 | 22.89 ms | 32.65 ms | 2.624 核 | 10,041 |
| B2 | AWS-LC | 14.061 | 13.336 | 22.62 ms | 30.16 ms | 2.641 核 | 12,605 |
| A2 | Ring | 14.315 | 13.301 | 21.11 ms | 41.47 ms | 2.497 核 | 14,878 |
| A1 | Ring | 14.569 | 13.617 | 24.62 ms | 42.07 ms | 2.487 核 | 25,004 |
| B1 | AWS-LC | 14.154 | 13.204 | 20.60 ms | 34.17 ms | 2.613 核 | 10,545 |
| B2 | AWS-LC | 14.037 | 13.022 | 21.65 ms | 33.89 ms | 2.617 核 | 9,205 |
| A2 | Ring | 14.416 | 13.385 | 23.58 ms | 31.73 ms | 2.511 核 | 14,776 |

Ring 在该负载下有较高的吞吐点估计和较低的 Client CPU，但 API p95/p99 没有一起改善；尾延迟比 AWS-LC 高，且 Ring 的 UDP 接收缓冲错误显著更多。每格下载速率 CV 为 4.05%–5.44%，上传 CV 为 5.55%–7.33%；因此 +3.16% 下载差异仍不足以证明稳定优势。此前 protocol-core 单独传输对照中 Ring 与 AWS-LC 的吞吐差异只有约 1.4%–1.5%，也低于单格波动。当前证据支持“Ring 可作为进一步节省客户端 CPU 的候选”，不支持切换产品默认 provider，也不支持宣称 Ring 提升真实网络吞吐。

中间一次复测在 AWS-LC 完整校验时未能建立第 3 个 HY2 连接，SOCKS 连接返回失败；该格未计入性能样本。随后完整 A/B/B/A 中四格均一次通过全内容校验。保留这次失败作为稳定性证据，不把失败格当作低吞吐数据。

系统 UDP `RcvbufErrors` 每格增加 9,205–25,004；读取到的 Client/Server socket 实际接收缓冲均为 8 MiB。该误差与 Server 侧 socket drop 增量较大相符，说明本机 loopback UDP 接收队列仍会丢包，影响吞吐和 API 尾延迟。因此下一步应先解决或控制接收队列丢弃，再扩大 provider 对照；`net.core.rmem_max` 当前上限不能由本测试用户调整，本轮没有修改系统参数。

原始数据：第一轮在 `本机临时目录`，第二轮完整 A/B/B/A 在 `本机临时目录`。失败的中间尝试在 `本机临时目录`。测试只增加/使用 benchmark feature，不改变生产加密 provider 默认值。

### 同条件无代理直连对照

随后停掉 HY2 Client 和 Server，以同一 payload target、发生器、CPU 0–7、8 路双向 TLS 流和 4 条应用层 TLS API 连接做四格直连基线。负载节奏、响应大小、证书验证设置与上面的混合压测一致；直连也先通过完整内容校验。四格各运行 15 秒，共完成 2400/2400 个 API 请求，系统 UDP `RcvbufErrors` 增量为 0。

| 直连格 | 下载 Gbit/s | 上传 Gbit/s | API p50 | API p95 | API p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 24.422 | 24.697 | 0.326 ms | 0.442 ms | 0.556 ms |
| 2 | 23.979 | 24.389 | 0.335 ms | 0.444 ms | 0.564 ms |
| 3 | 23.847 | 24.217 | 0.337 ms | 0.457 ms | 0.551 ms |
| 4 | 24.021 | 24.415 | 0.335 ms | 0.465 ms | 0.577 ms |
| 中位数 | **24.000** | **24.402** | **0.335 ms** | **0.451 ms** | **0.560 ms** |

同一负载下 Ring 达到直连下载/上传中位数的 60.4% / 55.3%，AWS-LC 为 58.5% / 54.2%；这说明同机 HY2 隧道仍有约 40%–46% 的吞吐差距。API p95/p99 相对直连高约 49–65 倍，且代理各格出现 9,205–25,004 个系统 UDP 接收缓冲错误，直连为零。这个结果把当前本机 HY2 路径与源站上限区分开来，但并非公网效率估计：代理路径额外运行 Client、Server、QUIC 与隧道加密；应用 API TLS 的证书校验在两组都关闭，且直连是在代理 A/B 完成后单独运行，未做时间交错配对。

直连四格原始记录位于 `本机临时目录`。此前相同 payload 的 90 秒直连双向基线和 Server/Client receive-buffer 测量见 [HY2 本机回环与直连基线报告](RESULTS_HY2_RCVBUF_2026-11-28.md)。

## 服务端 HY2 Rustls provider 交叉验证

在客户端 provider 对照之后，固定服务端以外的参数，单独切换 Chimera Server Hysteria2 QUIC TLS provider：AWS-LC 基线保持 Server master `[源码快照已省略]`，Ring 消融版从同一干净源码归档构建，只改隔离副本中的 provider 选择。两份隔离测试二进制均为 17,928,160 bytes：AWS-LC SHA-256 `7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d`，Ring SHA-256 `a30e685efefcf2eecdbad2779164a11619c59fa8db4d25b6d2c1407b1c1b5cf1`。

使用两种固定客户端分别做两轮顺序相反的 ABBA/BAAB：

- Chimera production Handler binary SHA-256 `ab9d9cd9b12de05dfaf1d6548d8d44f993200e40f4b2573444c4b94dac71df2e`，使用同一 AWS-LC 客户端配置和 q4。客户端来自 Client HEAD `[源码快照已省略]` 加当时的本地未提交改动。
- 官方 Hysteria 客户端源码标记 `app/v2.14.0`，commit `c2b181e0b0e72b077e4b0b7297735af14d1f9929`，二进制 SHA-256 `0756ac435d941ad6d6ada75e00865f248a5d6c5593dd1495869e8ff49eb81a0d`，使用其默认拥塞设置。它没有与 Chimera 配置相同的 q4 参数，因此只比较同一官方客户端连接两种 Server provider 的差值，不比较两种客户端的绝对吞吐。
- 每格先跑 4 路双向各 1 MiB 的 full-content 校验，再测 15 秒：8 条 TCP/TLS 全双工流，另有 4 条持久 TLS API 连接、每条 10 requests/s、响应 256 bytes。Client、Server、源站与发生器固定 CPU 0–7。
- API 层证书校验关闭；测试流量仍有 TLS 加密。所有服务均绑定本机回环，结果不是公网或物理网卡成绩。

每个客户端/provider 组合有 4 格；吞吐、CPU、延迟均为格级中位数的中位数。每格 600/600 API 成功，并通过完整内容校验。

| 固定客户端 | Server provider | 下载 Gbit/s | 上传 Gbit/s | Client CPU 核 | Server CPU 核 | API p95 | API p99 | 系统 UDP `RcvbufErrors` 中位数/格 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Chimera Handler q4 | AWS-LC | 14.059 | 13.223 | 2.608 | 2.472 | 22.175 ms | 37.280 ms | 11,840 |
| Chimera Handler q4 | Ring | 14.515 | 13.870 | 2.670 | 2.315 | 18.559 ms | 31.195 ms | 10,929 |
| 官方 Hysteria 2.14.0 | AWS-LC | 3.696 | 5.852 | 1.951 | 1.105 | 11.207 ms | 22.735 ms | 0 |
| 官方 Hysteria 2.14.0 | Ring | 3.878 | 6.430 | 2.007 | 1.100 | 11.510 ms | 21.455 ms | 0 |

相对同一客户端下的 AWS-LC Server，Ring Server 的 Chimera 客户端吞吐高 3.24%/4.89%（下/上行），Server CPU 少 6.36%；官方客户端下高 4.94%/9.89%，Server CPU 基本持平。方向一致的吞吐提升在第二种客户端上也复现，因此这是服务端 provider 候选，而不是只对 Chimera Client 生效。

延迟证据没有同样一致：Chimera 客户端 API p95/p99 中位数约低 16%；官方客户端 p95 约慢 2.7%，p99 约快 5.6%。Chimera 组的总系统 UDP 接收错误中位数略低，但丢弃从 Server socket 向 Client socket 转移：Ring 的 Client/Server socket drops 中位数分别为 4,463/6,608，AWS-LC 为 2,568/8,955。官方客户端组两种 provider 都没有 socket drops。不能据此声称 Ring 在所有工作负载下改善尾延迟或丢包。

同条件无代理直连为 24.000/24.402 Gbit/s 下/上行；Ring Server 分别达到直连中位数的 60.5%/56.8%，AWS-LC 为 58.6%/54.2%。服务端 provider 只解释了其中一小部分本机差距。前一轮 Server perf 采样中 AWS-LC GCM decrypt 路径占总用户态样本约 10.76%，与这次吞吐方向一致，但还没有 Ring 对照 perf profile，不能把全部收益归因成单一 AES 子函数。

性能 A/B 使用的 Ring Server 是隔离副本中的强制 Ring 消融二进制 `[源码快照已省略]...`；它证明在本轮 P-256、无客户端证书指纹的配置下 Ring 的可测数据路径表现。随后把实现收敛为兼容性更安全的本地候选：仅 Hysteria2 可使用 Ring；未配置客户端证书指纹且 Ring 能加载服务端私钥时选择 Ring，否则回退 AWS-LC。因而启用 TLS 客户端证书指纹验证或使用 Ring 不支持的密钥类型（如 P-521）时仍走 AWS-LC。通用 TLS/QUIC 与 TUIC 保持 AWS-LC。该最终源码构建的 `minimal-hysteria` release 二进制 SHA-256 为 `63aa52a56003f7311de93d41547a34f05e27611653ef8126eb40f3019ff5e4be`，大小 17,929,808 bytes；官方 Hysteria 与 Chimera Handler 分别通过 full-content smoke（校验记录 47/50）。最终候选没有重跑性能矩阵，所以表中性能数字仍归属于前述隔离 Ring 消融版，不应当作最终源码二进制的直接 A/B 结果。新增四项单测覆盖 HY2 的 Ring 选择、证书指纹回退、P-521 回退以及通用配置保持 AWS-LC；TUIC stream/datagram E2E 也通过。Server 改动仍是本地未提交候选，尚未进入 remote node/WAN 测量。

原始数据：Chimera 客户端两轮分别在 `本机临时目录` 与 `本机临时目录`；官方客户端两轮分别在 `本机临时目录` 与 `本机临时目录`。最终 Server 源码构建及两种客户端 smoke 位于 `本机临时目录` 与 `本机临时目录`。

## Client/Server CPU 拓扑与 SMT 调度对照

此前回环矩阵把 Client、Server、payload、API 源站和发生器都限制在 CPU 0–7。`lscpu` 显示 CPU 0–7 是 8 个物理核的首线程，CPU 8–15 是对应 SMT sibling。为判断进程争用是否扭曲本机结果，本轮固定 Client、payload、证书、8 路全双工 TLS、q4、前台 API 负载和 Server 二进制，只改变进程可运行的 CPU 集合。Server 对照为 AWS-LC master binary `7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d` 与本地兼容 Ring candidate `63aa52a56003f7311de93d41547a34f05e27611653ef8126eb40f3019ff5e4be`；Client SHA-256 `ab9d9cd9b12de05dfaf1d6548d8d44f993200e40f4b2573444c4b94dac71df2e`。

每个 CPU profile 做两轮顺序相反的 ABBA/BAAB；每个 profile 的每种 provider 有 4 个 15 秒性能格。每格执行 1 MiB 全内容校验和 8 路双向业务流，同时发 4 条持久 TLS API 连接、每条 10 requests/s、256-byte 响应。API 证书校验关闭，传输仍为 TLS。Client、Server、源站与发生器均为本机回环。

| CPU profile | Client/发生器 CPU | Server/payload/API 源站 CPU | Server provider | 下载 Gbit/s (CV) | 上传 Gbit/s (CV) | API p95/p99 | 系统 `RcvbufErrors` 中位数 | Client/Server socket drops 中位数 | Server CPU 核 |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 共享物理核 | 0–7 | 0–7 | AWS-LC | 9.740 (2.01%) | 8.831 (3.51%) | 27.91/42.47 ms | 14,190 | 6,346/7,117 | 2.40 |
| 共享物理核 | 0–7 | 0–7 | Ring | 9.905 (3.31%) | 8.948 (4.90%) | 27.60/43.80 ms | 15,191 | 8,641/6,180 | 2.29 |
| 共享 SMT | 0–15 | 0–15 | AWS-LC | 9.651 (0.88%) | 8.895 (0.40%) | 11.40/16.61 ms | 15 | 0/0 | 3.48 |
| 共享 SMT | 0–15 | 0–15 | Ring | 10.236 (0.37%) | 8.907 (0.88%) | 10.52/15.21 ms | 13 | 13/0 | 3.41 |
| 分核同线程数 | 0–3 | 4–7 | AWS-LC | 9.966 (2.43%) | 8.761 (6.45%) | 35.52/81.21 ms | 1,807 | 1,210/919 | 2.06 |
| 分核同线程数 | 0–3 | 4–7 | Ring | 10.415 (1.15%) | 9.111 (0.78%) | 38.56/66.30 ms | 1,610 | 1,237/569 | 2.05 |
| 分核并启用 SMT | 0–3, 8–11 | 4–7, 12–15 | AWS-LC | 10.698 (0.70%) | 9.988 (0.71%) | 20.59/32.18 ms | 795 | 301/554 | 3.25 |
| 分核并启用 SMT | 0–3, 8–11 | 4–7, 12–15 | Ring | 11.125 (0.97%) | 9.789 (4.44%) | 19.79/32.36 ms | 706 | 319/261 | 3.08 |

所有 32 格均通过完整内容校验和 600/600 API 请求。分核并启用 SMT 的吞吐比共享 SMT 高约 9%–12%，但 API p95 高约 81%–88%、p99 高约 94%–113%；两个分核 profile 的接收 drop 低于共享物理核 profile，但低 drop 并未保证更好的交互尾延迟。分核同线程数相对共享物理核只有小幅吞吐变化，却显著抬高 API p95/p99。由此，本机压测不应把 Client 与 Server 固定到互斥核组；对所有压测进程开放 CPU 0–15 的共享 SMT profile，在当前测试中得到最好的 API 尾延迟和几乎为零的 UDP 接收错误。它没有稳定提升总吞吐，不能视为生产代码优化。

Ring/AWS-LC 的相对差异也随 CPU profile 变化：共享 SMT 下 Ring 下载高 6.06%，上传仅高 0.13%，API p95/p99 约低 8%；共享物理核下吞吐优势约 1%–2%；分核 profile 的上传方向和 API 尾延迟则不一致。结合 profile 间差异，这组数据不足以宣称 Ring 在任意调度环境下有固定吞吐收益。

随后在相同 CPU 0–15 与相同负载下跑了 4 格无代理直连控制：下载/上传中位数为 **20.611/20.988 Gbit/s**，API p95/p99 为 **0.919/1.320 ms**，无 UDP receive-buffer errors；4 格共 2,400 个 API 请求全部成功并通过完整内容校验。共享 SMT 下代理约为直连速率的 47%–50%（下载）和 42%（上传），源站不是代理成绩的吞吐上限。当前直连低于先前 CPU 0–7 的 24.000/24.402 Gbit/s；本轮运行时桌面远程控制进程约占 0.52 CPU，且 CPU 频率/其他负载与旧批次不同，因此跨批次差值不能归因于代码。

全部 32 个代理格、4 个直连格共 21,600 个 API 请求无失败。代理数据位于 `本机临时目录,a2-shared,b1-split,b2-split,c1-split-equal,c2-split-equal,d1-shared-smt,d2-shared-smt}/summary.json`；本轮直连记录在 `本机临时目录`。临时 runner 是原 provider A/B runner 的本机副本，没有改动仓库压测脚本或生产 CPU 亲和性配置。
