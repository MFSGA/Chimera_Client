# Chimera 传输性能迭代计划

本计划依据同一任务内形成的《Chimera 高性能传输设计：从 meow-rs 学什么，先改哪里》，并将其拆分为可独立验证的代码迭代。目标是在保留协议互通与切网行为的前提下，逐步缩小 HY2 上传、下载和繁忙时延与 meow、官方客户端的差距。

## 迭代原则

- 每一迭代只改变一个数据面因素，先回环验证，再测真实线路。
- 使用相同客户端/服务端对端、拥塞控制、会话数、负载、CPU 亲和性和构建类型。报告上传、下载、CPU 秒/GiB、完成率、内存和前台请求 p95/p99。
- 以内容完整校验和为准。测试超时、失败轮及实际活动 QUIC 会话数均进入结果，不只比较成功轮峰值。
- 协议与路径修改至少为 L2。外部 Xray 行为按仓库固定基线复核，保留回退路径。

## 阶段计划

| 阶段 | 工作项 | 主要代码所有者 | 验收条件 | 状态 |
|---|---|---|---|---|
| 0 | 稳定基准，分别核对默认配置与固定会话/拥塞控制配置 | 测试工具与客户端/服务端 | 回环和 bsy 分组；逐轮完整校验；记录 CPU、完成率、会话数及混合负载 p95/p99 | 已有回环结果，bsy 有效吞吐待补 |
| 1a | 解除 Brutal 丢包回调重入锁；以 ACK 字节和丢失字节计算补偿比例 | Client HY2 congestion controller | 定向单测；受控丢包下连接继续交付；Brutal 前后吞吐、延迟和恢复行为无回退 | 代码与单测已完成，受控丢包运行验证待做 |
| 1b | 修正 HY2 上下行速率独立解析及认证协商 | Client converter、HY2 auth/controller | 仅上行、仅下行、双向和 auto 四组行为对齐固定官方实现 | 代码及定向验证完成 |
| 2 | 普通直连将已按路由/网卡/mark 选出的 UDP socket 原生交给 Quinn | Client connector、HY2 建连 | 对照通用适配器提升吞吐并降低 CPU；覆盖切网、保护、代理链、混淆和平台回退 | Linux 回环 A/B 显著改善上传和 CPU；组合兼容与 bsy 远端待补 |
| 3 | HY2 连接、认证、驱动、取消及路径代际收敛为单个会话所有者 | Client HY2 lifecycle | 并发冷启动只产生必要握手；切网后旧槽不能复用；取消、重连及 UDP 亲和性通过 | 待执行 |
| 4 | 添加可选 K=1/2/4 QUIC 会话池，懒建、轮询分配、故障降级 | Client HY2 pool | K=1 保持旧语义；记录实际连接数、认证、用户计量、单流及多流结果；混合负载没有明显尾延迟回退 | 待执行 |
| 5a | 服务端 HY2 下行采用拥有缓冲区的写入以消除一次复制 | Server TCP→H3→QUIC 写入 | 单变量 10 对复测；完整覆盖部分写、短读、背压、取消、EOF、计量和半关闭 | 有原型数据，需收窄为独立补丁 |
| 5b | 定位服务端单会话发送驱动的等待来源并优化主要等待阶段 | Quinn 驱动/发送路径 | 等应用、流控、拥塞窗口、加密和 socket 的分项时间；队列/批处理 A/B 达到吞吐目标且尾延迟、丢包和内存不过线 | 待归因 |
| 6 | REALITY/Vision、WS 与 XHTTP/H2/H3 的跨客户端对照及混合负载验收 | 各传输 owner | 固定协商与请求参数；先完成 Xray 互通，再提交性能比较；记录 API p95/p99 和完成率 | 部分回环数据，互通矩阵待补 |
| 7 | 真实 bsy 线路复核最终候选并交付结果表 | Client + Server | 直连与 CDN 分组；源站在出口侧；通过内容校验；公开逐轮摘要、版本、环境和不确定性 | 待执行 |

## 本轮执行记录

**阶段 1a，风险 L2。**

- 目标：Brutal 的同步丢包回调不再从 Quinn 连接驱动持锁区间内反向读取同一连接统计；拥塞补偿仍依据实际 ACK 与丢失数据字节。
- 非目标：本轮不修改带宽配置解析、UDP socket 适配器、QUIC 会话池或服务端转发。
- 边界与所有者：`clash-lib/src/proxy/hysteria2/congestion.rs` 的 `Brutal` 状态和回调。
- 实际验证：`cargo fmt --all`、`cargo fmt --all -- --check` 通过；`cargo test -p clash-lib --all-features --lib proxy::hysteria2::congestion::tests` 通过，6 个测试。普通 feature 组合下测试模块未编译入目标，因此使用 all-features 明确覆盖 HY2。受控丢包实际连接验证尚未运行，不能宣称运行期死锁已实测排除。此任务不启动系统路由/TUN 测试。
- 回退：恢复 `Brutal` 回调和字段，默认 BBR 路径不受本项影响。
- 外部基线：Chimera Client `c450cf8e`；参考 Hysteria 源码提交 `c2b181e0`。本项仅改变内部 Brutal 采样方式，不改变线协议。


**阶段 1b，风险 L2。**

- 独立保存上行和下行配置，单方向限速不再因 zip() 被丢弃；认证请求按下行限速生成 Hysteria-CC-RX。
- 依据固定的 Hysteria 客户端参考规则，服务端选择 auto 时保留客户端配置的拥塞控制；固定速率时采用服务端接收速率与客户端发送上限中的较小值，缺省/零值按官方行为处理。
- 实际验证：cargo fmt --all -- --check、cargo clippy -p clash-lib --all-targets --all-features -- -D warnings 通过；cargo test -p clash-lib --all-features --lib hysteria_ 9 个通过，配置转换用例 cargo test -p clash-lib --all-features --lib convert_hysteria2_config 1 个通过。未运行真实网络 Brutal/auto 组合。
- 本轮未改变协议字段格式或带宽输入单位，仍使用现有配置解析后得到的数值。


**阶段 2，风险 L2。状态：Linux 回环性能验收通过；完整兼容验收未完成。**

- 目标：普通直连 HY2 复用现有网络路径选择和 UDP socket 创建，再把同一 socket 交给 Quinn，跳过通用 Stream/Sink 数据报适配器。
- 非目标：不改 QUIC 拥塞控制、流控窗口、会话池、HY2 wire/auth、服务端转发和其他客户端协议。
- 边界：proxy_connector 定义 Quinn socket opt-in 与路径健康观测；direct connector 共用原 UDP socket 选择逻辑；HY2 只在 connector opt-in 时走原生 socket。其他 connector 保留旧适配器，端口跳跃继续走 UdpHop。
- 兼容性：保留 source/interface/SO_MARK、路径代际检查和路径健康证明；Tokio UDP socket 转成 std socket 后交给 Quinn TokioRuntime。Salamander 仍包装最终 socket。撤销本阶段提交可恢复旧路径。

**实测条件与版本**

- 客户端基线为 Chimera Client afba9086e574cc6cdb6f52d74a0f60e1923df798，版本 clash-rs 0.29.1；候选从同一提交构建。基线和候选 release 二进制 SHA-256 分别为 0f9d21fe6f60a4d37870be55f1335703e844f3bc33cffd97d9cf88ddad4b9c63 和 e22629c21248c49ccc774d8571048d3217f483229a5afa036a44a4f9837d9496。
- 服务端来自本机 Chimera Server 提交 3c636e4a0ba24de6b0fdf85d283d05ab366d3291，版本 chimera-server 26.10.26。该 Server 本机 master 比当时的 origin/master 35f970d9f5fd687e3191b2fa5d08984fed928df9 超前 13 个提交，不代表远端 master 的服务端版本。
- 主机为 Linux 6.18.35 x86_64、AMD Ryzen 7 5800、16 逻辑 CPU、performance governor。客户端和服务端均为 release 构建，10 对测试交替先后顺序。
- 服务端 Hysteria2 配置声明 10000 mbps 上下行；每个客户端进程先预热 16 MiB，再以一个 SOCKS TCP 流上传 512 MiB、下载 512 MiB。源站和代理服务端均在同机 loopback，不使用 Docker。
- 客户端 mode 使用 rule，规则为 MATCH,hy2。错误认证预热会断流；debug 记录确认正式连接选中 hy2、ALPN=h3、服务端认证成功。服务端 Xray 兼容策略默认拒绝 Hysteria2 访问私网目标，测试 Freedom 仅显式允许 127.0.0.0/8。20/20 轮均通过上传内容检查和下载 SHA-256 校验，成功率 100%。
- 逐轮 JSONL 结果：bench/results/hy2-native-udp-loopback-2026-11-21.jsonl。早期 mode=global 的初测允许错误认证仍完成传输，说明请求绕过了代理；该批数据全部排除。改为 mode=rule 并通过错误认证负向检查后才开始正式测量。

**正式结果**（吞吐为十进制 Mbps；CPU 秒/GiB 按上下行合计 1 GiB 数据计算）

| 指标 | 旧适配器中位数（范围） | 原生 socket 中位数（范围） | 配对中位变化 |
|---|---:|---:|---:|
| 客户端上传 | 1004.5（701.9–1027.3） | 3228.2（2651.4–3413.7） | +227.9%（+159.6%–+358.2%） |
| 客户端下载 | 2924.4（962.7–3086.3） | 3137.6（2691.4–3224.3） | +6.4%（−7.4%–+214.0%） |
| 客户端 CPU | 7.49 秒/GiB（7.35–8.83） | 2.51 秒/GiB（2.37–2.78） | −67.8%（−71.4%–−62.3%） |
| 服务端 CPU | 3.97 秒/轮（3.87–5.27） | 2.09 秒/轮（2.01–2.44） | −46.9%（−60.4%–−39.2%） |

下载配对差值范围较宽，有一轮基线低值（旧适配器 962.7 Mbps、原生 socket 3022.5 Mbps）；不据此单独宣称下载大幅提升。回环单流的可靠结论是上传中位数约提升至 3.21 倍，客户端 CPU/GiB 约下降 68%；下载中位数约提升 7%，但收益较小且轮间离散。

| 配对轮次 | 旧适配器上传 | 原生 socket 上传 | 旧适配器下载 | 原生 socket 下载 | 客户端 CPU 秒/GiB：旧→新 |
|---:|---:|---:|---:|---:|---:|
| 1 | 1027 | 3414 | 3086 | 3217 | 7.36 → 2.37 |
| 2 | 1000 | 3363 | 2967 | 3205 | 7.46 → 2.39 |
| 3 | 1021 | 2651 | 2803 | 2929 | 7.37 → 2.78 |
| 4 | 1016 | 3048 | 2443 | 3033 | 7.67 → 2.67 |
| 5 | 702 | 3216 | 1084 | 3124 | 8.83 → 2.52 |
| 6 | 1008 | 3359 | 3010 | 3181 | 7.52 → 2.40 |
| 7 | 965 | 3301 | 3076 | 3224 | 7.45 → 2.41 |
| 8 | 1002 | 3240 | 963 | 3023 | 8.60 → 2.51 |
| 9 | 1007 | 3144 | 2942 | 3151 | 7.35 → 2.53 |
| 10 | 970 | 2971 | 2907 | 2691 | 7.53 → 2.76 |

**验证与剩余范围**

- 通过：cargo fmt --all -- --check；CARGO_TARGET_DIR=/tmp/chimera-client-hy2-native-target cargo test -p clash-lib --features hysteria --lib proxy::utils::proxy_connector::direct_connector::tests:: -- --test-threads=1（34 passed）；CARGO_TARGET_DIR=/tmp/chimera-client-hy2-native-target cargo clippy -p clash-lib --all-targets --features hysteria -- -D warnings；cargo check -p clash-lib --features hysteria --lib；基线/候选客户端 release 构建；Server release 构建；10 对双向校验。
- 未通过或未执行：all-features native_quinn 测试构建受缺失 clash-dashboard/dist 阻断；no-default-features hysteria 检查触发仓库已有 dead-code warnings。未运行 Windows/macOS、bsy/WAN、延迟/丢包、TUN 切换、显式网卡/mark、代理链、Salamander、端口跳跃或 HY2 UDP 应用负载。
- 实际构建与测量命令：

      CARGO_TARGET_DIR=/tmp/chimera-client-hy2-native-target cargo build --release -p clash-rs --no-default-features --features standard,aws-lc-rs
      cargo build --release --bin chimera_server_app
      python3 /tmp/chimera-hy2-native-bench.py --server /home/si/Desktop/mfsga/Chimera_Server/target/release/chimera_server_app --base /tmp/chimera-hy2-native-bench/base-clash-rs --native /tmp/chimera-hy2-native-bench/native-clash-rs --pairs 10 --bytes 536870912 --out /tmp/chimera-hy2-native-valid/results.jsonl
- 已尝试但未通过的命令：

      CARGO_TARGET_DIR=/tmp/chimera-client-hy2-native-target cargo test -p clash-lib --all-features --lib native_quinn
      cargo check -p clash-lib --no-default-features --features hysteria --lib

  第一条缺少内嵌 Dashboard 构建产物；第二条被现有 DNS/TLS dead-code warnings 阻断。本次标准 hysteria feature 下的定向编译、测试和 Clippy 均通过。
- 独立 L2 Reviewer 检查实际 diff 和测量设置，未发现阻塞性 correctness 问题，建议推送至 codex/hy2-native-udp 供维护者审查。Reviewer 结论不等于维护者批准，也不授权并入 master。
- 下一步继续验证新 socket 下的多网卡/mark、切网、混淆与端口跳跃，再用 bsy 线路复测。阶段 2 的组合兼容和远端结果补齐前，不标记为完全完成；随后进入阶段 3 的会话所有者、取消与重连问题。

**阶段 2 补充：Salamander 收包正确性及回环对照，风险 L2。**

- 客户端基线为 `f599e19a08dd302132dcc860443fd2dc690effe1`；候选在此基础上修改 `clash-lib/src/proxy/hysteria2/salamander.rs`。基线和候选 release 二进制 SHA-256 分别为 `e22629c21248c49ccc774d8571048d3217f483229a5afa036a44a4f9837d9496` 和 `d657f6b89ca7f43609a65e9c99cf430edeb69d0837f275859dae22bf1c1217fa`。
- 根因：旧实现会缩短可复用的接收切片，后续较大数据报可能被截断或导致错误；它还把 GRO 聚合后的多段当成一段解混淆，且未将底层 GRO 接收容量告知 Quinn。修复保留切片容量、逐段解混淆并压紧数据，同时为每段盐预留 8 字节。
- Quinn 0.11.12 当前按最大 UDP payload 与 `max_receive_segments` 的乘积分配接收区，且前者至少为 1200 字节。包装器以保守的段数上界预留盐空间，不改变 QUIC 通告参数；升级 Quinn 时必须重跑真实 endpoint 缓冲分配测试。`ConnectorUdpSocket` 对异常超大包返回错误并可能终止 endpoint 的既有问题单列，不纳入本项已修复范围。
- 参考 `ref/` 的同路径实现已处理 GRO 分段，但未传递 `max_receive_segments`；本轮额外保留无效数据报计数以维持 Quinn 的工作量限制，并覆盖缓冲复用。候选 worktree 的参考子模块未检出，固定 gitlink 为 `39d06a49`；只读比较使用主检出参考目录当前 `2f624526`，二者不是同一参考版本。
- 服务端使用 Hysteria 官方 v2.14.0、相同的本地 Salamander 配置。测试机与 CPU 亲和性同上；源站、代理和客户端均在同一 Linux 主机，且每个进程限定 2 个物理核心。每方向合计 128 MiB，先预热一次，五对按顺序交替，完整检查内容；以下为每项吞吐中位数和配对变化。结果是固定资源条件下的回环对照，不是不限资源的硬件极限。

| 负载 | 基线上行 / 下行 Mbps | 候选上行 / 下行 Mbps | 上行 / 下行配对中位变化 |
|---|---:|---:|---:|
| 单流 | 1246 / 932 | 1244 / 1268 | +0.95% / +37.58% |
| 8 并发 | 1329 / 905 | 1334 / 1276 | −1.35% / +41.31% |

- 下行五对范围：单流 +34.55% 至 +38.42%，8 并发 +38.30% 至 +43.40%；8 并发上行一对低至 −17.15%，其余轮次和更长负载仍需继续检查。GRO 容量和分段解混淆共同改变，不能把收益归因于其中某一项。
- 通过 8 个普通定向测试，以及显式执行的 Linux 内核 GSO/GRO 测试：内核实际合并四个 1208 字节混淆数据报，解混淆后 4800 字节逐字节一致。官方服务端上，普通 HY2 和 Salamander 的 TCP/UDP 在 `/network/reset` 前后均可用，并观察到重新认证的连接。上述测试未覆盖真正的代理链；该配置的负向对照发现 HY2 `dialer-proxy` 被静默忽略，须作为独立问题处理，不能将此前所谓代理链结果视为有效。
- Linux 上真实底层最多 64 段时，Quinn 每 endpoint 的接收区理论分配从 47,104 字节变为 3,061,760 字节；这是分配量，不等于 RSS。三对 16 节点顺序激活测试确认各自存在 16 个 UDP socket；扣除空闲进程后，候选相对基线 RSS 差值为 −416、1516、2572 KiB，中位 1516 KiB。该短测存在明显波动，不能作为大量节点同时满载的内存上限。
- 通过 `cargo fmt --all -- --check`、`CARGO_TARGET_DIR=/tmp/chimera-client-hy2-native-target cargo test --locked -p clash-lib --features hysteria --lib proxy::hysteria2::salamander::tests -- --test-threads=1`、以及 `cargo clippy --locked -p clash-lib --all-targets --features hysteria -- -D warnings`。真实 GSO/GRO 用例默认忽略，另以 `cargo test --locked -p clash-lib --features hysteria --lib proxy::hysteria2::salamander::tests::native_socket_decrypts_real_gro_segments -- --exact --ignored --nocapture` 实际运行一次并通过。
- 独立 Reviewer 已审查修复思路；最终提交 SHA 仍需重新核验。Windows/macOS、混合负载 p95/p99、模拟丢包、多节点同时满载及实际线路均未验证。回退此项提交可恢复先前收包行为；回退也会恢复前述既有正确性问题。

**HY2 无混淆本地交叉矩阵。**

使用同一主机、相同两物理核心分配和 SOCKS5 入口，每单元预热一次、正式重复三次；单流每方向 128 MiB，8 并发为每流每方向 16 MiB，均做内容校验。客户端包括 Chimera、meow-rs 0.29.0、Mihomo Meta v1.19.33、Hysteria 2 v2.14.0 和 Xray 26.11.9；服务端包括官方 Hysteria、Chimera Server `3c636e4a` 与 Xray。meow 配置固定 `quic-connections: 1`，各单元客户端实际观察到 1 个 UDP socket，官方服务端对应日志各有 1 次认证；其默认配置在另一组测试中建立了 2 个连接，不能将不同会话宽度直接归因于架构。以下为上传 / 下载吞吐中位数，单位十进制 Gbps：

| 服务端 | 客户端 | 单流 | 8 并发 |
|---|---|---:|---:|
| 官方 Hysteria | Chimera | 3.48 / 4.87 | 3.65 / 5.47 |
| 官方 Hysteria | meow K=1 | 1.53 / 3.33 | 1.66 / 4.29 |
| 官方 Hysteria | Mihomo | 3.98 / 4.00 | 4.30 / 4.13 |
| 官方 Hysteria | 官方 Hysteria | 4.61 / 4.40 | 4.23 / 4.25 |
| 官方 Hysteria | Xray | 3.56 / 4.12 | 3.73 / 4.12 |
| Chimera | Chimera | 4.29 / 5.45 | 5.06 / 5.76 |
| Chimera | meow K=1 | 1.54 / 4.32 | 1.55 / 4.17 |
| Chimera | Mihomo | 5.19 / 3.13 | 6.07 / 3.19 |
| Chimera | 官方 Hysteria | 5.22 / 3.42 | 6.26 / 3.38 |
| Chimera | Xray | 4.07 / 2.95 | 5.41 / 2.95 |
| Xray | Chimera | 3.36 / 3.91 | 3.36 / 4.96 |
| Xray | meow K=1 | 1.54 / 3.08 | 1.64 / 3.62 |
| Xray | Mihomo | 3.76 / 2.87 | 4.22 / 3.74 |
| Xray | 官方 Hysteria | 4.04 / 3.44 | 3.93 / 3.62 |
| Xray | Xray | 3.36 / 3.38 | 3.73 / 3.56 |

表中不同客户端的 QUIC 流控和拥塞控制实现仍有差异，不能作为单一实现效率排名。单独的长流重试中，meow→Chimera Server 在 K=1 的 3 次中有 1 次、K=2 的 3 次中有 2 次未能在 8 秒内完成每方向 128 MiB 的预热请求；对应 meow→官方服务端 6 次均完成。日志显示失败轮认证已接受，但故障阶段和根因未确定，不能仅用成功轮吞吐掩盖失败。逐轮数据、二进制哈希和失败记录保存在 `bench/results/hy2-local-cross-2026-11-21.jsonl`；各客户端批次不是同一时间同时运行，数字有机器状态和构建差异。

额外的阶段定位工具不进行内容校验，因此只用于诊断：相同连接上先上传 128 MiB、收到源站确认后再下载 128 MiB，meow K=1 与 Chimera Server 八轮中有两轮在下行约 23.4 MB 后触发 8 秒总超时，官方服务端八轮均完成；失败时客户端与服务端 UDP socket 的丢包计数均为零。失败轮服务端一次 5 秒采样中拥塞窗口为 5808 字节，QUIC 丢包和服务端发送的两类流控阻塞帧增量为零；这是单个时间窗口的观测，尚不能排除其他时间点的丢包、流控或应用调度问题，更不能单凭它断定责任端。独立上传和独立下载各三轮暂未复现，后续应控制接收窗口和拥塞控制做 A/B。
