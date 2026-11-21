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
