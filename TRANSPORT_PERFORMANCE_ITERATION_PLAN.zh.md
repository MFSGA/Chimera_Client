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
| 0 | 稳定基准，分别核对默认配置与固定会话/拥塞控制配置 | 测试工具与客户端/服务端 | 回环和 远端节点 分组；逐轮完整校验；记录 CPU、完成率、会话数及混合负载 p95/p99 | 已有回环结果，远端节点 有效吞吐待补 |
| 1a | 解除 Brutal 丢包回调重入锁；以 ACK 字节和丢失字节计算补偿比例 | Client HY2 congestion controller | 定向单测；受控丢包下连接继续交付；Brutal 前后吞吐、延迟和恢复行为无回退 | 代码与单测已完成，受控丢包运行验证待做 |
| 1b | 修正 HY2 上下行速率独立解析及认证协商 | Client converter、HY2 auth/controller | 仅上行、仅下行、双向和 auto 四组行为对齐固定官方实现 | 代码及定向验证完成 |
| 2 | 普通直连将已按路由/网卡/mark 选出的 UDP socket 原生交给 Quinn | Client connector、HY2 建连 | 对照通用适配器提升吞吐并降低 CPU；覆盖切网、保护、代理链、混淆和平台回退 | 待执行 |
| 3 | HY2 连接、认证、驱动、取消及路径代际收敛为单个会话所有者 | Client HY2 lifecycle | 并发冷启动只产生必要握手；切网后旧槽不能复用；取消、重连及 UDP 亲和性通过 | 待执行 |
| 4 | 添加可选 K=1/2/4 QUIC 会话池，懒建、轮询分配、故障降级 | Client HY2 pool | K=1 保持旧语义；记录实际连接数、认证、用户计量、单流及多流结果；混合负载没有明显尾延迟回退 | 待执行 |
| 5a | 服务端 HY2 下行采用拥有缓冲区的写入以消除一次复制 | Server TCP→H3→QUIC 写入 | 单变量 10 对复测；完整覆盖部分写、短读、背压、取消、EOF、计量和半关闭 | 有原型数据，需收窄为独立补丁 |
| 5b | 定位服务端单会话发送驱动的等待来源并优化主要等待阶段 | Quinn 驱动/发送路径 | 等应用、流控、拥塞窗口、加密和 socket 的分项时间；队列/批处理 A/B 达到吞吐目标且尾延迟、丢包和内存不过线 | 待归因 |
| 6 | REALITY/Vision、WS 与 XHTTP/H2/H3 的跨客户端对照及混合负载验收 | 各传输 owner | 固定协商与请求参数；先完成 Xray 互通，再提交性能比较；记录 API p95/p99 和完成率 | 部分回环数据，互通矩阵待补 |
| 7 | 真实 远端节点 线路复核最终候选并交付结果表 | Client + Server | 直连与 CDN 分组；源站在出口侧；通过内容校验；公开逐轮摘要、版本、环境和不确定性 | 待执行 |

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
