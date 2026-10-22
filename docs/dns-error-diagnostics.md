# DNS 查询失败的错误语义（2026-10-20）

## 基线与目标

- 代码基线：本地 `master` `175befc5eaeb236108e54a42c08dd4d1d7568c1d`；
  固定参考 `ref/` `39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`。
- 用户目标：DNS 全部不可用时不要把上游故障误报为「没有 DNS 记录」；
  多个上游/主 DNS+fallback 失败时保留每条错误原因。
- 本切片不新增后台探测、健康状态 API、自动切换策略或公网互操作。
  不更改已有 DNS 超时上限（并发上游整体 10 秒）。

## 本轮行为

1. `EnhancedResolver::batch_exchange` 仍并行查询配置的上游，
   并在得到可接受的响应时立即结束剩余查询；
   `NOERROR` 与 `NXDOMAIN` 是有效 DNS 响应。
   `SERVFAIL`、`REFUSED` 等其他错误 RCODE 不再计作上游查询成功，
   会继续尝试其他上游。全部失败或超时时，上抛包含域名、记录类型、
   上游身份及失败原因的诊断；未完成的上游注明超时。
2. `lookup_ip` 将 `NXDOMAIN` 与 `NOERROR` 但无 A/AAAA 记录的
   `NODATA` 分开报告；`resolve` 和 `resolve_all` 不再吞掉 A/AAAA
   两个地址族的失败原因。若任一地址族成功得到 IP，仍可立即或在
   完成并发查询后返回该地址。
3. `ip_exchange` 在主 DNS 和 fallback 都失败时保留双方失败原因；
   当主 DNS 返回了无法采用的答复而 fallback 失败，也会显式标明。
   `nameserver-policy` 仍按指定上游处理，未添加未授权的回退。
4. `make_clients` 对多个普通 DNS 上游初始化失败（例如 hostname
   bootstrap）保留每条初始化失败原因；显式 DHCP 的硬错误仍立即返回。
5. 本地 DNS listener 的错误处理仍将最终解析失败转成 `SERVFAIL`，
   Controller `/dns/query` 内部出错时仍按现有 API 返回 HTTP 500；
   此处只改错误准确性，不变更 API 契约。

## 验证及未覆盖事项

- 使用全内存测试客户端模拟多个 upstream 错误、健康服务器、
  `SERVFAIL`、`REFUSED`、`NXDOMAIN`、`NODATA`、
  A/AAAA 均失败、部分地址族成功、主/备用均失败及
  多个 bootstrap 失败。不依赖公网 DNS。
- 核心库、严格 Clippy、最小 feature 和集成 DNS listener 的
  最终验收结果以当前提交的验证日志为准。
- 尚未实现：每上游持续健康快照、故障率/恢复时间指标、独立健康 API、
  Dashboard 诊断页面、真实 DNS 端点全不可达场景的端到端注入。
- **注意**：无法仅凭“请求成功（Fake-IP/hosts/cache 命中）”
  认定上游 DNS 健康；`NXDOMAIN` 是合法负面响应，不代表 DNS
  传输通道已断。当前改动不做此类健康判定。

## 2026-10-21：被动 DNS 健康快照与 Controller API

- 本地基线：`36d330b9584f65d5b18bd0cbe38b2de83c850e04`。
- 新增 `GET /dns/health`（沿用现有 Controller Bearer 认证），
  `enabled=false, status=disabled` 表示当前使用系统 DNS；启用内部 DNS
  时提供 `status`、`passive=true` 和 `groups`。
- 如果某个普通上游在初始化阶段失败、但其余上游仍成功建立 Client，
  失败上游也会作为独立记录出现在所属分组中，不会因跳过初始化而消失。
- `groups[].name` 可为 `main`、`fallback`、`bootstrap`、
  `proxy_server`、`direct`、`policy`；每组上游包含
  `server`、`status`、`successes`、`failures`、
  `consecutiveFailures`、`lastSuccessAt`、`lastFailureAt`、
  `lastError`。时间是 Unix 秒；错误说明最多 512 字符。
- 状态仅根据各 DNS Client 最后一次**真实上游请求**计算：
  `unknown`（还没有充分观测）、`healthy`（近期被动观测成功）、
  `degraded`（部分上游失败或依靠 fallback）、
  `unavailable`（已观测的主/fallback 均失败）。
  `NOERROR` / `NXDOMAIN` 代表 DNS 服务有响应；
  `SERVFAIL` / `REFUSED` / 传输错误 / 批量超时视为失败。
  Fake-IP、hosts、命中 DNS 缓存、只创建 DNS Client、不发请求等
  **不计作 DNS 上游成功**。只读 API 自身也不会发探测包。
- 没有新请求的被动观测在 300 秒后变回 `unknown`，而非无限期保持健康。
  `reset_transports` / 网络路径重置也会将实时状态清回 `unknown`，
  保留历史计数与时间，避免旧路径成功被误认为新路径健康。
  内存状态与 Resolver 生命周期一致，重建配置即重新登记。
- **限制**：`unavailable` 表达最后一次有效被动观测，
  不是实时联网保证；没有请求时保持 `unknown`，不会后台探测。
  辅助 DNS 的异常不会直接判定主 DNS 全部不可用；各组有单独快照。
  当前不增加主动探针、阈值报警、长期持久化、Dashboard 页面，
  不依赖公网互操作。完整测试结果以本轮实际验收日志为准。

## 2026-10-21：仅 IPv4 Fake-IP DNS 完善

- **范围**：仅完成 IPv4 Fake-IP 地址分配、IPv4 PTR、本地 DNS
  响应、Controller DNS 查询以及 `fake-ip-filter` 与非 A 查询的兼容性；
  不接入或修改 IPv6 Fake-IP 池、Fake AAAA、IPv6 路由。
- IPv4 假地址池耗尽会将 `pool exhausted` 错误返回 DNS 调用方，
  不再进入 `unreachable!()`；已分配域名/IP 的映射继续保持稳定。
  `hosts` 仅有非 IPv4 记录时，对 A 查询返回 NODATA
  (`NOERROR` + 空记录)，避免地址族不匹配导致进程 abort。
- `EnhancedResolver::should_fake_ip` 按真实的 Fake-IP 过滤器判断：
  明确被 `fake-ip-filter` 排除的域名，其 TXT/HTTPS/SVCB/MX/SRV 等
  非地址查询按已有 nameserver-policy/上游规则查询；未被排除的
  Fake-IP 域名仍返回空的 `NOERROR`，不会为非 A 查询向上游泄漏域名。
- 对已分配且保存反向映射的 IPv4 假地址，`in-addr.arpa` PTR 查询
  会在本地生成指向原始域名的 PTR 记录；不为 PTR 请求新分配地址。
- 统一普通监听器、TUN DNS 劫持和 Controller 查询的 Fake-IP 规则：
  TUN UDP/TCP 遇到解析器错误返回保留请求 ID 的 `SERVFAIL`，
  不再静默丢弃查询或关闭 DNS TCP 会话；多个 Question 在入口
  返回 `FORMERR`，不会向上游请求。Controller `/dns/query` 的
  Fake-IP A 解析和非 A 拦截语义与普通 DNS 监听器一致。
- 添加全内存测试覆盖：Fake-IP 池耗尽、已有映射重用、过滤域名
  A 和非地址查询、已分配地址的 PTR、本地 `SERVFAIL`、多 Question
  `FORMERR` 与 Controller Fake A 查询；不执行公网 DNS 互操作。
- **限制**：未实现 Fake AAAA 或 IPv6 PTR；被隔离的 Fake-IP 域名
  的 TXT/HTTPS/SVCB 等仍按隐私防泄漏策略空答，而不是通用递归 DNS
  全记录兼容。畸形 DNS 消息在 TUN 入口的解码错误仍可能被丢弃，
  尚未新增长时间 TUN 真实设备验收。最终测试结果以交付的构建日志为准。

## 2026-10-21：TUN DNS 劫持离线报文回归（仅 IPv4）

- 测试不创建系统 TUN 设备、不修改路由表，也不向公网 DNS 查询。
  在 TUN UDP 生产入口提取一小段共用的 `exchange_hijacked_udp_dns`；
  生产分支和离线测试调用**同一个** DNS 解析/错误转换函数。
- UDP 测试利用 `watfaq-netstack::UdpSocket` 的 `SplitWrite` 构造
  真实 IPv4+UDP 数据包，再由 `SplitRead` 检查 IP/UDP 校验和与
  源/目标端口，送入共用 DNS 劫持处理函数后将答复再次封为
  IPv4+UDP 数据包，最后再用 `SplitRead` 校验返回报文。
- 覆盖 Fake IPv4 A 答复、过滤域名 TXT/SRV 真实上游调用、未过滤域名
  HTTPS 防泄漏、上游报错时 `SERVFAIL`、两个 DNS Question 时
  `FORMERR`、请求/回复事务 ID 和地址反向、畸形 UDP DNS 负载。
- TCP 测试让**生产 `handle_tcp_dns` 处理循环**直接接受 Tokio
  `AsyncRead + AsyncWrite` 双向流，在无设备环境验证两字节
  DNS-over-TCP 长度前缀、Fake IPv4 A 答复、`SERVFAIL`、`FORMERR`
  和同一会话多次请求后的可用性；所有响应读取设置超时。
- **边界**：这验证了生产 DNS 劫持函数及真实 netstack UDP
  封解包、TCP DNS framing，不等于端到端运行整个
  `Dispatcher`、smoltcp TCP 建连、内核 TUN 设备和 OS 路由策略。
  这些环节仍属于实际设备验收范围；IPv6 Fake-IP 不包含在本次变更中。

## 2026-10-21：DNS 缓存和多上游否定应答的正确性

- **缓存应答完整性**：修复 ResponseCache 命中后只复制 Answer 的问题；
  现在保留上游成功应答中的 RCODE、AA/RA 标记、Authority、Additional
  以及 hickory 已递减的 TTL，只替换当前请求的事务 ID、Question 和
  RD/CD 标志。不复用旧客户端的 DNS 事务 ID。
- **缓存请求适用性**：hickory ResponseCache 的键仅包含 DNS Question，
  不包含 RD/CD、DNSSEC/EDNS 的上下文。因此目前仅缓存普通 RD=1、
  没有 EDNS/签名和 DNSSEC 请求标志的单 Question 查询及其安全应答。
  EDNS、DNSSEC、RD=0 等请求直接查询上游，避免不同网络/安全上下文
  共享应答。拒绝缓存截断响应、零 TTL 记录及不完整否定响应。
  这些条件侧重正确性，会降低某些高级查询的缓存命中率。
- **否定响应**：NXDOMAIN、NODATA 及 SERVFAIL 不能通过普通正缓存
  保存。NXDOMAIN 和空 NOERROR 仍由上游确定；后续若引入负缓存，
  必须根据 SOA MINIMUM 和 SOA RR TTL 计算 TTL、区分域名不存在与
  特定记录不存在（RFC 2308），不得用通用正缓存默认 TTL 替代。
- **多上游应答冲突**：多个已选定的 DNS 并发查询时，拥有真实 Answer
  的 NOERROR 响应优先于尚在等待的 NXDOMAIN/NODATA。收到首个
  否定应答后给予最多 200ms 的候选响应等待期；如果仍无正答，
  选择配置顺序最靠前的否定答复，避免纯调度竞态。如果只有失败或
  服务器错误，继续按照已有上游错误聚合机制报告。这个有限等待
  是兼顾短暂上游差异和尾部延迟的策略，不保证等待期之后到达的
  正答会被采用；不更改 nameserver-policy/fallback 的路径优先级。
- **验证**：全内存用例覆盖缓存 Authority/Additional/AA/RA/ID、TTL
  递减与过期、EDNS 复用隔离、零 TTL 与 NODATA 不缓存、NXDOMAIN
  不缓存、快速 NXDOMAIN/NODATA 与稍慢 IPv4 正答冲突，以及两个
  否定答复选择的配置顺序。未进行公网递归 DNS 互操作；完整结果
  以本地质量门禁日志为准。

## 2026-10-21：RFC 2308 负缓存及 DNS 策略防泄漏回归

- **范围**：在既有 `ResponseCache` 正缓存旁，为符合条件的
  `NXDOMAIN` / `NODATA` 增加独立、有容量限制的内存负缓存（每个
  EnhancedResolver 最多 1024 项）；不修改 Fake-IP v6、UDP/TCP
  传输协议、nameserver-policy 的解析规则、自动 fallback 路由。
- **缓存准入**：只对与查询域名有祖先区关系的 SOA 权威记录建立
  负缓存。所用 TTL 是 `min(SOA RR TTL, SOA.MINIMUM)`；为 0、
  没有 SOA、SOA 所属区域不相关、截断、SERVFAIL 等响应不缓存。
  SOA 的 DNS Class 还必须匹配 Query 的 DNS Class。
  为避免对 CNAME 链进行过度推断，当前只缓存空 Answer 的
  `NXDOMAIN` 或 `NOERROR`（NODATA），不会将所有无 A 的响应
  误认为 NODATA。
- **查询隔离**：负缓存的键包含规范化 QNAME、QCLASS 和 QTYPE；
  即使 NXDOMAIN 从协议语义上可以跨 QTYPE 使用，目前也保守地
  不跨类型复用。只对满足既有 `cache_safe_request` 的普通递归
  查询启用缓存；EDNS、DNSSEC 和非普通查询不会命中此缓存。
- **应答**：命中负缓存时保留原始 RCODE、Authority（含 SOA）、
  Additional 与必要标志，重写本次事务 ID / Question，递减各区段
  TTL。过期立即重新请求上游；同一 Question 收到真实正答时
  清除旧的负缓存，避免较早的 NXDOMAIN 在正缓存过期后重新出现。
  网络路径重置时清除已有负缓存，避免在切换内网 / 分流 DNS 后
  继续使用旧路径的否定应答。
- **防泄漏验证**：全内存计数客户端检查 policy 指定的私有 DNS
  发生 NXDOMAIN 或连接失败时，普通 main/fallback 没有被调用；
  对代理服务端域名，proxy-server-nameserver 优先于 policy/main；
  同时验证 SOA TTL、过期、无效/错误区域 SOA、零 TTL、不同 QTYPE
  和网络重置。以上是 DNS 客户端选择层面的确定性测试，尚未
  通过抓包证明 OS 级别的实际网络出口；不等同真实公网/内网测试。
- **限制**：负缓存没有跨 QTYPE 优化，主要为了保守隔离；容量
  和 TTL 规则是内部实现，不公开新的控制器设置。配置热重载通过
  新 Resolver 生命周期重建缓存。测试结果以本次运行日志为准。
