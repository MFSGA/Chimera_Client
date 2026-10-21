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
