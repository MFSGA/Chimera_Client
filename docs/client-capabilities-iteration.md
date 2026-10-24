# 客户端能力闭环迭代记录

日期：2026-10-23。基线：本地 `master` / `origin/master` 均为 `4604758fea1d125cbf2d1e1b6c4c72b5a259e136`。参考快照：`ref`=`39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`，`ref-mihomo`=`63bd52ec794b7051569b76ede2f6cdbf4c091fda`，`ref-meow`=`3bf59376708809386c20b648c4d709148a077a79`。本轮未更新参考子模块；`ref-meow` 目录保留开工前状态。

## 目标与边界

补齐 Chimera Client 核心向桌面与移动客户端提供的能力接口：节点配置校验与构建能力查询、启动就绪状态查询、可区分测速目标的历史记录、可清除并重新继承当前配置的会话代理模式覆写，以及网络恢复状态观测。

TLS 指纹模拟明确排除。Android FFI、页面交互以及本地 gRPC 旧校验属于另一仓库，不在本仓库实现范围内；本核心已经提供代理 `alive` 状态、运行就绪与网络恢复观测，Android 仍需接入这些接口。

## 本轮变更

- 新增 `GET /capabilities`，返回当前平台、已编译出站协议和实际启用的 Cargo feature 名称，供客户端按当前构建选择功能。
- 新增 `POST /configs/validate`，接收 `payload` YAML，在不启动监听器或联网的情况下执行 YAML/merge 解析、配置转换与校验、普通出站构造、`dialer-proxy` 目标、代理组成员/provider 引用及依赖环检查；同时识别会被运行时内置 `GLOBAL` 遮蔽的同名代理或代理组。问题包含稳定错误码、节点名、可取得的字段路径和原因。响应 `validationScope` 明确不代表外部 provider 内容可用、节点网络可达或组件已启动。
- 新增 `GET /configs/mode`、`PUT /configs/mode`、`DELETE /configs/mode`。既有 `PATCH /configs` 设置模式仍然有效，并记录为会话覆写；DELETE 清除覆写并恢复当前运行配置中的模式。成功重载创建新运行实例后，模式继承新配置。
- 测速历史记录增加 URL 维度。`GET /proxies/{name}/history` 返回该节点全部目标的记录，`?url=<目标>` 只查指定目标；既有代理 `history` 字段保留并为每条外部 URL 记录增加经过脱敏的 `url`。URL userinfo 会移除，查询参数值会遮盖，fragment 会移除；服务端仍以原始 URL 精确区分及筛选。每节点最多保存 16 个目标，每个目标最多 20 条记录。

## 已有能力核对

- `GET /runtime` 已返回生命周期、整体健康、组件就绪/失败和错误信息；启动成功前核心等待 API、DNS、TUN（启用时）及入站监听器的就绪信号。
- `/network` 与 `/runtime/network/*` 已提供网络变化、恢复操作、路径决策、有效路径及临时路径偏好查询。详细迭代及尚待专用平台验收的事项见 [网络可用性迭代计划](network-availability-iteration-plan.md)。本轮不重复建设恢复状态机。
- `/proxies` 的代理详情已包含 `alive`；面向 Android 的 FFI 模型接入不属于此仓库。

## 验证记录

- `cargo fmt -p clash-lib`：通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo check -p clash-lib`：通过。
- 同一目标目录下 `cargo check -p clash-lib --no-default-features` 与 `cargo check -p clash-lib --all-features`：本轮最终改动后通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo clippy -p clash-lib --all-targets --no-default-features --features zero_copy,tls,extended-health-check,aws-lc-rs,ring,ws,anytls,shadowsocks,wireguard,trojan,hysteria,xhttp-h3,tun,tproxy,redir,http_port,mixed_port,tracing,port,reality,vless-encryption -- -D warnings`：通过；该组合覆盖全部核心 feature，不启用会触发 Dashboard `npm ci` 的 `dashboard`。
- `cargo fmt --all -- --check`：通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo test -p clash-lib --lib client_capability`：6 个定向用例通过，978 个其他测试被过滤。
- 同一目标目录下 `cargo test -p clash-lib --lib client_capability --features shadowsocks,anytls,trojan,hysteria,wireguard,ws,xhttp-h3`：6 个定向用例通过，1143 个其他测试被过滤。
- `cargo fmt --all -- --check` 与 `git diff --check`：通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo test -p clash-lib --test api_tests client_capability_controller_endpoints_expose_validation_and_mode_override -- --exact`：通过；覆盖能力查询、节点校验、合法/非法组、组循环、会话覆写清除和测速历史查询路由。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo test -p clash-lib --test api_reload_tests put_configs_reloads_runtime_from_file -- --exact`：通过；确认重载后有效模式继承新配置且旧会话覆写清除。
- 最终复审补出 `dialer-proxy` 目标校验、自动注册的 `GLOBAL` 目标及 URL fragment 脱敏缺口；实现后再次运行 Controller 集成测试，覆盖 `DIRECT`/`GLOBAL`/有效代理组目标、缺失目标、保留名冲突和就绪状态查询，通过。6 个能力定向单测也通过。fragment、userinfo 和 query 值均不会出现在测速历史响应中。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo check -p clash-lib`、`--no-default-features`、`--all-features`：均通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo clippy -p clash-lib --all-targets --no-default-features --features zero_copy,tls,extended-health-check,aws-lc-rs,ring,ws,anytls,shadowsocks,wireguard,trojan,hysteria,xhttp-h3,tun,tproxy,redir,http_port,mixed_port,tracing,port,reality,vless-encryption -- -D warnings`：通过。
- 后续补跑本机端到端行为用例：`cargo test -p clash-lib --test direct_udp_integration_tests`（3 项）、`cargo test -p clash-lib --test shadowsocks_integration_tests --features shadowsocks`（4 项）、`cargo test -p clash-lib --test anytls_integration_tests --features anytls`（2 项）、`cargo test -p clash-lib --test connection_chain_tests`（1 项）、`cargo test -p clash-lib --test vless_transport_contract_tests --features ws`（4 项），全部通过。这些测试使用本地 loopback 服务；Direct UDP 恢复用例调用本地 `/network/reset`，不修改宿主机网卡、路由或 DNS。
- `git diff --check`：通过。
- 初次使用仓库默认 `target` 软链接构建时，目标卷仅剩 33 MiB，写入失败；改用主卷临时目录后完成上述编译和测试。没有删除原构建缓存。
- 带 `--all-features` 的定向测试被 Dashboard 构建脚本的 `npm ci` 阻断：现有 `node_modules/lucide-react` 清理返回 `ENOTEMPTY`。Rust `--all-features` 编译已通过；未删除或重装前端依赖。
- 完整 `clash-lib` 测试、跨平台构建和真实 API 客户端互操作尚未执行。
- 独立 Reviewer 在最终 diff 上未发现阻塞问题；Reviewer 为只读审查，未独立重跑测试。没有创建 PR 或推送；本轮按本地 `master` 迭代流程提交，提交签名与 SHA 在交付信息中核验。

## 2026-10-24 追加验证

- 本次续接基线为本地 `master` `718495497864f4451a26061e0c18aaf3a2d18fe0`；增加 `dialer_proxy_connects_through_a_local_socks5_hop`，通过两个 loopback SOCKS5 中继和本地 HTTP 目标验证真实 TCP `dialer-proxy` 链。测试解析并断言 upstream 到 leaf、leaf 到目标的 CONNECT 地址，检查 HTTP 请求头和响应体，并为连接、读取及目标任务设置超时；不操作宿主机网卡、路由、DNS 或 TUN。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo test -p clash-lib --test connection_chain_tests`：2 项通过。
- `CARGO_TARGET_DIR=/private/tmp/chimera-client-capability-target cargo clippy -p clash-lib --test connection_chain_tests -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check`：通过。
- 独立 Reviewer 只读复核本次最终测试 diff，未发现阻塞问题；Reviewer 未独立重跑测试。残余小风险是测试端口“释放后再绑定”的竞争窗口；本测试实际路径全程使用 loopback。

## 剩余边界

- 本轮实现的是 `Chimera_Client` 核心 API；Android 仓库的 FFI 模型、gRPC 旧校验及配置覆写页面仍需另一个仓库接入这些接口。
- 完整 `clash-lib` 测试、跨平台运行、外部真实代理节点互操作与操作系统级网络切换未执行。本机 loopback 握手、TCP/UDP 往返及恢复 API 已按上面的定向用例验证。带 `--all-features` 的测试仍被 Dashboard `npm ci` 的 `ENOTEMPTY` 环境错误阻断；不能据此声明这些验证通过。
- TLS 指纹模拟按用户要求排除。
