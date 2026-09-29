# macOS TUN 全流量与 DNS 接管迭代记录

## 目标

尽最大努力通过 TUN 接管 IPv4/IPv6 三层单播流量，并把系统 UDP/TCP 53 查询送入 Chimera DNS：代理域名返回 fake-IP，由远端代理使用域名连接；DIRECT 专用 DNS 暂缓，本轮继续使用现有 DNS 上游配置。

系统 DNS 不指向 TUN 网关。后续系统级接管计划使用非局域网、不可公网路由的 DNS 目标（候选 `192.0.2.1`）作为哨兵：成功进入 TUN 时由 53 劫持处理；若 macOS 绕过 TUN，查询应失败关闭，而不是发往真实公共 DNS。macOS 的按服务 DNS 作用域仍可能绕过普通路由，因此这只能作为尽力方案，不能承诺覆盖所有系统和应用 DNS。

## 参考基线

- `ref/` 本地提交：`39d06a4`。包含 Linux DNS 策略路由和 Windows TUN DNS 设置；没有 macOS 系统 DNS 服务切换。
- `ref-mihomo/` 本地提交：`63bd52e`。Mihomo 的 fake-IP 实现同时有 IPv4/IPv6 地址池；当前 Chimera Client 只有 IPv4 fake-IP。
- 本轮只读参考目录，没有修改子模块。

## 本轮完成

- macOS TUN 配置若启用 DNS 劫持，必须同时启用 `route-all`、DNS resolver、fake-IP，并同时覆盖任意目标 UDP/TCP 53；避免“看似启用劫持，系统 DNS 实际仍走物理网卡”的配置被静默接受。
- macOS 物理网关查询改为按已选物理接口执行。TUN 已安装拆分默认路由时，非作用域的 `route get default` 可能返回 TUN 路径；之前的 IPv6 查询参数顺序也会被当前 macOS `route` 命令拒绝。IPv6 link-local 网关会去除 `%interface` scope 后再交给已有 `-ifscope` 路由命令。
- fake-IP 模式下，A 查询使用 IPv4 fake-IP 池；可选 `dns.fake-ip-range6` 为 AAAA 查询启用独立 IPv6 池。未配置 IPv6 池时，符合 fake-IP 条件的 AAAA、HTTPS/SVCB、TXT 等非 A 查询在本地返回空答案，不把明文 QNAME 发给真实 DNS 上游；代价是这类连接暂时没有 IPv6 DNS 结果。hosts 和显式 `fake-ip-filter` 仍按配置返回真实结果。
- 防泄漏判断会检查 DNS 报文中的全部 question，而不是只看第一项；多 question 报文里只要有 fake-IP 域名的非 A 查询，就在本地应答，不把整条报文转发上游。回归用例 `later_non_a_question_for_fake_ip_domain_is_not_forwarded` 通过。
- 同时启用 DNS IPv6 与 IPv6 fake-IP 池时，转换层要求 TUN IPv6 已启用、fake-IP 段不与 TUN IPv6 网关子网重叠，并在非 route-all 模式下把该段加入 TUN 路由。IPv4 与 IPv6 对同一域名分别保留映射；启用 fake-IP 持久化时，IPv6 使用独立缓存键，清理一个地址族不会删掉另一个地址族的反向映射。

## 仍待实现 / 验证

- 外层 Chimera 应用已接入 `MacosDnsController`：通过 `scutil` dynamic-store 的 `State:/Network/Service/chimera-dns/DNS` 添加/删除哨兵 resolver，并由管理器负责停止前恢复和启动时 orphan reconcile。该实现没有改写物理网络服务的持久 DNS 设置。
- 在目标 Mac 上确认该 resolver 是否优先于物理服务 resolver，以及哨兵超时后 macOS 是否会回退到其他 resolver。未通过此检查前，不能声称已消除 DNS 泄漏。
- 受保护配置启动时，如果设置哨兵失败或 macOS 管理器未注册 DNS 控制器，会拒绝启动核心。热更新到需要哨兵的目标配置也会先预激活；切换到不再需要哨兵的配置时，只要存在 ownership 记录，就会在提交配置或启动替换核心前恢复并读回原 resolver，失败则阻止不受保护的目标配置继续生效。
- 管理器的停止、shutdown 和隔离恢复若无法确认 DNS 哨兵已移除，会中止后续停核/完成状态发布并保留 ownership 记录。服务外层现在会等待控制事务结束，并以封顶指数退避持续重试 manager shutdown；恢复与停核成功前不会主动拆除服务。平台持续失败时，受控关停会一直等待，保证运行时仍有机会接管哨兵 DNS 查询。该逻辑不代表 macOS 一定选择哨兵 resolver，也不等于已经实机证明无 DNS 泄漏。
- `scutil` resolver 顺序与回退行为仍需实机证明。Apple 支持 DNS Proxy Network Extension 接管设备 UDP/TCP 53，但系统同时只能启用一个 DNS Proxy。Chimera 已有可构建的 Xcode extension target 和 Rust loopback DNS bridge；Tauri 现在配置了 bundle 嵌入路径，但产物仍未签名或激活，宿主也尚未配置所需 entitlement/profile，活动 DNS Proxy 的冲突处理仍待实现。
- 确认系统 resolver 的服务作用域流量实际进入 utun；只靠默认路由和 53 劫持无法证明所有 macOS DNS 都被接管。
- 在目标 Mac 验证 IPv6 fake-IP 子网确实进入 utun，且 fake AAAA 连接经过 TUN 与域名规则分流；未完成实机抓包前，这仍是代码路径与定向测试结果，不是全系统 IPv6 接管证据。
- `fake-ip-filter`、hosts、自定义 DoH/DoT/DoQ、浏览器内置安全 DNS、mDNS/Bonjour 不属于本轮 UDP/TCP 53 的完整覆盖范围。
- `DnsRunner` 在 macOS、TUN 启用 DNS 劫持且 DNS 服务启用时，额外开受管 `127.0.0.1:1053` UDP/TCP listener，和用户现有 `dns.listen` 并行；现有同端口 loopback/wildcard listener 会复用，其他端口冲突会导致 DNS listener readiness 失败，阻止核心报告启动成功。该端口仅监听 loopback。
- 外层仓库 `../Chimera/backend/tauri/macos/dns-proxy` 现有独立 Swift 包与 Xcode `system-extension` target：provider 仅接受 `127.0.0.1`，转发 UDP/TCP flow 并设置超时。Xcode 27 下构建脚本产出 arm64+x86_64 的未签名 bundle，最低系统版本为 macOS 12；Swift 包 4 个配置测试通过。Tauri 已配置 build hook 和 bundle 路径，并通过 `pnpm tauri build --bundles app --no-sign` 确认扩展落在 `Contents/Library/SystemExtensions/chimera-dns-proxy.systemextension`。Rust loopback listener 已接入核心 DNS resolver，但扩展/宿主仍未完成匹配签名、entitlement/profile 和激活，provider configuration 尚未由宿主设置，不能据此声称系统查询已进入 Chimera DNS。

## 2026-09-28 管理器预激活切片

- 两份 `chimera-core-manager`（桌面应用 workspace 与 `backend/chimera-runtime` 服务 workspace）现在会在启动/替换受保护配置的核心前应用并读回系统 DNS 哨兵。应用失败、超时或无法持久化 ownership 时，目标核心不会启动；启动拒绝后会尝试恢复 DNS，并保留无法确认清理的 ownership 记录供后续恢复。
- 新增回归用例 `dns_activation_failure_blocks_runtime_launch`、`missing_macos_dns_controller_blocks_protected_launch` 和 `dns_restore_failure_aborts_stop_and_keeps_ownership_record`，分别在两个 manager workspace 通过；相关 manager、Tauri 与 service 包 `cargo check` 通过。检查验证管理器策略，不代表 macOS resolver 选择或真实 DNS 抓包已通过。
- 对目标配置仍需要 DNS 哨兵的运行中热更新，也会在提交配置前预激活。停止接管时，若存在 ownership 记录，manager 会在目标提交/启动前尝试恢复；恢复失败会阻止不受保护的目标转换。所有公开 manager 入口还会检查最后的 converge tail。尾部 DNS apply/restore/读回/ownership 写入失败会显式返回错误并保留记录，但目标运行态可能已提交，调用方需先读取当前状态。macOS `scutil` resolver 优先级/回退也仍未证明，所以整体仍不能标为无泄漏。
- 新增 `dns_restore_failure_is_reported_by_convergence` 和 `dns_restore_failure_blocks_unprotected_runtime_launch`，分别验证 converge 错误可见，以及 DNS 无法恢复时不启动不受保护的目标运行态；桌面与服务两份 manager workspace 定向测试通过。
- Service shutdown 在首次 manager shutdown 失败或超时后会等待控制 executor 结束，并反复执行 manager shutdown，直到 DNS restore 与 core stop 成功才返回；新增 `shutdown_retry_keeps_retrying_after_a_transient_failure` 验证瞬时失败后的重试。持续平台故障会阻止 service teardown，这是为了避免主动拆掉仍接管系统 DNS 的 core。
- 为运行 service 定向测试，补上其原本缺失的 `tempfile` 开发依赖，并把已过时的 `Meow` 测试映射改为当前支持的 `ChimeraClient` 映射。首次测试发现这两处既有编译问题，修正后目标用例可运行。
- 下一步：在签名宿主进程接入 System Extension 激活/停用与 DNS Proxy provider 配置，设置 `127.0.0.1:1053` 并纳入现有 ownership 生命周期；确认服务模式与桌面模式的启停行为一致，且不会静默覆盖其他 DNS Proxy。bundle 落位和 loopback bridge 已完成；当前机器没有有效代码签名身份，激活验证仍需匹配 Team ID、entitlement/profile。然后做专用 Mac resolver/物理网卡抓包验证。DIRECT 专用 DNS 继续暂缓，不阻塞该链路。

## 验证记录

- 只读确认当前 macOS `route` 语法：`route -n get -ifscope en0 default` 与 `route -n get -inet6 -ifscope en0 default` 均返回物理网关；未修改本机 DNS 或路由。
- `cargo check -p clash-lib`：通过（Darwin，2026-09-28）。
- `cargo test -p clash-lib --lib later_non_a_question_for_fake_ip_domain_is_not_forwarded -- --nocapture`：通过，验证后续 question 中的非 A fake-IP 查询也不会触发上游请求。
- `cargo test -p clash-lib --lib managed_bridge -- --nocapture`：通过，3 个用例验证默认双协议 listener、复用匹配 loopback listener 与避免 IPv4 wildcard 重复绑定。为恢复本轮测试编译，给当前工作树已有 `Session.sniff_host` 扩展对应的 dispatcher 测试 fixture 补了 `None`。
- 没有在运行中的客户端或真实网络上执行 TUN/DNS 主机变更。

## 2026-09-28 可选 IPv6 fake-IP 切片

- 依据本地 `ref-mihomo/` 的 `fake-ip-range6` 配置与双 fake-IP pool 结构，在 Client 增加可选 `dns.fake-ip-range6`。配置缺省保持兼容：IPv4 fake-IP 继续工作；没有 IPv6 池时 fake 域名 AAAA 在本地空答，不向上游发送原始域名。
- `FakeDns` 现在支持 IPv4/IPv6 池，IPv6 池限定有界容量并拒绝 unspecified、loopback、multicast、link-local 和无可分配地址的范围。A/AAAA 共用同一域名时分别分配、反查和缓存；IPv4 缓存键保持原格式，IPv6 使用独立键空间。
- fake AAAA 由 IPv6 池生成。IPv6 fake-IP 段需配合 TUN IPv6 启用，拒绝和 TUN IPv6 网关段重叠；非 route-all 配置会显式路由该段进入 TUN。
- 验证：`cargo check -p clash-lib` 通过；fake-IP 模块测试 11 通过、1 个既有 ignored；DNS handler 定向测试 8 通过；`cargo test -p clash-lib --test dns_config_tests -- --test-threads=1` 的 16 项全部通过；IPv6 池 TUN 路由与重叠检查测试通过；相关文件 `rustfmt --check` 与 `git diff --check` 通过。该配置集使用串行运行避免并发启动用例共享全局运行时状态。
- 这些检查只验证配置、分配/反查、缓存隔离、DNS 回答以及路由转换逻辑。macOS utun 捕获、真实 AAAA 请求和物理网卡 DNS 抓包仍未验证。

## 下一步

扩展构建、Tauri bundle 落位和 `127.0.0.1:1053` loopback bridge 已完成。当前机器没有有效的代码签名身份，因此宿主激活/停用和 provider 配置还不能在此验证；这仍需匹配的 Team ID、entitlement/profile，并要让桌面/服务模式共享 ownership 生命周期。完成宿主接入后，再安排专用 Mac resolver 顺序、普通 A/AAAA/HTTPS 查询和物理网卡抓包验证。DIRECT 专用 DNS 继续暂缓，不阻塞系统级 DNS 接管。
