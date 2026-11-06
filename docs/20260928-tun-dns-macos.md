# macOS TUN 全流量与 DNS 接管迭代记录

## 目标

尽最大努力通过 TUN 接管 IPv4/IPv6 三层单播流量，并把系统 UDP/TCP 53 查询送入 Chimera DNS：代理域名返回 fake-IP，由远端代理使用域名连接；DIRECT 专用 DNS 暂缓，本轮继续使用现有 DNS 上游配置。

System DNS 指向一个与 fake-IP 池、TUN 网关子网及 route exclusions 不冲突的文档网段虚拟地址。macOS 按服务 resolver 可能使用接口作用域路由，因此仅改 DNS 地址和添加 TUN 默认路由不够；Client 还需对每个启用网络服务的接口添加指向 utun 的作用域 host route，再由 TUN 对 UDP/TCP 53 执行 DNS hijack。此方案目标是让 DNS 报文本身进入 utun；DoH/DoT、mDNS/Bonjour 和第三方 VPN resolver 仍需分别验证。

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
- Client 现会为启用网络服务的接口安装虚拟 DNS 地址的作用域 host route，并在改写系统 resolver 前读回路由；仍需在目标 Mac 抓包确认 resolver 的 UDP/TCP 53 报文本身实际进入 utun。
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

## 2026-09-29 Client-only utun DNS packet 接入切片

- 本轮只修改 `Chimera_Client`。启用 macOS TUN、`dns-hijack` 和 fake-IP DNS 时，Client 从文档网段中选择一个不与 fake-IP 池、TUN gateway 子网或 route exclusions 冲突的虚拟 DNS IPv4 地址。默认 fake-IP 池为 `198.19.0.0/16` 时，首选 `192.0.2.53`。
- 启动先恢复上次异常退出留下的系统 DNS 状态，再启动 TUN 并等待接口、拆分默认路由及按物理接口保留的 scoped default route 就绪。然后为启用且具有 IPv4/IPv6 地址的网络服务设备添加 `route add -ifscope <service-device> -host <virtual-dns> -interface <utun>`，读回确认目的路由通过当前 utun，最后把这些服务的 DNS 临时改为虚拟地址并验证 `networksetup` 和 `scutil --dns`。当前 Mac 实机发现该跨接口 scoped route 不能安装；见下方验证记录。
- 虚拟目标不是 DNS listener 地址。系统发往 `<virtual-dns>:53` 的 UDP/TCP 包经 utun 进入现有 TUN netstack，由 DNS hijack 调用 Client resolver；fake-IP 答案和之后的 fake-IP 连接继续使用现有 fake-IP 路由。移除了此前临时增加的 `127.0.0.1:53` listener 与 gate，因为 loopback 路径不能满足“DNS 查询包本身进入 utun”的目标。现有 `127.0.0.1:1053` DNS proxy bridge 保留。
- 网络服务清单使用当前 macOS 支持的 `networksetup -listnetworkserviceorder`。持久化状态升级为版本 2，记录原 DNS、虚拟 DNS、utun 名称和 Client 管理的作用域 host routes；读取版本 1 时按旧 loopback 目标迁移/恢复。关停时先恢复 DNS，再删除仍明确指向 Client utun 的 host route；用户改过 DNS 的服务会保留用户新值。设置或读回失败时会走回滚路径，无法确认的状态记录保留以便重试。
- 配置验证仍要求 `route-all`、DNS resolver、fake-IP，以及 catch-all UDP/TCP 53 hijack 规则。若三个文档网段候选都与 fake-IP、TUN gateway 或 exclusions 冲突，配置会明确拒绝启动。
- `cargo check -p clash-lib` 通过；`cargo fmt --all -- --check` 和 `git diff --check` 通过。没有启动或重启当前运行中的客户端，也没有修改本机 DNS/路由；尚未执行修改路由的命令或物理网卡抓包。因此目前验证到的是代码编译和只读 macOS service-order/route 行为，不能声称 DNS 报文已经在运行时进入 utun 或已消除所有 DNS 泄漏。

## 2026-09-29 当前 Mac 实机运行验证

- `cargo build -p clash-rs --features tun` 与 `target/debug/clash-rs --test-config --config config.yaml` 通过。真实配置启用 `route-all`、`dns-hijack` 和 fake-IP；进程创建 `utun1989` 并设置 TUN 分流默认路由后，在 DNS 激活阶段失败关闭，未改写系统 resolver。
- 本机 `route -n get -ifscope bridge0 192.0.2.53` 以退出码 0 返回空 stdout、并将 `not in table` 写到 stderr。路由解析器现把空 stdout 解释为没有已有路由；DNS 服务枚举也跳过没有 IP 地址的接口，因此不再尝试无地址的 Thunderbolt Bridge。
- 对活动 Wi-Fi (`en1`) 的 `route add -ifscope en1 -host 192.0.2.53 -interface utun1989`，macOS 返回 `Network is unreachable`，读回仍选择 `en1` 的物理默认路由。相同目标的无作用域 host route 可指向 utun，但 `route -n get -ifscope en1 192.0.2.53` 仍选择 `en1`。因此当前 Client-only scoped-route 方案不能接管本机按服务作用域发出的系统 DNS；需要另一个 macOS DNS 接入机制，不能把它标为通过。
- 为分离验证 TUN/fake-IP，使用临时配置副本关闭 `route-all` 与系统 DNS 劫持、启用 loopback DNS listener `127.0.0.1:1053`。本地查询 `example.com` 返回 fake-IP `198.19.0.2`；`tcpdump` 在 `utun1989` 捕获到发往该 fake-IP 的 TCP SYN，证明 fake-IP 连接包确实进入 TUN。随后 HTTP 请求 5 秒超时，未验证出站代理响应。
- 两次完整配置启动均在系统 DNS 写入前失败，并正常退出。最终复查未发现 `utun1989`、TUN 分流或 DNS host route 残留；默认路由仍经原 `en1`，`scutil --dns` resolver 恢复为启动前状态。没有留下运行中的测试客户端。
- 修正后的 `cargo test -p clash-lib --lib --features tun macos_dns::tests -- --nocapture`：2 项通过；`cargo fmt --all -- --check` 与 `git diff --check` 通过。较宽的 `cargo test -p clash-lib --features tun macos_dns::tests -- --nocapture` 会编译到现有 `api_protocol_tests`，并被其中未使用导入的 `-D warnings` 阻止；这与本轮路由单测无关。
- 下一步：不要仅靠 `-ifscope` host route 宣称 macOS 系统 DNS 已进入 utun。需要验证 DNS Proxy Network Extension 或另一种能处理服务作用域 resolver 的方案；在此之前，当前配置保持失败关闭。

## 2026-09-29 Mihomo fake-IP key semantics and TUN startup readiness

- Mihomo 参考基线为本机 `ref-mihomo` submodule 的 `Alpha` 分支提交 `63bd52e`（`component/fakeip/pool.go`）；这是本地参考版本，不代表远端最新提交。该版本在 fake-IP pool lookup 时将主机名转为小写，再用规范化键保存和反查。
- Chimera 的 `FakeDns` 现在在分配、查找已有映射、反向查域名和 fake-IP skip-filter 查询前统一将域名转为小写。这样同一域名大小写不同的 DNS 查询复用同一个 fake-IP，反向映射给规则路由时也稳定，大小写不同的过滤规则仍可命中。保留了 Chimera 已有的“反向映射不存在时回退到 IP”行为及其测试，不照搬 Mihomo 的错误处理差异。
- macOS TUN runner 的成功 readiness 通知现在位于 TUN 设备、数据泵以及 TCP/UDP handler 构造完成之后。DNS 接管层一旦收到 ready 就可以开始送包，因此不会因通知过早而在数据面尚未装配时放行首批 DNS 包；初始化失败仍沿错误路径返回。
- 验证：`cargo test -p clash-lib --lib fakeip::`（14 passed，1 ignored）、`cargo test -p clash-lib --lib reverse_lookup_falls_back_to_ip_when_fake_ip_record_is_missing`（1 passed）、`cargo check -p clash-lib` 均通过。未运行会修改主机网络状态的 ignored 真实 TUN 集成测试。
- 这验证的是域名映射大小写稳定性、代码编译和单元级行为；没有证明当前 Mac 的系统 DNS resolver 已进入 utun，也没有端到端验证 Chimera 的 DIRECT 与代理双出站。DNS 查询包本身是否经过 TUN 与后续 fake-IP 连接是否能由 TUN 恢复域名并按规则分流是两个独立观察点；本轮只加固后一个流程所依赖的映射，并修正启动时序风险。

## 2026-09-29 system proxy 开启时的 TUN/fake-IP 双出站实测

- 测试前 macOS HTTP、HTTPS、SOCKS 系统代理均已启用在本机 `127.0.0.1:7866`，由现有 Nyanpasu Mihomo 监听。本轮没有关闭代理、修改系统 DNS 或停止该进程。
- `cargo build -p clash-rs --features tun` 成功。运行配置是 `config.yaml` 的私有临时副本：TUN 保留开启，但设 `route-all: false`、关闭 TUN 系统 DNS 劫持，DNS 只监听 `127.0.0.1:1153`；Fake-IP 网段路由由 Chimera 自动安装到新建 `utun1989`。DNS 临时使用可用的 UDP `114.114.114.114`，并关闭临时副本中的 fallback，以便验证真实域名出站解析。原配置没有被改写。
- 对 Chimera DNS 查询 `apple.com` 和 `cloudflare.com` 分别获得 fake-IP `198.19.0.2`、`198.19.0.3`；两者的主机路由均指向 `utun1989`。用 `curl -q --proxy '' --noproxy '*' --resolve <domain>:443:<fake-IP>` 发起 HTTPS 请求，明确绕过代理环境和客户端代理设置。两次均完成 TLS 并返回 HTTP 301；TUN 抓包捕获到对应 fake-IP TCP 包。
- Chimera `/flows` 记录 `apple.com` 命中 `DomainSuffix -> DIRECT`；`cloudflare.com` 命中 `DomainSuffix -> 🎲 上网入口`，并走配置的代理链。两条测试请求没有连接系统代理 `127.0.0.1:7866`。
- 测试副本进程已正常退出；复查 `utun1989` 和 `198.19.0.0/16` 路由均已清除，默认路由仍经 `en1`，系统代理仍启用，Nyanpasu 仍运行；私有临时配置、缓存和抓包记录已删除。
- 结果范围：这证明两条显式绕过系统代理的测试进程可经 TUN/fake-IP 按 DIRECT 和代理规则分流。系统代理仍然启用，因此其他遵循 macOS 系统代理设置的应用仍会连接本机 `127.0.0.1:7866`；本轮没有验证这些应用是否绕过系统代理，也没有验证全局 `route-all`、macOS 系统 DNS 劫持或全主机所有协议的覆盖情况。

## 2026-09-30 macOS TUN + fake-IP 使用本机 DNS listener

- 用户确认 DNS 查询包本身不必进入 utun；目标是让应用拿到 fake-IP，并让之后的连接进入 TUN，由 fake-IP 映射恢复域名后按规则选择 DIRECT 或代理。
- 移除依赖 `route add -ifscope <physical-interface> -host <virtual-dns> -interface <utun>` 的 DNS 接入方案。该命令在当前 Mac 的 Wi-Fi 服务上返回 `Network is unreachable`，是完整配置之前启动失败的具体原因。
- macOS 上只要 TUN、DNS 和 `enhanced-mode: fake-ip` 开启，Client 现在准备 `127.0.0.1:53` UDP/TCP listener，并通过 `networksetup` 将活动网络服务临时指向 loopback DNS；该接入独立于 `tun.dns-hijack`。fake-IP 网段仍走现有 TUN 路由配置。DNS 查询本身留在本机 loopback，不再声称它经过 utun。
- 新的持久化状态版本为 3。启动恢复能读取 v1/v2 旧状态并清除旧方案留下且仍明确指向旧 utun 的作用域路由；停止时先恢复之前保存的 DNS，再停止数据面。DNS listener 在改写系统 resolver 前完成 readiness。
- 验证：`cargo check -p clash-lib`、`cargo check -p clash-lib --features tun`、`cargo fmt --all -- --check`、`git diff --check` 通过。`cargo run -p clash-rs --no-default-features --features standard,aws-lc-rs -- -t -c config.yaml` 和另一个只启用 TUN + fake-IP、关闭 `route-all` 与 `dns-hijack` 的临时最小配置检查均通过。当前端口 53 没有发现监听进程。带默认 Dashboard feature 的 CLI 构建另因已有 `node_modules/.tmp/tsconfig.app.tsbuildinfo` 权限不足，在 `npm ci` 阶段失败；关闭 Dashboard feature 后的核心 CLI 检查成功。
- 最终实机复测使用 `config.yaml` 的私有临时副本，保留 `tun.enable`、`route-all: true`、`dns-hijack: true`、fake-IP、DNS 上游、规则和代理；只将入站监听收窄到 loopback、把 mixed-port 设为 0、控制器改为临时端口。临时运行目录没有 `Country.mmdb`，所以测试副本把 `mmdb` 指向仓库现有数据库文件，避免缺库触发默认下载，也避免 `fallback-filter.geoip: true` 在无数据库时把所有答案都送去 fallback。用 `--compatibility false` 启动。TUN 创建为 `utun1989`，之前的 `Network is unreachable` scoped-route 错误没有再出现；系统 resolver 指向 `127.0.0.1`，本机 UDP/TCP 53 listener 可用。直接向本机 listener 查询 `www.google.com` 和 `www.baidu.com` 都得到 fake-IP；路由查询确认 `8.8.8.8` 和 fake-IP `198.19.0.9` 都经 `utun1989`。
- 使用 `curl -q --proxy '' --noproxy '*' --resolve <domain>:443:<fake-IP>` 显式绕过仍启用的系统 HTTP/HTTPS/SOCKS 代理。百度返回 HTTP 200，TLS 校验成功；Controller `/flows` 记录 `www.baidu.com` 命中 `DomainKeyword baidu -> DIRECT`，有实际上传与下载字节。Google 返回 HTTP 200，TLS 校验成功；`/flows` 记录 `www.google.com` 命中 `DomainKeyword google`，经配置的 `VLESS Reality Vision plus -> 一定有网 -> 上网入口` 代理链，收到实际响应数据。两条连接都以 fake-IP 作为 TUN 入站目标，Dispatcher 恢复域名后用于规则判断。
- 中间曾有一次无效对照：临时配置把 `mmdb` 设为空，却保留 `fallback-filter.geoip: true`。当前 `GeoIPFilter` 在没有 GeoIP 数据库时会把答案判定为需要 fallback；本机的部分 DoH/DoT fallback 随后报连接 reset，导致测试人为失败。有效复测使用了现有 `Country.mmdb`，没有因此修改 DNS 上游或关闭 GeoIP fallback。
- 按 Ctrl-C 正常停止后，`utun1989` 消失，53 端口 listener 关闭；Wi-Fi 与 Ethernet DNS 均恢复为原来的 `8.8.8.8`、`114.114.114.114`，默认路由恢复经 `en1`。HTTP/HTTPS/SOCKS 系统代理仍启用在 `127.0.0.1:7866`，Nyanpasu/Mihomo 仍在运行；测试请求明确绕过了它。临时配置使用私有文件权限，原始 `config.yaml` 未修改。
- 这次验证覆盖了当前配置的 TUN + fake-IP + 全局路由下，一条 DIRECT 和一条代理规则的真实 HTTPS 流量；不等同于证明每个应用、每个协议、浏览器内置 DoH/DoT、mDNS 或所有目标网站都已覆盖。端口 53 被占用、缺少修改系统 DNS 的权限，或 macOS `networksetup`/`scutil` 操作失败时，启动仍会明确失败并尝试恢复原 DNS；本次系统 DNS 改写与清理均成功。
- Dispatcher 对缺少反向记录的 fake-IP 现在按 fail-closed 处理：丢弃该 TCP/UDP 流并写明日志，不再把合成地址当真实 IP 继续匹配规则。这样不会静默跳过域名规则；行为与本地 Mihomo 基线 `63bd52e` 的 `preHandleMetadata` 对 fake DNS mapping 缺失时返回错误相符。回归用例 `reverse_lookup_rejects_fake_ip_when_mapping_is_missing` 定向运行通过（1 passed）。本轮 `cargo fmt --all -- --check`、`cargo check -p clash-lib --features tun`、`git diff --check` 也通过；没有启动会修改主机网络的 TUN 测试。

## 2026-09-30 需求澄清：fake-IP 不依赖改写 macOS 系统 DNS

- 用户目标是让到达 Chimera DNS 的域名查询返回 fake-IP，并在 DNS 回答阶段不请求真实 IP；不要求 `networksetup` 把 macOS resolver 改到 `127.0.0.1:53`。已从当前实现移除系统 DNS 改写、端口 53 自动 listener 和对应状态文件；保留仓库原有的 TUN DNS hijack、`dns.listen` 和 `127.0.0.1:1053` proxy bridge 行为。核心 fake-IP 路由仍会在 `route-all: false` 时单独加入 fake-IP 子网。
- DNS 入口和 fake-IP 应答是两段：配置的 `dns.listen` 可以接收直接发给该 listener 的查询；TUN `dns-hijack` 则在 DNS UDP/TCP 流量已经进入 TUN 后解析报文，并把请求交给同一个 `exchange_with_resolver`。系统 resolver 若继续查询外部 DNS，只有其 DNS 流量命中 TUN 路由且匹配 hijack 规则时，Chimera 才能透明捕获；关闭 hijack 且客户端不使用 `dns.listen` 时，核心看不到该查询。
- fake-IP 模式下，普通未过滤域名的 A 查询走 `resolve_v4` 的 fake 池分配路径，创建并保存“fake-IP ↔ 域名”映射后直接返回，不调用 `lookup_ip` 或真实 DNS 上游。hosts、`fake-ip-filter`、非 fake-IP 查询模式是现有例外路径；配置若要求所有域名严格 fake-IP，应同时审查这些例外配置。fake-IP 的 DNS 回答不需要真实 IP；后续 DIRECT 连接仍需要某个出站解析路径取得真实目的 IP，代理出站可将域名交给代理端处理。
- 定向验证：`fake_ip_tun_adds_fake_ip_route_without_hijack_or_route_all`、`managed_bridge`（3 项）、`a_query_returns_fake_ip_without_forwarding_to_upstream`、`reverse_lookup_rejects_fake_ip_when_mapping_is_missing` 和 `dns_hijack_uses_rules`（TCP/UDP 各 1 项）均通过；`cargo check -p clash-lib --features tun`、格式检查和 `git diff --check` 通过。没有在本轮启动主机网络测试或改写系统 DNS。

## 2026-09-30 三平台 TUN/fake-IP 行为统一与真实 E2E

- 统一的行为契约是：DNS listener 与 TUN DNS hijack 共用 `exchange_with_resolver`；符合 fake-IP 策略的 A/AAAA 查询本地分配并保存域名映射；连接 fake-IP 后由共用 Dispatcher 反查域名并应用同一套规则。平台仍各自负责 TUN 设备与系统路由接入；macOS 不因这项统一而自动改写系统 DNS。
- `TunRunner` readiness/error 通知已从 macOS 专用扩展到所有 TUN 平台。启动流程只有在设备、路由和 TCP/UDP handler 准备好后才报告 TUN ready；初始化错误现在会沿启动错误路径返回。Windows 配置 TUN 网卡 DNS 失败也改为启动失败，不再只记日志后继续。
- 加强 `tun_fake_ip_real_tests`：每次执行选一个未占用的 TUN 名称、独立 fake-IP `/24` 和网关；配置 `route-all: false`、`dns-hijack: false`，只查询显式本机 DNS listener，不触碰系统 DNS。它分别用 UDP/TCP 查询两个域名，检查两种传输复用相同映射且 fake-IP 答案阶段没有新增上游 DNS 请求，再用真实 TUN 流量验证 DIRECT 和本机 SOCKS5 代理都能成功，并检查规则分发日志。测试使用本地可控 DNS/HTTP/SOCKS 服务，不依赖公共网站。
- macOS 实机运行 `tun_fake_ip_answers_without_upstream_and_routes_direct_and_proxy`：通过（1 passed）。命令为 `cargo test -p clash-lib --features tun --test tun_fake_ip_real_tests --no-run` 后，以 root 执行生成的集成测试二进制并带 `--ignored --nocapture --test-threads=1`。本轮先检查到主机已有 root 运行的 `clash-rs`/`utun1989`；测试用了独立的 `utun4` 及动态网段，测试退出后复查只剩原有 utun 与路由，未修改系统 DNS 或默认路由。
- `cargo test -p clash-lib --lib --features tun a_query_returns_fake_ip_without_forwarding_to_upstream`：1 passed；`cargo check -p clash-lib --features tun` 和 `cargo check -p clash-lib --no-default-features`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。当前 Rust 工具链只安装了 `aarch64-apple-darwin` 目标，因此 Linux/Windows 的实机执行与交叉编译尚未验证；Windows DNS 设置和三端系统路由接入仍需各自平台验证。

## 2026-11-05 Mihomo 兼容配置与代理目标 DNS 隐私约束（第一阶段）

- 本轮基于 `origin/master` `902c5e7` 的独立 Worktree；对应本地 Mihomo 参考 gitlink `63bd52e`（本轮 Worktree 未初始化参考子模块，仅核对源工作区中的同一参考检出）。不改主工作区、子模块及 macOS 网络设置。
- 对齐 Mihomo 配置语义：`dns.respect-rules: true` 必须有非空、可用的 `dns.proxy-server-nameserver`，避免节点 DNS 依赖通过需要该节点的规则路由而自循环；`dns.fake-ip-filter-mode: blacklist` 兼容既有过滤语义，`whitelist` / `rule` 尚未实现，解析时明确拒绝而非忽略。`tun.strict-route: true` 尚无等价 macOS 路由与防泄漏实施，明确报错；省略该项或 `false` 保持原行为。不要把 `strict-route: false` 解读为具备物理网卡封锁能力。
- `tun.enable + dns.enable + enhanced-mode: fake-ip` 下禁止 `experimental.proxy-resolve-local: true`：该开关会把已按代理规则选定的目标域名转换为真实 IP 并触发本地 DNS 查询。保护逻辑在内部 `Config::validate`，同时覆盖 YAML 解析、内部配置和热重载；仅针对代理**目标**域名，代理服务器本身的地址解析及 DIRECT 解析仍分别遵循原有策略。
- 保留的调用链：本地 DNS 入口 / TUN hijack → `exchange_with_resolver` 生成 Fake-IP → TUN 捕获合成地址连接 → Dispatcher 恢复域名 → 选择策略 → PROXY 携域名拨号；缺失映射继续 fail-closed。新增不触发任何本地 resolver 的代理目标测试，并用配置测试覆盖上述拒绝路径。
- **未完成的系统级防泄漏保证**：macOS service-scoped resolver 未必经过 utun；当前没有已证明运行的系统 DNS Proxy Extension 激活与 ownership 事务、物理 NIC 出口阻断或 DNS 抓包证据。浏览器自有 DoH/DoT、其他系统扩展、QUIC DNS、代理节点 DNS、`fake-ip-filter` 明确例外和 DIRECT 仍可能发生各自合法或未受控的解析。不能用本轮单测或 `route-all` 宣称全系统零泄漏。
- **本轮实际验证**：`cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6`：812 passed、0 failed、11 ignored；`cargo test -p clash-lib --test dns_config_tests --no-default-features --features tun,ring --locked -j 6`：17 passed；`cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring --locked -j 6 -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。关闭 `tun` 的整库单测有 779 passed、7 failed、9 ignored：7 项现有测试直接启用 TUN fixture，却触发原本已有的无 `tun` Feature 配置拒绝门禁；本轮没有降低该门禁。相同无 TUN 组合下针对 `mihomo_` 的 9 项及新增的代理目标远端解析测试 1 项通过。未执行真实 TUN、系统 resolver 或物理网卡抓包；尚未验证 Linux/Windows 原生运行。
- **下一阶段验收条件**：在授权的专用 macOS 测试环境以受管 DNS Proxy Extension 或等效系统 DNS 控制面接管系统查询；对 IPv4/IPv6、UDP/TCP 53、路由切换、睡眠恢复、proxy 故障/断线、TUN 关闭、非 A/AAAA DNS 问题进行隔离抓包并核验物理 NIC 上不存在受保护的 QNAME 或明文目标解析请求。失败应阻断受保护流量而不是回退系统 DNS / DIRECT。Mihomo 的 `fake-ip-filter-mode: rule`、`tun.strict-route` 在实现并验证前继续拒绝或维持明确不可用状态。

## 2026-11-05 Mihomo fake-ip-filter-mode: whitelist 兼容切片

- 在独立 `codex/macos-tun-fakeip-dns-privacy` 分支上继续；基线 `0c36e2e`，`master=e42dabe`，`origin/master=902c5e7`（未执行同步或重写历史），固定本地 Mihomo gitlink `63bd52e`。参考 `ref-mihomo/component/fakeip/skipper.go` 中 `ShouldSkipped` 的白名单反转语义及 `constant/dns.go` 中 `FilterMode.UnmarshalText` 大小写不敏感输入；参考子模块保持只读。
- 实现 `dns.fake-ip-filter-mode: whitelist`，沿原始配置 → `app::dns::Config` → `FakeDns::should_skip` → resolver Fake-IP/真实上游的链路传递配置。黑名单仍是缺省模式且保持原行为；白名单仅对匹配 `fake-ip-filter` 的域名分配 Fake-IP，其他域名**会使用真实 DNS**，严格无泄漏配置不要选择此模式，除非完整审计所有未列出的代理域名。空白名单不会分配 Fake-IP。`rule` 模式仍明确拒绝，不假装支持 GeoSite/RuleSet 特殊条目。
- 新增配置大小写兼容测试、白名单空集/大小写/通配符匹配测试、带模拟上游的解析器测试（保护域名不触发上游查询，未受保护域名触发真实查询）、原始配置→运行时模式转发金标准。额外增加对 `geosite:`、`rule-set:` 和 `RULE-SET,`/`GEOSITE,`/`MATCH,` 等 Mihomo 高级 `fake-ip-filter` 条目的明确拒绝；否则它们可能作为字面主机名被跳过，在 whitelist 下使未匹配域名走真实 DNS。当前原有 `fake-ip-range6` 的真实运行路径及系统 DNS/TUN 抓包不在本切片覆盖范围。
- 本轮验证：`cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6`：816 passed / 0 failed / 11 ignored；`cargo test -p clash-lib --test dns_config_tests --no-default-features --features tun,ring --locked`：17 passed；`cargo test -p clash-lib --lib --no-default-features --features ring --locked whitelist`：3 passed；无 TUN 的内部配置拒绝测试 1 passed；`cargo check -p clash-rs --no-default-features --features standard,aws-lc-rs --locked`、`cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring --locked -j 6 -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 均通过。原始→内部配置的白名单金标准及高级 filter 错误测试均通过。
- 已知独立金标准冲突：`dns_legacy_golden_tests` 全部执行为 12 passed / 1 failed；失败的是 `s00_respect_rules_and_legacy_proxy_modifier_are_preserved`，在本轮修改前的 `0c36e2e` 中已经与 `dns.respect-rules` 必须存在 `proxy-server-nameserver` 的校验不一致。不能把该失败当成 whitelist 回归，也不能静默更新金标准测试；需要独立的兼容性决策和修正。
- 后续开发应优先检查尚未合入的 `codex/macos-mihomo-privacy-field-guard-20261105` (2c7fd34)，避免重复工作；仍需评估代理服务器 DNS 引导回退和 macOS 系统级失效关闭。无授权不修改机器网络、不推送。

## 2026-11-06 Mihomo proxy-server-nameserver-policy（普通域名子集）

- 独立开发起点是本地 `e8e9fcce761d8e6cb233c45cd1cf91dd77fd212f`，固定 Mihomo 参考 gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。源码对照 `config/config.go::parseNameServerPolicy` 与 `dns/resolver.go` 的专用节点解析器。参考目录保持只读。没有同步、合并、推送或修改 macOS 宿主网络。
- 允许有序普通域名选择器、逗号分隔多个域名、单值或多值 DNS 上游、大小写不敏感；连接节点域名优先使用选中策略，否则使用独立 `proxy-server-nameserver`。专用解析器/策略失败时不自动切换到主 DNS 或 fallback；内部配置也不能绕过专用节点 DNS 必填检查。Network path reset 覆盖策略客户端。
- 本阶段明确拒绝尚无等价行为的 `geosite:` / `rule-set:`、`system` DNS 上游及策略内部 `#proxy`。匹配依赖 Chimera 现有域名 trie；并不等价于 Mihomo 完整 RuleSet、GeoSite 和特殊出站语义。对实际 macOS 系统物理网卡的 DNS 零泄漏仍没有运行时抓包证明。
- 增加定向 YAML/运行时/模拟上游测试：规则顺序、多个上游、大小写、策略命中和未命中、专用 DNS 错误 fail-closed、网络路径重建和内部配置校验。另将相同的有序节点策略挂入 DNS 传输层实际使用的独立 `outbound_resolver`，测试该调用入口命中策略和未命中走专用默认解析器；内部 Config 热更新即使直接输入 `geosite:` 也会拒绝。`dns_legacy_golden_tests::s00_respect_rules_and_legacy_proxy_modifier_are_preserved` 仍有先前的 `respect-rules` 校验差异，需要单独兼容性决策，不能藉本次改动无依据更新测试。
- 验收待补：默认/全功能和无 TUN 组合、Linux/Windows、真实 DNS 节点和 macOS TUN/NIC 出口、L2 独立 Reviewer 和维护者批准，均不得由单纯配置解析或模拟上游测试替代。

## 2026-11-06 Mihomo direct-nameserver-follow-policy 与原有金标准冲突（L2 待审）

- 基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy` HEAD `a734515f5e33027013cc0bb3652272ed49a120e3`；`master=e42dabe74282c77245da1023de0b828830928216`，`origin/master=902c5e7702960ab4f978a014d7079c79d17079fd`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。参考 `ref-mihomo/config/config.go::parseDNS`、`ref-mihomo/dns/resolver.go` 的 DirectResolver 及 `DirectFollowPolicy`，只读不修改参考目录。
- 新增 `dns.direct-nameserver-follow-policy: bool`，默认 false；通过原始 YAML → 运行时 Config → `EnhancedResolver::new` 的 DIRECT 解析器创建 → Dispatcher 选用 DIRECT 解析器。配置为 true 时，DIRECT 解析器与主解析器共享已编译的 `nameserver-policy`（同一组客户端），规则匹配时走指定 DNS 上游，匹配失败不转主 DNS。未命中使用 `direct-nameserver`；此时专用上游故障也不回退普通 DNS，以免 QNAME 越过显式 DIRECT 策略边界。false 保留原先的 direct→main fallback，以兼容旧 Chimera 行为；未配置 `direct-nameserver` 时与 Mihomo 一样没有专用 DirectResolver，此字段不会改变主解析器。
- 同时修复主 DNS `nameserver-policy` 构造和 QNAME 匹配的大小写问题（之前混合大小写可绕开策略）；DIRECT 共享同一组策略客户端也获此修复。因共享策略也共享客户端，将其网络切换重置的所有权留在主解析器；DIRECT 子解析器只重置自己独有的传输，避免同一策略客户端重置两次。新增解析配置、模式开关、匹配/未匹配、多上游失败不回退、混合大小写策略、共享策略重置、调用链测试；无真实 DNS、NIC 或 TUN 外网请求。
- **保留的 S00 金标准冲突**：`dns_legacy_golden_tests::s00_respect_rules_and_legacy_proxy_modifier_are_preserved` 仍要求 `respect-rules: true` 无 `proxy-server-nameserver` 可通过，但固定 Mihomo `parseDNS` 必须要求节点引导 DNS。选择安全语义后，该旧金标准不再符合当前兼容约束；不能为了绿色测试放宽安全校验、禁用测试或擅自更改历史金标准。本轮新增独立正反配置测试证明：缺少时明确拒绝，补上专用节点 DNS 后 `#proxy=PROXY` 保留。旧用例改版需独立 L2 兼容性决策及维护者批准，测试缺口继续如实报告。
- 本阶段（TUN + Ring）核心单测 834 passed / 0 failed / 11 ignored，DNS 配置集成 26 passed / 0 failed；严格 Clippy、无 Dashboard CLI 编译、Rust 格式和 diff 检查通过。无 TUN 的完整库测试为 800 passed / 7 failed / 9 ignored：7 项均为既有 `config::internal::convert::tests` 的 TUN 正例在关闭 TUN feature 下得到预期的配置拒绝，但旧测试仍要求成功；本轮新增的无 TUN `direct_follow_policy` 两项及共享重置一项通过。旧 S00 金标准仍为 12 passed / 1 failed（缺少节点引导 DNS 的 `respect-rules` 用例），需维护者独立决定迁移；未修改这些历史测试。
- 仍需专用 macOS 受权网络测试环境完成 DNS 出口抓包、切换网络服务、IPv6、DIRECT 和代理节点上游故障、TUN 关闭等边界验证；无法据单测证明系统级 DNS 零泄漏。

## 2026-11-06 Mihomo nameserver-policy 普通域名子集安全增强（L2 待审）

- 基线：本地 `9dfd4b327eb6a67f1adfc84796473c518face9cb`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy`。参考 Go 实现会将逗号分隔的域名键拆开，对 `geosite:` 和 `rule-set:` 建立专用 Matcher；Chimera 仍没有这两个 Matcher，不能让输入静默落为字面 domain trie。
- 原始配置 `dns.nameserver-policy` 现在支持普通域名逗号拆分，保持每条规则**仅单个**上游字符串的既有格式；任何 `geosite:`/`rule-set:` 子键明确报错（即使混在逗号列表中），重复域名键拒绝以避免 HashMap 不确定覆盖；普通域名键在转换时转小写。内部配置与热更新也拒绝高级选择器和未拆分逗号键，避免绕过 YAML 的防泄漏校验。完整 GeoSite/RuleSet、多上游数组与 Mihomo 有序规则优先级尚未实现。
- 测试按“旧实现失败 → 修复后通过”增加逗号匹配、GeoSite/RuleSet 显式拒绝、重复键检测及内部配置无法绕过用例；旧版单个字符串上游 S00 金标准定向测试仍通过。TUN + Ring 核心单测 835 passed / 0 failed / 11 ignored，DNS 配置集成 29 passed，严格 Clippy、无 Dashboard CLI 编译、fmt 与 diff 检查通过。旧版 DNS 金标准全套仍为 12 passed / 1 failed（历史 `respect-rules` 夹具冲突），未修改旧测试。没有对真实 macOS 系统 DNS、NIC、TUN 或代理出站进行操作。

## 2026-11-06 Mihomo fake-ip-ttl 合成应答语义（L2 待审）

- 基线本地 `36ad858c18b633d547b7d02c7356b82998f00e9a`；对照固定只读 Mihomo `ref-mihomo/config/config.go`、`dns/enhancer.go`、`dns/middleware.go::withFakeIP`：默认 TTL 1 秒，值低于 1 秒向上规范化；仅对真正合成的 Fake-IP A/AAAA DNS 答案应用该 TTL。
- 从原始 YAML `dns.fake-ip-ttl` 到内部 DNS 配置、解析器和共享 DNS handler 接通，影响普通 DNS server、TUN UDP/TCP hijack 与 DNS API 共用的应答函数。仍未支持运行时完整 Fake IPv6/TUN 抓包认证，不可据此宣称全系统 DNS 零泄漏。
- Fake-IP 排除域名 A/AAAA 的响应继续使用真实上游 DNS 原始 RRset（包含实际 TTL），**不能**将合成 Fake-IP TTL 写入真实记录；带有 hosts 改写的路径也需后续独立验收。PTR 仍保留现有独立 TTL，不因 fake-ip-ttl 改变。
- 原 Chimera 合成 Fake-IP TTL 默认 60 秒；本轮默认改为 Mihomo 一致的 1 秒，属于向后兼容的可观察行为变化，需 L2 审查；如必须保留 60 秒，可显式设置 `fake-ip-ttl: 60`。定向测试覆盖默认、0/负数钳制、自定义 45 秒、合成 A/AAAA、过滤排除真实 TTL 与真实配置构造；实际系统 DNS 和物理 NIC 未测试。

## 2026-11-06 XHTTP 二次连接系统 DNS 旁路保护（L2 待审）

- 本地起点 `4cdac10187ebb2075f56b24e63d6ed10ab7156ca`，隔离分支 `codex/macos-tun-fakeip-dns-privacy`；本地 `master=e42dabe74282c77245da1023de0b828830928216`、`origin/master=902c5e7702960ab4f978a014d7079c79d17079fd`。固定参考 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 未变更。
- 源码路径：`proxy/transport/xhttp/mod.rs::connect_endpoint_stream` 对 HTTP/2 `download-settings` 独立下行和 HTTP/1.1 后续 upload reconnect 直接调用 `tokio::net::lookup_host`，并没有接收专用 `proxy-server-nameserver` 的解析器。macOS 的 service-scoped DNS 查询不一定经过 utun，`dns-hijack: true` 无法证明对此路径生效；只要 secondary endpoint 是域名，就可能触发系统 resolver。
- 在 `tun.enable && dns.enable && enhanced-mode: fake-ip` 时，内部配置 `Config::validate` 拒绝需要系统 DNS 的 XHTTP HTTP/1.1 hostname 重连、HTTP/2 非 IP 字面量的有效 `download-settings` 终端；包括 `xhttp-opts.extra.download-settings` 优先于顶层 download-settings 和隐式继承主节点域名的情形。只输出选项名，不回显可能敏感的 endpoint。普通 HTTP/2 代理节点使用已有专用节点解析，不会因此被拒；`download-settings` 指向 IP literal 仍可用。HTTP/3 已使用包含解析器/connector 的单独连接路径，此门禁不机械应用于 HTTP/3。
- 影响：原来允许的 TUN + Fake-IP + XHTTP split-downlink 域名或 HTTP/1.1 节点域名现在会被拒绝。可暂时使用受控 IP literal secondary endpoint（保留 TLS SNI / 证书校验设置），或者在**未启用上述隐私敏感组合**时保留旧行为。此拒绝不等于端到端 DNS 隔离认证。
- 实际验证边界：这只是静态/热重载和离线单测的 fail-closed 防线；代理 provider 动态下发的节点和其它仍调用系统 `lookup_host` 的模块（包括 AnyTLS inbound fallback）不一定受此特定校验保护；Network Extension DNS Proxy、浏览器 DoH/DoT、自定义系统 service-scoped resolver、跨网卡 IPv4/IPv6、睡眠/断线/切网及真实抓包仍未完成，不能声称全系统零泄漏。

### macOS 系统级 DNS 受控验收矩阵（尚未执行）

> 以下是**授权的独立 macOS 测试机**验收计划，不是本轮运行日志。不得在用户日常网络或与其它代理实例共用的宿主机自动执行网络设置或特权抓包。

| 场景 | 必须核实的事实 | 当前可用证据 / 缺口 |
| --- | --- | --- |
| 系统 resolver 正常请求 | `scutil --dns` 中活动 service-scoped resolver 的顺序、接口与 DNS 服务器；向专用测试域名 A/AAAA/TXT 发请求，证明是否进入 Chimera DNS listener 或 utun | 目前只有 listener/TUN 内部单测；service-scoped ownership 无证据 |
| UDP/TCP 53 与 IPv4/IPv6 | 在物理 NIC 和 utun 同时抓包，只比较专用 canary QNAME 的出现位置；包括 UDP 截断转 TCP、TCP 多问题拒绝和 IPv6 | 目前无受权 NIC 抓包；不应将局部 TUN 劫持称为物理 NIC 禁止出站 |
| XHTTP H2 split / H1 reconnect | 有意配置域名 secondary endpoint，TUN+Fake-IP 加载应在启动前拒绝；IP literal 保留行为。模拟动态 Provider / 非 TUN 时单独检查 | 配置校验与离线测试覆盖静态/热重载；Provider 仍有缺口 |
| 网络切换 / Wi-Fi → 其它物理 NIC / 睡眠恢复 | 触发系统 DNS resolver 变化、上游断线、DNS 超时并记录是否重新建立受控 ownership；验证失败时没有退回 service DNS | 现有 network epoch/重置只验证内部 DNS 连接，不是 OS 级 ownership |
| TUN 关闭 / DNS Proxy Extension 丢失授权 | 用专用 canary QNAME 验证系统入口是否依旧受控；如果严格防泄漏能力不可用，受保护请求必须拒绝，不可静默调用系统 resolver | 没有安装/启用 DNS Proxy Extension，也没有可证明的 fail-closed OS 接管事务 |
| 真实及受限出站 | 区分业务明确允许的 DIRECT、代理节点 bootstrap、显式 `fake-ip-filter` 和非受保护流量；只断言指定 canary 的未授权明文泄漏 | 需要维护者明确保护域集合及合法例外，不能泛称物理 NIC 不能有任何 DNS |

- 执行策略：先取得测试机所有者的明确许可，记录活动服务的原始配置以便回滚；用测试专用、不包含真实订阅或用户域名的 canary；通过系统**只读**检查与有权限的专用抓包并行关联，记录不含私有 QNAME 的摘要。没有 DNS Proxy Extension 或等效受管控制面时，验证结论只能是“覆盖不完整”，不能写“零泄漏”。
- 本地验收（macOS arm64，`--no-default-features --features tun,ring --locked`）：`cargo test -p clash-lib --lib -j 6` 843 passed / 0 failed / 11 ignored；`cargo test -p clash-lib --test dns_config_tests -j 6` 30 passed / 0 failed；`cargo clippy -p clash-lib --all-targets -j 6 -- -D warnings`、`cargo check -p clash-rs --no-default-features --features standard,aws-lc-rs --locked`、`cargo fmt --all -- --check`、`git diff --check` 通过。无 TUN 组合编译通过，但过滤特定 TUN 测试实际运行 0 项，不计作行为验收。离线测试先证实旧实现错误接受需系统 DNS 的 XHTTP secondary hostname，再验证配置转换、`extra.download-settings` 优先级、内部热重载的拒绝和 IP-literal/普通主节点的保留。

## 2026-11-06 AnyTLS 入站 fallback 系统 DNS 隔离（L2 待审）

- 基线：`codex/macos-tun-fakeip-dns-privacy`，本切片前 `HEAD=bb172c82f2737e3e003da6e979a37e352b469eff`，本地 `master=e42dabe74282c77245da1023de0b828830928216`、`origin/master=902c5e7702960ab4f978a014d7079c79d17079fd`。只读参考为主检出 `ref-mihomo` 固定 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本隔离工作树中子模块未检出，未更改 gitlink。固定 Mihomo `config/config.go::RawDNS` / `parseDNS` 用于 DNS 字段与失败路径对照；AnyTLS inbound camouflage fallback 是 Chimera 本地特定路径，本切片不声称存在同名 Mihomo 等价字段。
- 发现 `proxy/anytls/inbound/handler.rs::connect_fallback_backend` 在 AnyTLS 身份验证失败时调用 `tokio::net::lookup_host(fallback_addr)`，即使 TUN + Fake-IP 已启用，也不使用 Chimera 的受管 DNS 引导。macOS service-scoped resolver 可能通过物理 NIC 发出域名查询，不能以 TUN hijack 推断已保护。
- 在 `config/internal/config.rs::Config::validate` 为 `feature=anytls` 的 AnyTLS 入站增加保护：仅当 `tun.enable && dns.enable && enhanced-mode: fake-ip` 且配置了 `fallback` 时，要求值为可解析的 IP 字面量 `SocketAddr`（IPv4 `192.0.2.53:443`、IPv6 `[2001:db8::53]:443`）。域名或未明确端口的地址 fail-closed，报错不包含 hostname/密码；没有 fallback、未启用 TUN 或 DNS 的旧行为保持不变。此门禁同样覆盖内部配置热重载。
- 测试先在原有调用链下写拒绝域名的否定测试，新增 `fake_ip_tun_rejects_anytls_fallback_system_dns_hostname`、`fake_ip_tun_allows_anytls_ip_literal_fallback_and_non_tun_hostname`、`anytls_inbound_fallback_cannot_bypass_gate_by_internal_reload`。无实际 TUN、系统网络、权限提升或 NIC 抓包。迁移方式：敏感组合的 AnyTLS fallback 改用受控 IP:port（IPv6 必须方括号），或取消 fallback；不能把放宽 TUN 隐私设置视为等价的防泄漏方案。
- **限制**：静态配置拒绝不等于 OS DNS ownership / 全局防泄漏；动态 provider、其它系统解析器、DIRECT/代理节点 DNS、浏览器 DoH/DoT、切网、睡眠、IPv6 及真实物理 NIC 仍需独立授权测试。此行为变更需要 L2 独立 Reviewer 与维护者批准，不自动推送/合并。

## 2026-11-06 AnyTLS 入站 fallback 的系统 DNS 旁路（L2 待审）

- 开发起点 `bb172c82f2737e3e003da6e979a37e352b469eff`；`clash-lib/src/proxy/anytls/inbound/handler.rs::connect_fallback_backend` 在 TLS 客户端认证失败后，对 `fallback` 字段调用 `tokio::net::lookup_host`，绕过 Chimera 自己的 DNS resolver。macOS 的 service-scoped resolver 并不保证经过 utun，因此在 TUN + Fake-IP 的严格隐私场景下可能发生未受控 DNS 外发。
- 新的内部 `Config::validate` 校验在 `tun.enable && dns.enable && enhance_mode=fake-ip` 时拒绝 AnyTLS inbound `fallback` 非 `SocketAddr` 的值，只允许不需要系统解析的 `IPv4:port` 或 `[IPv6]:port`；`fallback` 未设置或 TUN 关闭时保留原有配置行为。配置错误不输出实际 fallback 地址。此改动限制原先允许的 hostname fallback，部署者可将该回退终端改为静态 IP 地址并自行确保 TLS/服务端兼容。
- 使用 `tun,ring,anytls` 特性组合的离线测试先确认旧配置错误地允许 hostname fallback，再覆盖普通加载、IPv4/IPv6 字面量、非 TUN 兼容及 Internal 热重载无法绕过。最终 `cargo test -p clash-lib --lib --no-default-features --features tun,ring,anytls --locked -j 6` 为 883 passed / 0 failed / 11 ignored；`cargo test -p clash-lib --test dns_config_tests --no-default-features --features tun,ring,anytls --locked -j 6` 为 30 passed；`cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring,anytls --locked -j 6 -- -D warnings`、fmt、diff 检查通过。无真实 AnyTLS 认证失败的外网请求或 macOS DNS/NIC 抓包。
- 此门禁仅涵盖代码可确认的 AnyTLS 入站伪装回退。不代表对所有通过 libc/getaddrinfo、浏览器 DoH、网络扩展、XHTTP 动态节点以及未识别的系统 DNS 路径均已控制；macOS DNS Proxy Extension 的服务级接管、可审计的出口保护和物理 NIC 的独立抓包仍未实现。

## 2026-11-06 XHTTP 动态 Provider 解析路径的防旁路校验（L2 待审）

- 开发起点 `76b27f3ee53f13e8b00b10af7d43d405969f9712`；固定 `ref-mihomo` gitlink 未变更。本地隔离分支 `codex/macos-tun-fakeip-dns-privacy`，没有同步远端、合并或操作宿主机网络。
- 补齐 `ProxySetProvider` 的**运行时更新入口**。之前 YAML 静态 `Config::validate` 可以阻止 XHTTP HTTP/2 独立下载和 HTTP/1.1 重连中的系统 DNS 域名，但是 HTTP/file Provider 后续从远端或文件更新新 VLESS/XHTTP 节点时会直接执行 `OutboundProxyProtocol::try_from` → `OutboundManager::load_provider_outbound`，不会再经过静态 Config 校验。此旁路可重新引入 `tokio::net::lookup_host` 触发的 macOS service-scoped DNS。
- `runtime::factory` 只在 `tun.enable && dns.enable && dns.enhance_mode=fake-ip` 时将隐私保护标志传入 `OutboundManager`，由 Http/File ProxySetProvider 的解析闭包应用与静态配置**相同**的 XHTTP secondary 域名拒绝逻辑。若任意新节点违反此保护，整次 Provider 更新报错、保留上次已生效的节点集合、内容 revision 和本地缓存；不得只过滤掉危险节点再悄悄发布部分更新。错误不输出敏感的 hostname。IP 字面量 downlink 与未启用此保护的旧行为保持可用。
- 测试使用完全离线的 `MockProviderVehicle` 和临时缓存，覆盖：初始安全代理、动态加载危险 H2 secondary hostname、混合安全 SOCKS + 危险 H1 reconnect 的原子拒绝、旧 revision/cache 保留、IP 字面量 XHTTP 和非严格模式下的域名兼容。没有真实订阅、DNS 查询或物理 NIC 出站。
- TUN + Ring 本地回归：`cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6` 847 passed / 0 failed / 11 ignored；`cargo test -p clash-lib --test dns_config_tests --no-default-features --features tun,ring --locked -j 6` 30 passed；严格 Clippy、无 Dashboard CLI 编译、fmt 与 diff 检查通过。没有证据支持“整个 macOS 系统的 DNS 已被接管”或“物理网卡零泄漏”。
- 剩余风险：DNS Proxy Extension ownership、macOS service-scoped resolver、浏览器内置 DoH/DoT、其它可能调用系统 resolver 的传输，以及独立授权测试机上的 IPv4/IPv6 NIC 与 utun 双边抓包未解决。动态 Provider 筛选基于此时的 TUN + Fake-IP 运行配置；运行时模式切换应通过重新构造 Provider 或显式重新校验完成，不能依赖旧标志代替真正的系统级 DNS 保护。
- `tun,ring,anytls` 组合的最后回归：`cargo test -p clash-lib --lib --no-default-features --features tun,ring,anytls --locked -j 6` 887 passed / 0 failed / 11 ignored；DNS 配置 30 passed；严格 Clippy 通过。额外执行旧 S00 `dns_legacy_golden_tests` 全套仍为 12 passed / 1 failed，唯一失败仍是历史 `respect-rules` 未指定节点引导 DNS 的夹具冲突，未修改测试、未标为新回归。静态配置与动态 Provider 均按同一规则执行，但仍需后续 L2 独立代码审查及测试机系统级 DNS 出口验证。
