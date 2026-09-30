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
