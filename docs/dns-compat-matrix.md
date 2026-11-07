## 2026-11-10 — P0：父 resolver 排队重置被取消时 DIRECT 子 resolver 失效关闭（L2 待审）

- 固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本工作树未检出 Go 源码，未完成本轮 Go 行为对照。该补丁针对 Chimera Rust async cancellation，**不宣称 Mihomo 全部运行语义等价**。
- 新增 `cancelled_parent_reset_waiting_for_lock_must_close_direct_child`：测试持有父 resolver reset mutex，排队父 reset 后取消；DIRECT 子 resolver 尚未开始 reset。修复前 **0/1 失败**：子 resolver 仍能使用旧网络上游；修复后 **1/1 通过**，且完整父子恢复后查询重新可用。
- 新增 `ClashResolver::invalidate_transports()` 同步默认空实现（兼容既有 System/Legacy resolver）；EnhancedResolver 实现立即失效关闭自身及 DIRECT 子 resolver。父 reset 在首个 `.await` 前同步调用，避免取消时子 reset future 从未被轮询。未改变系统 DNS/TUN/路由。
- 定向 EnhancedResolver 回归 **176 通过、0 失败、7 忽略**；DNS 配置集成 **46/46**；严格 Clippy (`tun,ring`, `all-targets`, `-D warnings`)、fmt、diff --check 通过。新增恢复断言通过；仍需全库回归、最小 feature、独立 L2 Reviewer、跨平台/真实 NIC 与 utun 抓包。
- 剩余风险：`invalidate_transports` 是逻辑门禁，不能代替 macOS 系统 DNS ownership 与物理出口隔离；并发独立子 reset/父 reset 的恢复线性化需继续审查。回滚时应一并移除 trait hook 与父子预失效调用，并保留 fail-closed 测试作为验收约束。

## 2026-11-10 — P0：取消部分 transport reset 后必须保持失败关闭（L2 待审）

- 固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，只读检查 `dns/resolver.go::ResetConnection`（循环重置 main/fallback/default；Go 的该函数无 Rust 异步取消语义）。本修复属于 Chimera 异步生命周期安全增强，**不代表完整 Mihomo 等价**。
- 新增 `cancelled_partial_reset_stays_fail_closed_until_successful_recovery`：模拟首轮 reset 永不返回、取消任务、随后查询及第二轮恢复。修复前 **0/1 失败**：取消后查询竟然访问旧 transport；修复后 **1/1 通过**，且成功完整 reset 后查询恢复。
- `reset_transports` 在首个异步等待前将 transport 集合标记为不可用，使用异步互斥锁串行化 reset，只有整轮成功才清除失败标记；取消或部分失败均保持失效关闭。保留查询门禁、网络代际缓存失效及旧 YAML 兼容。原取消测试的“取消后允许旧 transport 查询”期望改为安全拒绝。
- macOS ARM64 / Rust 1.99.1：修复前定向 0/1、修复后 1/1；transport-reset 定向回归 5/5；默认特性 + tun/ring 核心库 1199 通过、0 失败、11 忽略，DNS 配置集成 46/46；严格 Clippy（all-targets）、fmt 与 diff --check 通过。最小特性（no-default + tun/ring）严格 Clippy 和新增定向测试 1/1 通过。
- 仍需 L2 独立审查、并发 reset 确定性测试、完整 feature/跨平台回归、macOS 物理 NIC/utun 抓包。未修改系统网络。


## 2026-11-13 15:10 PST — 受保护候选 HTTP Provider 缓存预热与提交后激活（L2 待审）

- **基线**：在本地 `master` 的 `2e5ac13350f5ffa329bfd8014a8b54fe9a1460f5` 上迭代，开工时 `origin/master` 与远端 `master` 同 SHA；固定 Mihomo `ref-mihomo` 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。本改动没有对应的上游发布/提交事务 API，因此只实现 Chimera 本地运行时语义，没有改动参考子模块。
- **能力变化**：macOS + TUN + DNS Fake-IP 的未提交热更新候选，现在可解析并应用本地有效的 HTTP proxy/rule provider 缓存；候选构建阶段不启动 HTTP 拉取、轮询、文件写入或远端健康探测。缓存缺失或解析无效时保留原文件并延迟首次拉取。仅在旧 DNS owner 退休且新 DNS resolver/listener 发布后，异步启动这些 provider 的远端初始化；首次初始化采用 3 次尝试（含两次 250ms、1s 退避）。若三次均失败，非零 interval 继续走已有轮询；interval 为 0 时不启用周期刷新，provider 仍保留注册。对有效缓存，interval 为 0 保持原有“只用缓存、不远端刷新”语义；缺失/无效缓存仍会在提交后首次拉取。其他普通/非受保护配置沿用原初始化路径。
- **回归覆盖**：`protected_candidate_http_provider_fetches_only_after_commit` 验证损坏缓存提交前不改写、commit 后恢复节点并保存有效响应；`protected_candidate_http_proxy_provider_uses_cache_and_keeps_it_on_refresh_failure` 验证有效代理缓存和 selector 在提交前可用、提交后 503 不清空现有缓存/节点；三个 HTTP rule-provider 用例分别验证无缓存的提交后抓取、首次 503 后重试成功，以及有效缓存且 interval=0 时提交前后均不远端访问；`nonprotected_candidate_preserves_legacy_http_provider_bootstrap` 覆盖旧路径；既有受保护文件 provider health-check 用例继续覆盖候选期禁止探测及提交后恢复。测试服务只绑定 loopback，不查询公网 DNS，不启动真实 TUN 或修改系统网络。
- **验证**（macOS ARM64，Rust 1.99.1）：定向过滤 `candidate_` **28/28**；最小 `--no-default-features --features tun,ring` 的 `clash-lib --lib` **1098 通过、0 失败、11 忽略**；带默认 feature 的 `clash-lib --lib` **1290 通过、0 失败、11 忽略**；带默认 feature 的严格 `cargo clippy -p clash-lib --features tun,ring --all-targets --locked -j 2 -- -D warnings` 通过；`cargo fmt --all -- --check` 与 `git diff --check` 通过。独立 Reviewer 指出 interval=0 的首次失败没有自动恢复后，新增 `protected_candidate_http_rule_provider_retries_zero_interval_bootstrap`，首请求 503、第二请求成功的用例连续 **5/5** 通过；没有通过 lint 例外压制警告。
- **限制**：本轮没有 Linux/Windows 编译或运行、真实 macOS NIC/utun 抓包、系统 DNS 接管测试、外网服务实测或 GitHub CI。只有 HTTP provider 获得该两阶段行为；MMDB/GeoSite 候选下载仍由之前的保护逻辑拒绝。提交后启动的 provider 请求是异步的，reload 成功只表示运行时候选已发布，不保证远端 provider 当时可达；失败保留当前缓存/可用节点，interval 非零时已有轮询继续重试，interval 为 0 时仅完成 3 次无缓存/无效缓存的首次尝试，后续需显式刷新。最终 SHA 尚未形成，独立 L2 审查与维护者验收待完成；回滚本轮时需一并恢复 `factory.rs` 的受保护 HTTP 拒绝逻辑与 provider 延后激活调用，避免重新打开候选期出站窗口。

# DNS 兼容契约矩阵（S00 / 开发基线）

## 2026-11-10 — 网络重置不得隐式启用 DNS 正缓存（P0 回归）

- 固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本隔离工作树的 `ref-mihomo/` 未检出，无法在本轮直接运行 Go 对照。该用例验证 Chimera 自身的禁用缓存契约，不代表完整 Mihomo 互操作。
- 新增 `network_reset_does_not_enable_disabled_positive_cache`：`from_clients()` 默认不启用正缓存；执行 `reset_transports()` 后连续两次相同 A 查询必须访问上游两次，且不得创建新代际正缓存。定向测试 **1/1 通过**（首次即通过，未发现新生产缺陷）。
- 清理仅当前隔离工作树的可再生成 `target/debug/incremental`（约 610 MiB），使用 `CARGO_INCREMENTAL=0`。本轮仍未进行 NIC/utun 抓包或 L2 独立审查。

## 2026-11-10 — Provider ABA 与网络重置叠加的 NXDOMAIN 回归（P0，L2 待审）

- 在 `clash-lib/src/app/dns/resolver/enhanced.rs` 新增 `provider_aba_and_network_reset_during_dedicated_negative_lookup_fail_closed`，使用可控暂停的节点 DNS TXT/NXDOMAIN 查询，交错执行 Provider 注销→重新注册和 `reset_transports()`，验证旧节点负响应不得返回。定向测试 1/1 通过；未改生产运行时，不能视作修复新的漏洞。
- 固定 `ref-mihomo` gitlink 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本工作树缺少实际 `ref-mihomo/dns/resolver.go`，本轮仅核对 gitlink，未完成 Go 源码级对照。macOS 物理 NIC/utun 抓包、L2 独立审查仍未完成。


## 2026-11-09 19:59 PST — Provider Epoch Cache：防旧写入与 Network Reset 失效关闭（P0，待独立 L2 审查）

- **实时基线**：macOS @appledev 隔离工作树 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`，分支 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；开工前已有 8 个未提交文件，全部保留。固定 Mihomo 只读提交 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，其 `dns/resolver.go` 为普通与代理节点 DNS 使用独立 resolver/cache；Chimera 当前的动态 Provider 代际隔离属本地额外机制，**尚不能宣称 Mihomo 二进制语义完全等价**。
- **新发现与修复 A（写入 ABA）**：`ProviderEpochCacheEntry` 的读端虽能拒绝不同代际的条目，但写端原先无序覆盖，旧查询可能在新代际查询完成后重新覆盖有效缓存。先写 `stale_writer_must_not_replace_newer_provider_epoch_cache_entry`，修复前确认为 **0/1 失败**；随后在缓存锁内用 `peek` 比较代际，旧代际写入不再覆盖较新的有效条目，修复后 **1/1 通过**。这消除缓存退化/污染，但不能将所有上游结果交付与 Provider 更新视作系统原子事务。
- **新发现与修复 B（网络重置）**：`reset_transports()` 原先会清空代际缓存，但在该网络路径上早已发出的普通查询仍能在 reset 后返回或重新填入旧答案；缓存候选已选取后执行 reset 也能交付旧正/负响应。按“否定测试先失败”要求，`network_reset_during_former_provider_lookup_must_not_reseed_epoch_cache` 修复前 **0/1 失败**；`network_reset_rejects_selected_{positive,negative}_provider_epoch_cache` 修复前 **0/2 失败**。现新增 `provider_epoch_network_generation: AtomicU64`：reset 在持有代际缓存 Mutex 的同时递增网络代际并清空条目；查询读取时保留网络代际，异步上游返回、缓存写入（同一 Mutex 内校验）和选中缓存交付前再次检查，旧网络查询显式失败且不会重新缓存。上述测试修复后 **3/3 通过**。
- **恢复/兼容回归**：`network_reset_rejects_stale_epoch_cache_writer_under_same_lock` 验证旧网络 token 的直接插入失败，新网络 token 仍可缓存；`new_network_former_provider_query_caches_after_reset` 验证 reset 后当前网络普通 A 回应连查两次只调用一次上游，且不会泄漏到节点专用解析器。旧版 `old_public_*`、`provider_epoch_*`、多所有者及 Fake-IP/DNS 兼容测试继续运行。未更改不带代际标识的普通域名缓存行为。
- **目标编译测试**：Rust 1.99.1、macOS ARM64、`--features tun,ring`：`cargo fmt --check` 与 `cargo clippy -p clash-lib --features tun,ring --all-targets -- -D warnings` 通过；库单测 **1184 通过、0 失败、11 忽略**；`dns_config_tests` **46/46**，S00 `dns_legacy_golden_tests` **14/14**，S01 **17/17**、S02 **14/14**。最小 `--no-default-features --features tun,ring`：严格 Clippy 通过，库单测 **992 通过、0 失败、11 忽略**，DNS 配置 **46/46**、S00 **14/14**；`git diff --check` 通过。端口冲突日志来自故意覆盖 DNS listener 启动失败的通过用例，并非额外失败。
- **Further P0 regression**: Active Provider node DNS queries crossing a transport reset previously returned stale old-network addresses (`network_reset_during_active_provider_node_query_fails_closed`, red 0/1 then green 1/1). The outer resolver now revalidates network epoch before returning active-node answers. A static proxy node failed the same red test (0/1) because the outer static lookup searched a trailing-dot QNAME while the actual node dispatch searched a normalized name. The outer path now uses the same lowercased, trailing-dot-free `domain_name_of_message` as dispatch. The static test now passes 1/1, and `static_node_uses_normalized_qname_before_public_cache_selection` proves mixed-case static node requests bypass ordinary DNS cache selection, not merely reclassify after a cache hit. Node reclassification also revalidates network epoch.
- **Additional tests**: `network_reset_does_not_downgrade_active_provider_to_public_dns` verifies node DNS remains dedicated after a successful reset; `provider_epoch_nodata_txt_cache_uses_soa_minimum_and_expires` verifies RFC 2308 NOERROR/NODATA TXT caching follows SOA.MINIMUM. Twenty parallel reset-concurrency repetitions passed, each using 16 test threads. No system DNS, TUN, route or Network Extension changes were made.

- **远端只读核对**：`master=0b81617d828d73b66553104a11970622eda9268a`，master 的 CI run `42674574124` completed/success；开放 PR #111/#110/#85/#58。远端 CI **不是当前未提交改动的 CI**，本轮不推送、不合并、不更新 PR、不重写历史或修改物理 Mac DNS、路由、TUN、Network Extension、权限。
- **待审风险和下轮精确工作项**：① 普通未标记 Hickory `ResponseCache` 在 `reset_transports` 中**未被清空**（Hickory 的 `clear` 是 crate-private），不能把本轮历史 Provider 的保护套用于所有普通 DNS；需要独立、可回滚的网络代际/缓存所有权设计与否定测试。② `reset_transports` 的异步上游重置尚未用可控暂停测试覆盖“重置正在进行而新查询发出”的窗口；不同平台网络实际切换和 DNS resolver 接管/回退需实机验证。③ macOS 物理 NIC 与 utun 抓包、独立 L2 Reviewer、所有临界点交付原子性尚未完成。**不要据此宣称系统级零 DNS 泄漏**。


> 状态：**S00 实测/源码基线，不是 S01–S08 的功能承诺或弃用批准**。
> 指南：[`chimera-nextgen-dns-ai-guide.md`](chimera-nextgen-dns-ai-guide.md)，主要依据 §2、§3、§14、§17。
> 本地基线：`275ac992808acac4dd51783f5fc295c157218f8e`；指南公开基线：`71ddfd62ddb3dd6820130ae6282a786dfbe0b87f`。远端 `origin/master` 当时为 `71ddfd6`。
> **A = Core/Keep、B = Legacy/Review、C = Skip/Reject** 是指南的*产品取舍建议*，与“当前实现状态”是两个不同的判断轴。除非有 Decision 及维护者批准，表中的建议**不构成删除旧字段的授权**。

## 2026-11-09 18:01–18:04 PST — 内部查询入口 Provider ABA 防护（P0，L2 待审）

- 固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：`dns/resolver.go` 中 `ProxyServer` 具有独立的节点 DNS resolver/cache；此处额外代际约束属于 Chimera 动态 Provider 安全边界，不等于已完成二进制互操作验证。
- 新增 task-local `INTERNAL_HANDOFF_TEST_PAUSE` 与 `internal_handoff_provider_aba_rejects_obsolete_public_answer`：在外层 `exchange` 已验证代际、内层 `exchange_no_cache_with_policy` 再采样之前，执行注册→注销 ABA。修复前 **0/1 失败**（过期公共响应被接受），修复后 **1/1 通过**，且公共 DNS 未被调用、共享缓存未被污染。
- 最小生产修复：外层 `exchange` 将初始 `provider_generation` 显式传递给 `exchange_no_cache_with_policy_and_generation`；内层在分派上游前复核，且将同一代际用于公共响应写缓存前的检查。原有直接调用入口继续使用兼容 wrapper，自行采样代际。原有 `public_handoff_provider_aba_rejects_obsolete_public_answer` 仍通过。
- 同时补齐既有 epoch-cache 容量测试缺失的常量导入（此前导致 `--lib` 测试编译失败）；没有修改容量或缓存运行时语义。
- Rust 1.99.1/macOS ARM64：`cargo fmt --check`、严格 `clippy -p clash-lib --all-targets --features tun,ring -- -D warnings`、`git diff --check` 通过；核心库 **1159 通过、0 失败、11 忽略**，DNS 配置集成 **46/46** 通过。尚未完成 L2 独立审查、物理 NIC/utun 抓包或跨平台 CI。内层最终检查与实际缓存写入仍非同一原子临界区，不能声称已完全排除所有交错时序；下轮重点检查最终检查→写入间隙以及失败/取消路径。

## 2026-11-09 17:49–18:17 PST — 历史 Provider QNAME 代际缓存恢复（性能 + P0 可靠性，L2 待审）

- **基线/工作区**：沿用 `codex/macos-tun-fakeip-dns-privacy` 与当前 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，没有 checkout/rebase/提交；未清理或覆盖开工前的 8 个已修改文件。固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `dns/resolver.go` 将普通/代理节点 DNS resolver/cache 分开，`newCache()` 默认有限大小；本实现是 Chimera **动态 Provider ABA 特有的隔离增强**，不能仅凭字段解析断言完整 Mihomo 二进制语义一致。
- **原因**：上一轮为避免“首次注册之前的公共 DNS 正/负缓存，在 Provider 注销后复活”，对任何拥有非零历史代际的 QNAME 全面禁止普通缓存。这很安全但对后来合法的普通查询也导致每次访问上游。为兼顾恢复性能与隔离，新加独立 `ProviderEpochCacheEntry{generation,response,inserted,expires}`、`provider_epoch_cache`（`lru_time_cache`，**1024 条上限**），按规范化 QNAME/QCLASS/QTYPE 精确索引，读写时核对同一代际；活动节点绝不进入该缓存，仍使用 `proxy-server-nameserver`。
- **真实运行时行为**：当 `lru_cache` 启用且请求符合 `cache_safe_request` 时，非活动 Provider 的历史域名可以缓存当次公共 DNS 成功答案或 RFC 2308 NXDOMAIN/NODATA。下次请求命中本代际时恢复事务 ID/查询问题字段并扣减 TTL，交付前仍调用现有 `revalidate_public_cache_hit_with_generation`。当 Provider 重新注册、注销或发生 ABA，新的 generation 必定与缓存不同，无法返回此前答案；通用 Hickory 缓存仍不读取/写入历史域名。全正常域名不受影响，无缓存配置仍旧实时解析。
- **缓存安全/生存期**：复用既有 SOA.MINIMUM/authority TTL 校验和积极响应合法性门槛；0 TTL、truncated、AD/签名/EDNS、非 DNS Response、无效全 0 地址不缓存。正向记录按 Hickory 默认最大 TTL **86400 秒**保守限制；非地址记录分类型缓存，ACME TXT 继续禁用。陈旧代际的查询**不能删除更高代际的有效缓存项**（先写否定测试 0/1 失败再修复）；网络 `reset_transports()` 清空新缓存。所有 LRU `Mutex` 均不跨 `.await`，不会更改系统 DNS/TUN/路由。
- **测试证据**：`former_provider_public_{positive,negative}_answer_hits_current_generation_cache` 两项验证历史域名允许当前代际命中；`old_public_{positive,negative}_cache_is_not_reused_after_provider_ownership_aba` 继续阻止前代旧 IP/NXDOMAIN；`provider_epoch_cache_is_invalidated_on_next_ownership_cycle`、`provider_epoch_{positive,negative}_cache_handoff_rejects_aba`、`public_query_started_in_former_provider_epoch_rejects_later_aba` 验证交叉代际失效和并发隔离；另有 TTL 到期、容量上限、network reset、QNAME 大小写/QTYPE 隔离、未开启缓存、无关 Provider 更新和 CD 查询保护测试。`stale_reader_must_not_evict_newer_provider_epoch_cache_entry`、`provider_epoch_positive_ttl_is_clamped_to_hickory_default_max`、`provider_epoch_cache_rejects_authenticated_negative_and_non_response_messages` 修复前定向均 0/1，修复后均 1/1 通过。
- **空间故障和受控处理**：本机 APFS 系统卷短暂达到 100%，Cargo 无法创建临时文件。确认主要增量产物位于本**隔离工作树**内 `target/debug/incremental/clash_lib-*`（约 22 GiB），只清理这些可再生成的 `clash-lib` 增量编译产物，释放约 **15 GiB**；不删除源码、测试数据、Git 变更或其他包构建产物，后续用 `CARGO_INCREMENTAL=0` 降低磁盘再增长。未运行需要特权的网络/抓包。
- **剩余限制**：Provider 域名历史代际表 `provider_domain_generations` 目前仍记录全生命周期出现过的名字，**不是**有上限的长期内存结构；新缓存条目本身有限容量。真实 NIC+utun 防泄漏、macOS System Extension/DNS ownership、独立 L2 Reviewer 以及 Mihomo 二进制互操作均未验收，不能宣称系统级零泄漏。独立 Reviewer 应特别核对同名多所有者、网络 reset 并发与最终交付边界、TTL 与资源增长；回滚单独拆除新 epoch cache 并恢复上一轮 `generation != 0` 禁止公用缓存的方案，保留 ABA 安全防护。

## 2026-11-09 17:07 PST — Provider 历史所有权导致的公共缓存 ABA 复活（P0，L2 待审）

- 继续复用隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，起始/最终 HEAD 未改写；固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。本轮开始时工作树已有 8 个修改文件，全部保留；此次仅在既有 `enhanced.rs` 增加最小运行时防护和测试，不混合提交、不推送、不改 DNS/TUN/路由或权限。
- **新发现并成功复现**：普通 DNS 先缓存 `proxy.example.com` 的正向旧 IP 或 NXDOMAIN；Provider 注册该域名，随后注销；新的 `exchange` 只看到“当前无所有者”，按最新代际校验直接交付**注册之前**的老公共缓存值。新增 `old_public_{positive,negative}_cache_is_not_reused_after_provider_ownership_aba`；修复前实测两项均失败（老 IP `192.0.2.10` 或空 NXDOMAIN，预期是新普通 DNS `192.0.2.12`）；修复后 2/2 通过。
- **最小失效关闭**：当 `provider_domain_generation(qname) != 0`（此 resolver 生命周期内曾发生该域名的 Provider 所有权变化）时，禁止从无来源代际标签的公用正/负缓存读取或写入。这一条件按域名粒度，不会清空其他 DNS 缓存；以前的静态域名、动态 Provider 活跃状态和仍未出现 Provider 的域名遵循现有逻辑。通过 `unrelated_public_cache_still_hits_after_provider_ownership_aba` 验证无关域名缓存仍可命中；`former_provider_domain_does_not_populate_new_public_negative_cache` 验证退出节点后普通负响应仍可实时获取，但不进入无版本缓存。
- **范围和性能取舍**：Hickory `ResponseCache` 仅以 DNS Question 为键，暂无对外暴露的单键 purge/来源代际标签；因此对曾是节点的域名暂时牺牲公用缓存命中率，不能声称与 Mihomo 的内部缓存实现等价。今后可实现按 generation 分区的有限容量缓存恢复性能，但必须先验证 ABA 和跨 Provider 更新。对当前注册的节点仍必须使用 `proxy-server-nameserver`；本补丁绝不允许回退公共上游。
- 固定只读 Mihomo `dns/resolver.go::NewResolver` 为普通与代理节点构造独立 `ResponseCache`；本轮是 Chimera 的额外动态 Provider 所有权边界补强，尚无二进制互操作/物理 NIC 与 utun 抓包，不宣称 macOS 系统零泄漏。

- 额外回归：`last_provider_owner_removal_invalidates_preexisting_public_cache` 证明两个 Provider 共同持有域名时，移除一个不会切回普通 DNS，移除最后一个才允许新的普通解析，并且先前公用缓存被阻断。`former_provider_domain_does_not_populate_new_public_negative_cache` 验证撤销后新的 NXDOMAIN 不进入无代际标识的共享负缓存；无关域名仍命中缓存。
- macOS ARM64 / Rust 1.99.1 目标矩阵：`cargo +1.99.1 fmt --all -- --check`、`cargo +1.99.1 clippy -p clash-lib --features tun,ring --all-targets -- -D warnings`、`git diff --check` 通过；`cargo +1.99.1 test -p clash-lib --features tun,ring --lib --quiet` **1153 通过、0 失败、11 忽略**；`--no-default-features --features tun,ring --lib` **961 通过、0 失败、11 忽略**；DNS 配置、S01、S02、S00 分别 **46/46、17/17、14/14、14/14** 通过。关闭 TUN 的独立定向修复测试 2/2 与核心库 Clippy 通过，但无 TUN 的全库 **919 通过、9 失败、9 忽略**、DNS 配置集成 **42 通过、2 失败**；失败来自旧测试仍强制要求 TUN 或独立 Mock DNS expectation，不属于目标 feature 质量门禁，未修改这些测试来掩盖失败。
- 远端只读确认 `master=0b81617d828d73b66553104a11970622eda9268a`，CI run `42674574124` 完成 success；该 CI 不覆盖本地脏分支。开放 PR #111、#110、#85、#58，本轮未修改。当前本机系统盘约 **96% 已使用、仅 12 GiB 可用**，本工作树 `target/` 约 68 GiB；为了避免耗尽空间，不运行 release / all-features 新构建，也没有擅自清理缓存。L2 独立审查及授权的物理 NIC/utun 抓包尚未完成。

## 2026-11-09 P0 补充：缓存所有权及配置诊断隐私（隔离分支，L2 待审）

- 在真实 `EnhancedResolver::exchange` 的正/负缓存选取后增加**仅在测试中启用**的 Tokio task-local `Barrier`，配套 5 秒超时；非生产构建无该屏障和状态。覆盖同名 Provider 注册→移除 ABA、注册后仍有效并经专用 DNS 恢复，以及无关域名更新不应误拒；另外覆盖 TXT 负缓存的 ABA 拒绝。该测试补强原有运行时代际检查，**不表示检查到响应最终消费期间的原子性已解决**。`registered_provider_bypasses_existing_negative_cache_in_exchange` 修复缓存未实际启用的测试假阳性（补充 RD、`ResponseCache` 和真实命中探针）。
- 在 `app/dns/config.rs::validate_fake_ip_filter_patterns` 修复**日志诊断泄漏私有域名**：RuleSet/GeoSite/规则表达式仍安全拒绝，但错误文本不再原样拼接被拒绝的 `fake-ip-filter` 字符串。新增 `dns_config_tests.rs::unsupported_fake_ip_filter_rejects_without_echoing_private_selector`，修改前 0/1 失败（暴露测试私有域名），修复后 1/1 通过。更新内部重载及 S00 黄金测试对错误路径的断言，要求拒绝且无敏感值。
- 在 `config/def.rs::Config::from_str` 修复配置语法/锚点错误**回显完整 YAML（可能含认证密钥/订阅）**的问题；对 serde 类型、未知字段错误仅输出安全的固定根区段（如 `dns`/`tun`）和错误类别，丢弃原始字段值和无边界诊断细节。新建三项不回显敏感值测试：`malformed_dns_yaml_diagnostic_never_echoes_config_values`、`invalid_yaml_merge_diagnostic_never_echoes_config_values`、`invalid_dns_value_diagnostic_never_echoes_private_scalar`。其中前者、后者在修复前确实失败；serde 诊断修正为保留安全的 `unknown field` 类别以维持 S01 可操作性。
- `app/dns/config.rs` 的 DNS 上游 URI、普通 `nameserver-policy` 和专用 `proxy-server-nameserver-policy` 失败诊断，以及 `config/internal/config.rs` 内部重载拒绝路径，过去会直接回显无效 selector/URI（包括私有 DNS 主机名、可能的凭据）。`dns_config_tests.rs::policy_selector_diagnostics_reject_without_exposing_private_qname` 与 `invalid_upstream_diagnostics_do_not_echo_private_uri_parts` 修复前分别 0/1 失败；目前拒绝时仍给出配置字段、错误类别及索引，但**不回显 selector、URI、接口名或可含密钥的查询参数**。调整依赖旧回显行为的测试断言，保持受支持 DNS 上游/策略的运行语义不变。
- 本轮校验使用 macOS ARM64 和仓库锁定 Rust **1.99.1**：`cargo +1.99.1 clippy -p clash-lib --all-targets --features tun,ring -- -D warnings`、`cargo +1.99.1 fmt --all -- --check` 通过；`cargo +1.99.1 test -p clash-lib --features tun,ring --lib --quiet` **1143 通过、11 忽略、0 失败**；DNS 配置集成 `--test dns_config_tests` **46 通过、0 失败**；S01 `17/17`、S02 `14/14` 通过。`--all-features` Clippy 因本工作树缺少 `clash-dashboard/dist` 构建资产被 build.rs 阻断，**不得称全特性通过**。只读 `git show HEAD:` 证实旧版 S00 冲突及原始敏感日志回显均存在于本轮未修改前的 HEAD。
- **最终回归（2026-11-09 11:19 PST）**：Rust 1.99.1、macOS ARM64，默认 features + `tun,ring` 的库单测 **1145 通过、11 忽略、0 失败**；`--no-default-features --features tun,ring` 库单测 **953 通过、11 忽略、0 失败**；两组 feature 的 DNS 配置/S01/S02 集成分别 **46/46、17/17、14/14 通过**；`api_tests` 12/12 通过（普通测试监听器，DNS/TUN 均禁用）。两组 feature 的严格 `Clippy -D warnings`、`cargo fmt --check`、`git diff --check` 通过，最小 feature `cargo check` 通过。10 轮并行重复运行 `enhanced::tests::exchange_` 缓存并发回归全部通过；本轮另覆盖 TXT/SRV 负缓存 ABA 拒绝。`--all-features` Clippy 曾尝试，但因缺失 `clash-dashboard/dist` 构建资产被 build.rs 阻断；未改变用户前端依赖/资产。
- 对照固定 Mihomo `config/config.go:1420-1421`，它确实在 `respect-rules` 开启且 `proxy-server-nameserver` 为空时直接报错；`dns/resolver.go:608-615` 采用独立代理节点 resolver 与缓存。旧 Chimera S00 金标准与该上游要求的冲突不仅是推测：`git show HEAD:clash-lib/src/config/internal/config.rs` 和 `git show HEAD:clash-lib/tests/dns_legacy_golden_tests.rs` 同时证实两者在本轮开始前就存在。仅为兼容而绕过引导隔离会引入错误回退风险；仍需明确 L2 决策。
- `config/def.rs::unknown_dns_object_field_never_echoes_private_key` 验证严格 DNS resolver-profile 对象的未知字段仍报 `unknown field`，但不会在错误消息泄漏字段名；Rust 1.99.1 的定向测试及两套 Feature 全库回归均通过。
- **已存在的 L2 契约冲突待维护者裁决，禁止为了绿测试放松隔离**：`dns_legacy_golden_tests.rs::s00_respect_rules_and_legacy_proxy_modifier_are_preserved` 允许 `respect-rules: true` + `#proxy=PROXY` 且不配置 `proxy-server-nameserver`；当前 `config/internal/config.rs` 按固定 Mihomo `config/config.go::parseDNS` 的独立节点解析引导要求拒绝该组合。实际 S00 黄金测试在本轮检查 12/13 通过、1 失败；不能把这一项记作通过，也不能在无 L2 决策时自动消除旧兼容契约。若保留更严格规则，旧 YAML 必须显式迁移增加专用 `proxy-server-nameserver` 并经维护者审批。
- 固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `/dns/resolver.go`、`config/config.go` 已核对；无法由单元测试宣称 macOS 物理 NIC/utun 零 DNS 泄漏。所有网络设置、授权和持久系统状态均未修改。

## 2026-11-09 10:38–10:47 PST 正/负缓存交付并发屏障（P0 测试加强）

- 工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；本轮未提交、不修改系统网络。此前三个未提交文件均保留。
- 发现上轮 `registered_provider_bypasses_existing_negative_cache_in_exchange` **误覆盖**：`from_clients()` 默认 `lru_cache: None`，且请求须开启 RD 才符合 `cache_safe_request`。先增加缓存真实命中证明，旧测试先出现 0/1（公共 DNS 计数 1 而非预期 0）；随后启用 `ResponseCache` 和 RD，1/1 通过。这是测试可靠性修正，不能记为生产防泄漏修复。
- `enhanced.rs` 新增仅在 `#[cfg(test)]` 中编译的 `tokio::task_local!` 候选屏障：在实际正缓存和 RFC 2308 负缓存命中分支完成候选选取后，暂停至测试完成 Provider 注册/注销。任务局部而非全局开关，避免污染并行单测和生产 resolver 结构。新增四项 `exchange_{positive,negative}_cache_candidate_{rejects_provider_registration_aba,rejects_new_provider_and_recovers}`，验证注册后注销（ABA）失效关闭、注册后仍有效时拒绝旧缓存并由专用节点 DNS 恢复；均 4/4 通过。此项对 **既有** 代际保护建立运行时回归证据，未改变生产路径。
- 只读核对固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：在主工作区 `/Users/adam/src/Chimera_Client/ref-mihomo` 可读；`dns/resolver.go` 中 `ProxyServer` 构造独立 resolver/cache，`ExchangeContext` 可读取缓存。这不足以证明 Chimera 对 Provider 动态注册期间的错误语义与 Mihomo 完全相同；并发失效关闭是本地额外隐私约束。
- macOS、Rust 1.99.0、`--features tun,ring`：`cargo +1.99.0 fmt --all -- --check` 通过；`cargo +1.99.0 clippy -p clash-lib --all-targets --features tun,ring -- -D warnings` 通过；`cargo +1.99.0 test -p clash-lib --features tun,ring --lib` **1136 通过、0 失败、11 忽略**；`cargo +1.99.0 test -p clash-lib --features tun,ring --test dns_config_tests` **43 通过、0 失败**。无系统 DNS/TUN/NIC 变更。
- 远端只读检查：`master` 为 `0b81617d828d73b66553104a11970622eda9268a`（本地 `origin/master=f304da1` 已过期，未 fetch）；远端 master CI run `42674574124` 于本轮后续复查已完成且 **success**，不是本地脏工作树的 CI。当前开放 PR #111/#110/#85/#58；未创建/更新 PR。
- 剩余风险：校验与调用方实际消费答案之间不能声明原子；还需要缓存命中与 Provider **其他拥有者**并发更新的无误拒测试、macOS 物理 NIC/utun 抓包和独立 L2 审查。未声称系统级零泄漏。
- **下一最小 P0 切片（尚未证明有缺陷）**：`EnhancedResolver::exchange` 已在入口记录 `provider_generation`，但普通缓存未命中的路径调用 `exchange_no_cache_with_policy` 时，后者又独立采集 `public_generation`。应在两次采样之间设置仅测试中启用的阻塞点，制造同名 Provider 注册→移除 ABA，并检查是否出现公共 DNS 旧答案或错误缓存；若否定测试失败，再最小化传递原始代际/最终重分类，同时保护“注册后仍存在”的 dedicated DNS 重试语义。不要仅凭源码中的两次采样认定已发生泄漏。

## 2026-11-09 10:35 PST Provider 负缓存实际入口回归

- 工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；参考 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 未检出，不能宣称本轮独立确认 Go 运行时语义。
- 新增 `registered_provider_bypasses_existing_negative_cache_in_exchange`：真实 `EnhancedResolver::exchange` 路径预置 NXDOMAIN 负缓存，随后注册同名 Provider，断言专用节点 DNS 返回地址，普通 DNS 未调用。首次运行通过（1/1），属于回归覆盖而非已复现的新生产缺陷。
- `cargo +1.99.0 test -p clash-lib --features tun,ring registered_provider_bypasses_existing_negative_cache_in_exchange --lib`：1 通过；`cargo +1.99.0 clippy -p clash-lib --all-targets --features tun,ring -- -D warnings`：通过；`cargo +1.99.0 test -p clash-lib --test dns_config_tests --features tun,ring`：43 通过；`cargo +1.99.0 fmt --all`：完成。
- 尚缺真实负缓存选取与最终交付之间的确定性并发屏障测试、macOS 物理 NIC/utun 抓包、Rust 1.99.1 复测及独立 L2 审查；不得据此宣称零泄漏。

## 2026-11-07 运行时隔离补充（P0）

- 固定 Mihomo 只读参考：`ref-mihomo` gitlink / 工作树 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；`config/config.go::parseDNS` 中解析独立 `proxy-server-nameserver`，并在配置 `proxy-server-nameserver-policy` 时要求其非空。这里的运行时零客户端失效关闭是 Chimera 的隐私安全强化，**不是已证明 Mihomo 具有相同错误路径**。
- Chimera 基线 `e42dabe74282c77245da1023de0b828830928216`：`resolver/enhanced.rs::new_with_network_path_source` 对已配置但运行时零客户端的 `proxy-server-nameserver` 发出警告并回退默认 DNS；即使解析层通常会拒绝全跳过配置，内部配置和运行时构造仍可能出现此状态。
- 先写否定测试 `configured_proxy_nameserver_with_no_runtime_clients_fails_closed`，修复前实测 0 passed / 1 failed；修复后该状态直接返回 `InvalidConfig`，不会构造回退到默认 DNS 的代理节点解析器。测试不触碰系统 DNS、路由或 TUN；仍需故障注入验证实际已构造客户端超时、provider 更新和物理 NIC/utun 抓包。

## 1. 已有配置及行为

| 字段或机制 | 当前输入/真实行为（含边界） | 现状 | 建议 A/B/C | 会破坏现有使用吗？ / 迁移示例 | 实证/金标准 |
|---|---|---|---|---|---|
| `dns.enable` | `bool`；禁用则使用系统 DNS，启用需要至少一个可用 `nameserver` | implemented | A | 删除会破坏；保留 `enable: true` | `config/def.rs:398`、`dns/config.rs:367`；S00 `dns_disabled`、`invalid_values` |
| `dns.listen` | 既有 UDP/TCP/DoT/DoH/DoH3 对应配置入口；TLS listener 必须配置证书与密钥，不等于端到端互操作已测 | implemented/partial validation | A | 保留 `listen: {udp: '127.0.0.1:0'}` | `dns/config.rs`，`dns_config_tests.rs::encrypted_dns_listeners_require_certificate_pairs`；S00 `legacy_normal` |
| `dns.ipv6` | 需要顶层 `ipv6` 和 DNS 层 `ipv6` 同时启用；关闭时 DNS listener 对 AAAA 空答 | implemented | A | 保留现有两个开关 | `dns/config.rs:474`；S00 `ipv6_requires_global_and_dns_flags` |
| `dns.nameserver` | `Vec<String>`；支持 UDP/TCP/DoT/DoH/DHCP 入口（按编译特性），省略 scheme 时默认 UDP；`system` 被跳过，全部跳过时报错 | implemented | A | 不得默认改成新 profile；旧配置 `nameserver: [1.1.1.1]` 继续可用 | `dns/config.rs:81`；S00 `legacy_normal`、`invalid_values` |
| `dns.nameserver-policy` | `IndexMap<String,DnsPolicyUpstreams>`；保留 YAML 声明顺序，支持普通域名、逗号选择器、单字符串/多上游数组、静态加载的 `geosite:` 和 DNS 引用的 **inline + domain** `rule-set:`；文件/HTTP RuleSet 仍明确拒绝 | implemented subset | A（子集） | 保持原语法/顺序；GeoSite 需有效数据文件；DNS RuleSet 必须是有效非空内联域名规则；动态文件/远端 provider 未提供 DNS 引导与刷新语义 | `config/def.rs`、`dns/config.rs::parse_nameserver_policy`、`resolver/enhanced.rs::match_policy`、`rule_provider/provider.rs::match_dns_domain`；批次 5–9 回归 |
| `dns.default-nameserver` | `Vec<String>`；必须非空且解析为 IP literal，可用来 bootstrap 上游域名 | implemented | A | 旧 `default-nameserver: [223.5.5.5]` 保留 | `dns/config.rs:385–411`；`dns_config_tests.rs::default_nameserver_must_be_ip_address` |
| `dns.proxy-server-nameserver` | `Vec<String>`；非空时用于代理节点域名的特定解析；同名普通 DNS 不应越权替代 | implemented | A | 保留独立字段；`proxy-server-nameserver: [9.9.9.9]` | `dns/config.rs:414`、`resolver/enhanced.rs::ip_exchange`；S00 `proxy_and_direct_nameservers`；`proxy_server_nameserver_precedes_nameserver_policy_without_leaking` |
| `dns.direct-nameserver` | `Vec<String>`；非空时单独构造 direct resolver（有现存 fallback 语义） | implemented | A | 保留 `direct-nameserver: [192.0.2.53]` | `dns/config.rs:426`、`resolver/enhanced.rs::direct_resolver`；S00 `proxy_and_direct_nameservers`；`direct_resolver_prefers_direct_nameserver_without_fallback_query` |
| `dns.fallback` | `Vec<String>`；现有主/后备竞争、筛选及失败行为不是“所有错误必定回退”；已具备特定场景双失败诊断 | implemented | B（保留待评审） | 删除会破坏；保持 `fallback: [9.9.9.9]` | `dns/config.rs:374`、`resolver/enhanced.rs::ip_exchange`；S00 `fallback_filter_keeps_*`、`main_and_fallback_errors_are_both_reported` |
| `dns.fallback-filter` | 保留 `geoip`、`geoip-code`（规范化大写）、`ipcidr` 和 `domain`；依赖现有域名/IP 条件 | implemented | B（保留待评审） | 如迁移至 profile 需单独 Decision；旧 `fallback-filter: {geoip: true}` 继续 | `dns/config.rs:444–460`；S00 `fallback_filter_keeps_*`、`dns_config_tests.rs::invalid_fallback_cidr_is_rejected` |
| `dns.enhanced-mode: fake-ip` | IPv4 Fake-IP A 合成、PTR 反向映射、非 A 保守空答，已建立离线劫持测试 | implemented (IPv4) | A | 不改变默认合成规则；新增复杂记录能力必须 opt-in | `dns/server/handler.rs`、`dns/fakeip/`、`proxy/tun/`；S00 `fake_ip_filter_and_range_*`，已有 Fake-IP/TUN 回归 |
| `dns.fake-ip-range` | IPv4 CIDR，地址池错误（过小/耗尽）明确报错；映射当前没有安全 LRU 回收策略 | implemented (IPv4) | A | 保留 `fake-ip-range: 198.18.0.0/16`；不可随意复用活跃 IP | `dns/fakeip/mod.rs`；S00 `fake_ip_filter_and_range_*`、`invalid_fake_ip_ranges_fail_runtime_startup` |
| `dns.fake-ip-filter` | `Vec<String>`；匹配的域名不使用 Fake-IP，非 A 类型按现有策略转上游；其他非 A 仍保守空答 | implemented subset | A | `fake-ip-filter: ['*.lan']` 保留语义 | `dns/resolver/enhanced.rs::should_fake_ip`、`dns/server/handler.rs`；S00 `fake_ip_filter_and_range_*`、`fake_ip_filter_lets_excluded_domains_use_real_ipv4_dns` |
| `dns.fake-ip-range6` | 可解析 IPv6 子网；**没有证明实际 Fake-IPv6 分配/应答全链路可用** | partial | B（待评审） | 不得因 YAML 能读就宣称可用；暂保留旧输入形式 | `dns/config.rs:522`、`dns/resolver/enhanced.rs::resolve_v6`；`full_dns_fixture`、`fake_ip_range6_rejects_ipv4_prefix` |
| `dns.enhanced-mode: redir-host` | enum 可反序列化；**DNS 启用时明确以未实现拒绝** | unsupported at runtime | B（待评审） | 如弃用需决定 KEEP/REJECT，并给迁移：改用 `normal`（非语义等价）或 `fake-ip`（行为不同） | `config/def.rs:348`、`dns/config.rs:401`；S00 `legacy_invalid_values`、`enabled_redir_host_mode_is_rejected_as_unimplemented` |
| `dns.respect-rules` | `bool`；仅按现有 DNS dialer 与 Business Router 交互；未验证所有上游协议/代理池路径一致 | implemented, incomplete egress E2E | B | 保留 `respect-rules: true`，不替换为新 `egress` 默认 | `dns/runtime.rs::pick_outbound`、`dns/config.rs:551`；S00 `respect_rules_and_legacy_proxy_modifier_*` |
| DNS 地址修饰符 `#proxy`、`#interface` | 解析器接受修饰字段，`#RULES` 等值的运行时语义按现有 dialer 决定；未知 interface 可报错 | implemented subset | B | 新 `egress` 冲突须显式诊断；旧 `udp://1.1.1.1#proxy=PROXY` 必须保留 | `dns/config.rs::parse_outbound_proxy`、`parse_outbound_interface`；S00 `respect_rules_and_legacy_proxy_modifier_*` |
| `dns.edns-client-subnet` | IPv4/IPv6 CIDR 可解析，至少提供一个地址族；不默认添加 ECS | implemented parsing; wire not independently asserted here | B（需审计使用方） | 保留现有显式设置格式 | `dns/config.rs::parse_edns_client_subnet`、`dns_config_tests.rs::edns_client_subnet_requires_at_least_one_family` |
| `dns.use-hosts` | 显式开关（默认 true），DNS hosts 与 localhost 保留，非法地址直接报错 | implemented | A（S00 补充建议，待维护者确认） | 保留默认值；不擅自关掉 hosts | `config/def.rs`、`dns/config.rs:465`；`invalid_hosts_entry_is_rejected` |

## 2. 拟议新增字段/与 Mihomo 的取舍

| 字段/机制 | 当前实现事实 | 建议 A/B/C | 不兼容/迁移说明 | 证据/判定 |
|---|---|---|---|---|
| `dns.resolver-profiles` | **S01 已新增编译期输入与严格服务器列表校验**，但尚无实际查询执行；可选，不配置时旧行为不变 | implemented (parse/compile only)，执行尚未接线 | 后续 S02/S03 实现实际 resolver/egress；目前只声明 profile 不会改变 DNS 查询 | 指南 §6、§17；`config/def.rs`、`app/dns/policy.rs`、`dns_policy_s01_tests.rs` |
| `dns.policy-rules` | **S01 已实现 QNAME+QTYPE 有序编译/纯匹配及加载校验**；运行时对非空规则显式拒绝启动（执行器尚未实现），不能宣称 DNS 出口已生效 | implemented (parse/compile only)，runtime gated | S02/S03 完成 DNS query planning/egress 后再开放运行，不静默忽略 `on-failure: fail` | 指南 §6、§17；`app/dns/policy.rs`、`resolver/mod.rs`、`dns_policy_s01_tests.rs` |
| `fake-ip-filter-mode: whitelist` | **本地迭代分支已实现** Mihomo IPv4 Fake-IP 白名单语义：仅匹配的域名使用 Fake-IP，其他域名会使用真实 DNS；模式名称大小写不敏感。完整高级域名匹配及 Fake-IPv6 未实机验证 | A（有意 opt-in） | 严格隐私配置仍推荐 `blacklist` + 空过滤列表；`whitelist` 会让未列出的代理域名使用真实解析 | 本地 `ref-mihomo` 63bd52e `component/fakeip/skipper.go`、`constant/dns.go`；新增 FakeDns/resolver/配置测试 |
| `fake-ip-filter-mode: rule` | 尚未实现，解析时明确拒绝。`fake-ip-filter` 中的 `rule-set:`、`geosite:`、Mihomo 规则表达式也显式拒绝，防止字面匹配导致隐私意外降级 | C（条件成立） | 不允许静默映射到 blacklist / whitelist；需要先完成有序规则及 RuleSet/GeoSite 运行语义 | `config/def.rs`、`app/dns/config.rs`、`dns_legacy_golden_tests.rs` |
| `proxy-server-nameserver-policy` | **本地迭代分支已实现普通域名子集的运行时选择**：有序匹配、大小写不敏感、标量/多个上游、逗号分隔规则；未命中节点使用独立 `proxy-server-nameserver`，策略失败不降级至主 DNS。`geosite:`、`rule-set:`、`system`、`#proxy` 暂拒绝；未进行真实 macOS DNS 出口抓包或完整 Mihomo 互操作 | A（部分支持，L2 待审） | 仅此字段从 P0 拒绝列表移除；仍要求独立节点 nameserver | 固定 Mihomo `config/config.go::parseNameServerPolicy`、`dns/resolver.go`；`app/dns/config.rs`、`resolver/enhanced.rs`、`dns_config_tests.rs` |
| `direct-nameserver-follow-policy` | **本地分支实现运行时语义**：默认 false 保持旧 DIRECT 解析行为；设为 true 且配置 `direct-nameserver` 时，在独立 DIRECT 解析器上共享 `nameserver-policy` 的同一批上游/域名匹配器。匹配规则时优先策略且失败不回退；未命中时走 `direct-nameserver`，该上游失败也不降级为普通 DNS（Mihomo 独立 DirectResolver 语义）；没有 `direct-nameserver` 则和 Mihomo 一样不会生成专用解析器。域名匹配显式转为小写，防止大小写绕过策略 | A（部分等价，L2 待审） | 只有显式 true 更严格；false 下 Chimera 原有 DIRECT→主 DNS fallback 保留以维护既有兼容。尚无真实 macOS NIC/TUN 出口抓包 | 固定 Mihomo `config/config.go::parseDNS`、`dns/resolver.go::ReCreateServer`；`app/dns/config.rs`、`resolver/enhanced.rs`、新增 config/runtime 负例测试 |
| `dns.fake-ip-ttl` | **本地迭代分支实现**：Mihomo 默认/最小 TTL 为 1 秒，0 和负值规范化到 1；设置正整数时只改变合成 Fake-IP A/AAAA DNS 记录的 TTL，不改变被 `fake-ip-filter` 排除域名的真实 DNS 响应及 TTL。超过 `u32` 的值拒绝。相比原 Chimera 合成 A/AAAA 默认 60 秒，默认值变为 1 秒是有意兼容行为变更，需维护者 L2 审查 | A（合成应答运行时支持；L2 待审） | 不改真实上游 TTL；旧配置如果依赖缓存 60 秒需显式指定 `fake-ip-ttl: 60`；PTR 当前仍使用独立固定 TTL | 固定 Mihomo `config/config.go`、`dns/enhancer.go`、`dns/middleware.go::withFakeIP`；`app/dns/server/handler.rs`、配置/运行时/模拟上游测试 |
| `cache-algorithm`、`prefer-h3`、`fallback-lazy-query` | 未见原生承诺；不能因此把现存缓存和 fallback 功能标为缺失 | C（条件成立） | 保留实际已有缓存；不要求照搬 Mihomo 的调参名称 | 指南 §2.2 |

**尚未审定的事实**：Mihomo 端具体字段和行为尚未在固定 `ref-mihomo` 对照运行；本矩阵的 Mihomo 语义仅引用上传的 v2.0 设计稿所列候选，**不是经 Mihomo 运行验证的兼容认证**。`#RULES`、跨 Host/Gateway、多网卡真实 DNS 出口、IPv6 Fake-IP 仍需要专门实验，不能以配置解析成功代替运行时验证。

## 2026-11-06 macOS DNS 配置拒绝与节点引导失效关闭（L2 待审）

- 基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy`，开发前 HEAD `78b1d0cda8d231ece2748db44bbdade7c8de0128`；本地 `master=e42dabe74282c77245da1023de0b828830928216`，`origin/master=902c5e7702960ab4f978a014d7079c79d17079fd`；固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。同一项目另一隔离分支已有 `2c7fd3469989` 的类似字段拒绝提交；本轮不重置、不 cherry-pick、不改该分支。
- 参考：固定 Mihomo `config/config.go::RawDNS`、`RawTun`、`parseDNS` 和 `docs/config.yaml`。Mihomo 的节点 DNS 和 fallback 选择语义不能以 Chimera YAML 反序列化成功替代；不支持的敏感选项应当报错。这里只建立 fail-closed 边界，**未实现对应运行时字段语义**。
- 本轮在 YAML merge 后、反序列化前拒绝 12 项未实现的隐私相关输入：`tun.dns-mode`、`tun.auto-detect-interface`、`tun.include-interface`、`tun.exclude-interface`、`tun.stack`、`tun.route-address`、`dns.proxy-server-nameserver-policy`、`dns.direct-nameserver-follow-policy`、`dns.fake-ip-ttl`、`dns.use-system-hosts`、`dns.fallback-lazy-query`、`dns.fallback-filter.geosite`。保留不相关 vendor 字段兼容；诊断只输出字段名，不输出 DNS policy 值。以上 12 项仍为 unsupported，绝非 implemented。
- 内部解析器 `EnhancedResolver::new` 的 `proxy_server_nameserver=Some(vec![])` 原先会降级为默认解析器；现在直接拒绝，防止在配置转换之外（内部配置或未来热重载路径）悄然回退。没有配置（`None`）仍保留旧行为。普通 YAML 的空列表在配置转换层已提前拒绝。定向负例先证明旧实现错误地接受 `Some(empty)`，修复后通过。
- 仍存在的风险：`default-nameserver` 可能为系统/物理出口 DNS，当前系统 service-scoped DNS ownership 与物理 NIC 隔离尚未验证；macOS 真实网络与 TUN 抓包、跨平台测试及 L2 独立 Reviewer/维护者批准均未完成。没有修改系统 DNS、TUN、路由、权限、子模块或远端 Git。
- 当时计划的下一步是 `proxy-server-nameserver-policy`；它已在随后独立提交中实现普通域名子集，见下文。上述 12 项拒绝列表记录的是 P0 历史提交 `27d943b`，不能将它理解为本地 P1 HEAD 仍拒绝全部字段。

### 2026-11-06 节点 DNS 策略部分 Mihomo 兼容（L2 待审）

- 基线 `e8e9fcce761d8e6cb233c45cd1cf91dd77fd212f`；Mihomo 固定 gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，参考 `config/config.go::parseNameServerPolicy`、`dns/resolver.go` 的专用 ProxyResolver。参考子模块保持只读。
- `dns.proxy-server-nameserver-policy` 已支持按 YAML 顺序的普通域名选择器、既有 trie 的星号/加号域名匹配、逗号拆分域名、字符串或上游列表、大小写不敏感；仅代理节点域名应用，未命中走独立默认节点 DNS，匹配的策略失败则直接失败而不回退普通 DNS 或 fallback。网络路径重置包含其专属 DNS 客户端，内部配置也强制要求独立节点 nameserver。
- 运行时还将这套有序策略挂到 DNS 传输层的独立 `outbound_resolver` 上（并非只影响普通 DNS listener），新增该入口下选中专用策略或回退**专用默认节点 DNS**的模拟测试。内部配置绕过 YAML 注入不支持的 GeoSite 等规则也会被拒绝。
- 不支持且会明确报错：`geosite:`、`rule-set:`、策略值的 `system` 上游及 `#proxy` 指定出站。其它 Mihomo DNS 高级策略、真实 DNS 出口接口选择、系统 service-scoped resolver、TUN/NIC 抓包和跨平台运行仍未验证；不能宣称全部兼容或全系统零泄漏。
- 对应测试涵盖 YAML→运行时、客户端构造、多个上游、匹配顺序、未知节点默认专用解析器、策略失败无公共 DNS 回退、大小写、网络切换重置及内部热更新校验；既有 `dns_legacy_golden_tests::s00_respect_rules_and_legacy_proxy_modifier_are_preserved` 的前序冲突仍单列，不改旧测试掩盖失败。

## 3. 变更管理与 S01 准入

当前决定是 **保留已实现旧配置行为**，不存在本轮批准的 REMOVE/DEPRECATE。对每个未来不兼容行为使用指南 §2.3 的 `DNS-COMPAT-XXXX` 决策模板；没有具体旧行为、影响、迁移、回滚、测试和维护者批准，不允许落地。

S01 准入必须满足：金标准用例在目标 HEAD 实际运行；未知新配置不会被误称为可用；即使新规则生效，也严格保持业务规则顺序，不能将 `dns.egress` 当作业务流量出口。有关真实 DNS 出口与网络泄漏的完整证明在后续 S03/S04 隔离验证执行，S00 仅建立基线。

## 2026-11-08 — 代理节点专用 DNS 失败隔离回归（本地候选，L2 审查待办）

- 最新隔离整合分支 `codex/dns-master-integration-20261108-v3` 基于 `origin/master` `840c5a2b8f6a6be3e783dea026cc1bf3b5143f2f`，单独移植空客户端失效关闭修复及 A/AAAA 故障注入测试；不包含远端已经撤回的合并历史。原工作树、用户未提交更改不变。固定 Mihomo 参考为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，仅只读核查配置/解析器；尚无二进制互操作对照。
- `proxy_bootstrap_failure_never_queries_policy_main_or_fallback` 对 A 和 AAAA 注入专用 DNS 错误，断言专用上游共调用两次，policy/main/fallback 均未收到查询，两种请求均返回错误。此为内存客户端隔离断言，不证明物理 NIC 或 utun 上没有 DNS 泄漏。
- 定向 `configured_proxy_nameserver_with_no_runtime_clients_fails_closed` 不仅要求失败，还断言返回明确的 `InvalidConfig` 和静态诊断消息，避免将其他初始化错误误认为成功执行了隐私失效关闭。A/AAAA 故障测试分别在专用上游模拟失败，拒绝 policy/main/fallback 降级。TUN+Ring（无默认 feature）核心回归、DNS 配置及 S01/S02 策略测试用于验证未破坏旧配置；macOS DNS ownership、DNS Proxy 激活、抓包及 L2 独立审查仍未完成。
- `origin/master` 在 2026-11-08 先从 `a96c21d` 回到 `54b95ff`，又因提交重签从 `54b95ff` 变为 `840c5a2`；后两个基线 Git tree 相同但 Git 祖先不同。当前本地 `master` 仍有未提交修改，整合内容先保留于隔离候选分支。不得把测试成功或本地签名当成独立 L2 审查、GitHub Verified、required CI 或系统级隐私验收。

## 2026-11-08 — nameserver-policy 复合选择器失效关闭（新增候选，L2 审查待办）

- 固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy` 将逗号分隔域名、`geosite:` 和 `rule-set:` 视为有运行含义的策略选择器。Chimera 的 `parse_nameserver_policy` 原来只调用宽松的域名分割器，导致这些键及带空白的复合选择器被当作无法匹配的单个 trie 字面键，配置成功但没有预期 DNS 策略。
- 先新增 `nameserver_policy_rejects_unimplemented_compound_selectors` 否定测试，修复前因 `example.com other.test` 被错误接受而失败；再在 `clash-lib/src/app/dns/config.rs` 的转换层显式拒绝空白、逗号复合、`geosite:` 和 `rule-set:` 键。诊断不包含域名/上游地址；普通域名及现有 `*.`/`+.` 通配符继续成功。该切片是失效关闭，并**未实现** Mihomo 的高级规则执行语义。
- `clash-lib/tests/dns_config_tests.rs::nameserver_policy_compound_selectors_fail_closed_at_yaml_conversion` 对启用和禁用 DNS 的 YAML 都验证上述四类输入被拒绝，避免仅通过底层解析单测冒充 YAML 转换兼容。尚未执行 Mihomo 二进制差异运行、macOS 系统 resolver 或物理 NIC/utun 抓包。

## 2026-11-08 06:00 PST — fake-ip-ttl 未实现字段拒绝（独立本地 P0 候选）

- 只读参考固定 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：`config/config.go:240` 明确接受 `dns.fake-ip-ttl`；默认值 `1` 见第 513 行，配置值被赋给运行时 DNS 配置的 `FakeIPTTL`（第 1539 行）。Chimera 当前没有相应的 TTL 运行时字段或行为，故不能以 Serde 成功解析代替语义兼容。
- 在 `clash-lib/tests/dns_config_tests.rs` 先新增负例：`fake-ip-ttl` 与下划线误拼 `fake_ip_ttl`，分别在 `dns.enable=true/false` 时必须拒绝；还验证错误不泄露配置值、旧版 `fake-ip-range` 仍被接受。修复前定向测试 **0/1**，配置被静默接受；修复后 **1/1**。
- `clash-lib/src/config/def.rs` 在 YAML merge 后、Serde 反序列化前明确拒绝这两个键。该改动是安全 fail-closed 保护，**不声称实现 Mihomo 的 TTL 语义**，也不影响未显式设置 TTL 的旧配置。
- macOS 上 `--no-default-features --features tun,ring`：Cargo fmt、严格 Clippy（all-targets）、lib 832/832（另 11 ignored）、DNS config 20/20、S01 17/17、S02 14/14 全通过；默认 features 严格 Clippy 也通过。DNS listener 端口冲突日志为预期负例。未做真实 DNS/TUN/NIC 抓包、Mihomo 二进制对照或系统设置修改。
- 独立 L2 Reviewer/维护者批准仍缺失；本地候选不得自动并入 PR #107 或 master。下一切片应核对固定 Mihomo `proxy-server-nameserver-policy` 解析和运行时隔离，并做失效关闭故障注入。

## 2026-11-08 — 未实现的 Mihomo DNS 隐私字段严格拒绝（本地 P0 候选，L2 待审）

- 固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go` 定义 `fake-ip-filter-mode`、`proxy-server-nameserver-policy`、`direct-nameserver-follow-policy`、`use-system-hosts` 和 `fallback-lazy-query`，分别控制 Fake-IP 过滤、代理节点 DNS 策略、direct 查询策略、系统 hosts 使用及 fallback 查询时机。Chimera 仍没有相同运行语义，因此不将 YAML 反序列化成功视为兼容。
- `clash-lib/src/config/def.rs` 在 YAML merge 完成后、Serde 忽略未知字段前，拒绝这五个完整字段及相应下划线误拼；错误仅包含字段名，不回显配置值。无关 vendor 扩展与既有 DNS 配置继续可解析。其他隐私相关未知字段、仅部分近似拼写和平台特有限制仍待逐项审计。
- 新增 `clash-lib/tests/dns_config_tests.rs::unimplemented_mihomo_dns_privacy_controls_must_fail_closed`：启用/禁用 DNS、YAML merge、下划线误拼、错误保密以及无关 vendor 扩展回归。首次 canonical 用例修复前 0/1、证明被静默接受；新增 typo 用例及系统 hosts/fallback 字段用例均先失败再修复。修复后定向测试 1/1 通过。
- 在 macOS、`--no-default-features --features tun,ring` 下，核心单测 832 通过/0 失败/11 忽略；DNS 配置 19/19、S01 17/17、S02 14/14。关闭 TUN、启用 ring 的核心配置相关定向测试 7/7。Cargo fmt 和严格 Clippy（TUN+Ring all-targets；无 TUN、Ring lib）通过。尚未宣称 Mihomo 二进制行为等价或 NIC/utun 无泄漏。
- 该切片保留于独立本地分支，基线为 `840c5a2b8f6a6be3e783dea026cc1bf3b5143f2f`，原主工作区未提交修改、固定参考及系统 DNS/路由/TUN 未改变。独立 L2 审查、维护者批准、GitHub Verified 和候选 SHA 的 required CI 仍缺失，不合入本地/远端 master。

## 2026-11-08 05:17 PST — v0.29.0 新基线隔离整合（L2 待审）

- `origin/master` 在本轮新增 `ffda1a7c894e2b6cf14609fa2639630d91052d91`，修改 Cargo 版本及锁文件；旧的 `840c5a2` 候选现为历史快照。已在隔离分支 `codex/macos-dns-privacy-v029-integration-20261108` 上从 `ffda1a7` 重新签名 cherry-pick 六项 DNS 修复/否定测试；未覆盖原有候选和主工作树。
- v0.29.0、macOS：TUN+Ring、无默认 feature 核心单测 832 通过、0 失败、11 忽略；DNS 配置 19/19；S01 17/17；S02 14/14；默认 feature 核心单测 1024 通过、0 失败、11 忽略；DNS 配置 19/19。Cargo fmt、严格 Clippy（TUN+Ring 与默认 feature、all-targets）通过。测试中的 DNS 端口占用错误日志属于预期的负例，断言最终通过。
- 保持固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 只读；无 Mihomo 二进制实时对照、macOS NIC/utun 抓包或系统 DNS ownership 验收。候选仅本地签名、GitHub Verified 与候选 required CI 不可确认；L2 独立 Reviewer 及维护者批准仍缺失，禁止据此更新 master 或推送。

## 2026-11-08 06:01 PST — Fake-IP TTL 显式字段失效关闭（仅本地后续切片）

- 固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go` 声明 `dns.fake-ip-ttl`，并将值传给运行时 `FakeIPTTL`；Chimera 当前不支持同等响应 TTL 语义。接受该字段但不改变运行时结果会误导配置者。
- 从公开 PR #107 的固定 HEAD `8b3faa49c55906402e99bcb05a467afca62eee92` 本地派生 `codex/dns-fake-ip-ttl-strict-guard-20261108`，先添加 `fake_ip_ttl_not_implemented_must_not_be_silently_ignored`：`fake-ip-ttl` 和 `fake_ip_ttl`、DNS 开关两态必须明确报错且不回显用户值；原有 `fake-ip-range` 继续接受。修复前目标测试 0/1，证明静默接受；修复后 1/1。
- `clash-lib/src/config/def.rs` 仅在既有 merge 后严格字段检查中添加这两个键，没有实现、也没有声称实现 Mihomo TTL 语义；修改有潜在旧配置行为改变，因此仍为 L2。
- macOS v0.29.0、TUN + Ring、无默认 feature：核心单测 832 通过/0 失败/11 忽略、DNS 配置 20/20、S01 17/17、S02 14/14；默认 feature：核心单测 1024 通过/0 失败/11 忽略、DNS 配置 20/20；两组严格 Clippy（all-targets）、Cargo fmt 与 Git diff check 均通过。未运行实时 Mihomo 二进制对照与真实 NIC/utun 抓包。
- 该后续切片**仅在本地分支**；没有修改或推送 PR #107，也没有更改其待审 HEAD，新的本地提交尚未取得 GitHub Verified / 独立 Reviewer / required CI。PR #107 正在运行的 CI 和此前审查要求不得继承为本切片的批准。

## 2026-11-08 06:25 PST — PR #107 合并后基线重锚定

- PR #107 在 2026-11-08 06:20:34 PST 已合并为 `master` `befdcdb9360c5b88aa1920c75ef83861fba2ffeb`。该提交与原 PR HEAD `8b3faa49c55906402e99bcb05a467afca62eee92` 的 Git tree 相同，虽提交历史 SHA 不同，但七项 DNS 变更的最终源码已进入远端 `master`。
- 此 TTL 切片原本地提交 `7b9b2bb4649fa14836e21e4528756dadf7ef5510` 保留；已在独立分支 `codex/dns-fake-ip-ttl-post-merge-20261108` 上以新 `master` 为直接父提交单独签名移植（最终 SHA 以该分支 HEAD 为准），不重放 PR #107 已合并的七项提交。
- 此后续提交与 PR #107 是不同审查对象，不能继承后者的 GitHub Verified、CI、Reviewer 或维护者决定；必须独立核验最终 SHA、运行相关测试并获得 L2 审查/批准。未授权修改本机 DNS、路由、TUN 或进行物理 NIC/utun 抓包。

## 2026-11-09：最新 v0.29.1 主线上的独立 DNS 安全候选批次 1（L2 待审）

- 基线：`origin/master` `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定只读 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。本地 `master` 有未提交修改且与远端分叉，因此仅在隔离集成分支 `codex/dns-master-batch1-20261109` 提交，不改写或移动 `master`。
- 第一项：独立移植 `staged_cache_keeps_legacy_symlink_replacement_semantics`，验证 Provider 原子缓存覆盖符号链接路径而不修改其目标文件（源分支 `8cdec18`）；只移植兼容性回归，不复制不相关历史文档。
- 第二项：内部配置将 `dns.proxy-server-nameserver` 设为显式空列表时，验证阶段直接 `InvalidConfig`，未配置 `None` 则维持旧行为。源分支 `54b80b2` 的独立 P0 修复已适配最新主线；否定测试 `explicit_empty_proxy_node_bootstrap_fails_internal_reload` 先失败（0/1），再实施修复。
- macOS 本地验证：Rust 1.99.0（由于项目锁定的 1.99.1 安装不完整，需补跑锁定工具链），TUN+Ring、无默认 feature 核心库 834 通过、0 失败、11 忽略；`dns_config_tests` 20/20；严格 all-target Clippy（`-D warnings`）、Cargo fmt 和 Git diff 检查通过。端口占用日志是 DNS listener 失败路径的预期注入。
- 局限：未进行 macOS 物理 NIC/utun 抓包、Mihomo 二进制互操作、独立 L2 Reviewer 或远端 required CI。不得把本地候选标成已合并至 `master` 或已通过发布审查；未修改系统 DNS、路由、TUN、Network Extension、权限或远端分支。

## 2026-11-09 — 批次 2：内部 default-nameserver 引导安全校验（L2 待审）

- 以最新 `origin/master` `f304da17` 及第一批隔离提交为基线，借鉴原始 `088f487`，只移植可独立应用的 `default-nameserver` 内部配置校验及对应测试；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读。
- 内部配置和热重载拒绝空、非 IP 字面量、`#proxy` 或 `dhcp://` 上游，保留 IP 字面量 DoH 的旧配置；这并非系统级 macOS DNS 零泄漏验收。
- 独立 L2 审查、Rust 1.99.1 锁定工具链核验、Mihomo 二进制互操作和 NIC/utun 抓包仍待完成；未更新本地 `master` 或远端分支。

## 2026-11-09 — 批次 3：DNS 监听与 TLS 身份字段拼写失效关闭（L2 待审）

- 基于最新 `origin/master` `f304da17` 与前两批本地候选，独立适配原始候选 `377085f` 的 DNS 监听/TLS 隐私字段诊断，不引入其依赖的较大范围配置校验重构。
- 先写 `dns_listener_typo_must_not_silently_disable_listener`：旧行为会接受 `dns.listen.tpc`（否定测试 0/1）；新增合并后 YAML 校验，拒绝 DNS 监听协议和 DoH/DoT/DoH3 的证书、主机名、地址相关拼写错误，同时保持普通 `vendor-extension` 字段兼容。
- `dns_tls_certificate_typo_must_not_silently_disable_identity` 断言诊断不会打印 `secret.example`。两个定向测试通过；TUN+Ring 无默认 feature 核心库 837 通过/0 失败/11 忽略，DNS 配置 21/21，严格 all-target Clippy、fmt 和 diff 检查通过（Rust 1.99.0，锁定 1.99.1 安装状态待修复）。
- 固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读；未实际运行 Mihomo 二进制、macOS NIC/utun 抓包、远端 CI 或独立 L2 Review。此批仅保存在隔离集成分支，不将测试结果当成主线发布批准。

## 2026-11-09 — 批次 4：DNS/TUN 隐私配置字段拼写失效关闭（L2 待审）

- 基线为已推送的第 3 批 HEAD `24435eacc6d79abc4e794698db270f07785edca4`，上游 `origin/master` 为 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 保持只读。
- 独立移植旧 DNS 隐私分支 `0f3ef23` 中可审查的顶层 DNS/TUN 及 `fallback-filter` 字段诊断，并复用已验证的一编辑/相邻交换拼写比较函数。先写负向测试，旧配置会默默接受 `dns.nameserver-polcy`（0/1）；修复后明确拒绝安全敏感的近似拼写、YAML merge 后的错拼、TUN `strict-route`/`strcit-route`（尚无有效运行语义）、未实现的 `dns.fallback-filter.geosite`，同时保留普通 `vendor-extension` 兼容。
- 验证：Rust 1.99.0、macOS；无默认 feature + TUN/Ring 核心库 **842 通过 / 0 失败 / 11 忽略**，默认 feature + TUN/Ring 核心库 **1034 通过 / 0 失败 / 11 忽略**；两组 DNS 配置集成各 21/21。严格 all-target Clippy（两组）、Cargo fmt 与 Git diff --check 均通过。
- 此批次为仅本地签名候选，不包含在第 3 批远端推送的 SHA 内；独立 L2 审查、GitHub required CI、锁定 Rust 1.99.1 修复与复测、Mihomo 二进制互操作及 macOS NIC/utun 抓包仍待完成。未修改 `master`、系统 DNS/TUN/路由或其他工作树的未提交内容。

## 2026-11-09 — 批次 5：nameserver-policy 普通域名逗号选择器（L2 待审）

- 基于隔离分支 `codex/dns-master-batch4-20261109` 的 `efa18a1a2d1162e967396c9d8d4f05196b9c5f07`，上游 `origin/master` 快照 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定 Mihomo 只读 gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy` 对普通域名键以逗号拆分并共用指定 nameservers。此批仅移植 **普通域名选择器展开**，不宣称多 DNS 上游数组、GeoSite、RuleSet 或 Mihomo orderedmap 冲突优先级等价。
- `clash-lib/src/app/dns/config.rs::parse_nameserver_policy` 将 `example.com,other.test` 展开为两条规范化小写的可匹配键；`resolver/enhanced.rs::match_policy` 将查询域名规范化后查 trie。保持原有单域名/`*.`/`+.` 语法；拒绝空 token、选择器空白、重复及大小写折叠后的冲突、`geosite:` 和 `rule-set:`，不再将普通多域名逗号键拒绝或默默当字面串。
- 先写 `nameserver_policy_expands_comma_selectors_into_runtime_domains`，原代码确定性失败（0/1），修复后通过；另加 `nameserver_policy_rejects_ambiguous_or_unsupported_comma_keys`、YAML→内部配置集成测试，以及 `comma_delimited_nameserver_policy_uses_dedicated_upstream`，用 mock DNS 证明两个域名命中策略上游、未匹配域名仍走主上游。
- 本地验证：macOS，Rust 1.99.0；`--no-default-features --features tun,ring` 核心库 **845 pass/0 fail/11 ignored**，默认 features + `tun,ring` 核心库 **1037 pass/0 fail/11 ignored**；两组 `dns_config_tests` **22/22**，严格 `clippy --all-targets -D warnings`、`cargo fmt --check` 和 `git diff --check` 均通过。
- 未覆盖：policy value 多上游数组（当前 `HashMap<String,String>`）、Mihomo 有序 selector 冲突覆盖语义、实际 Mihomo 二进制互操作、macOS 物理 NIC/utun 抓包、Rust 1.99.1 锁定工具链（本机安装缺少 manifest）、远端 required CI、独立 L2 审查。本批只本地签名提交；不自动推送/合并主线，不修改系统网络。

### 2026-11-06：代理节点 DNS policy 选择器边界

- 固定 `ref-mihomo` gitlink：`63bd52ec794b7051569b76ede2f6cdbf4c091fda`；只读核对 `config/config.go` 的 `ProxyServerNameserverPolicy` 与 `parseNameServerPolicy` 调用，未执行 Mihomo 二进制对照测试。
- 内部配置（含热重载）和 YAML 解析均拒绝带空白字符的 `proxy-server-nameserver-policy` 域名选择器。此前内部配置会接受 `node.example `，但无法匹配实际查询，造成策略静默失效；新增先失败后通过的否定测试。
- 独立节点解析器增加混合大小写回归断言（既有实现已通过），保持节点 DNS 选择不区分 QNAME 大小写。
- 验证：`cargo test -p clash-lib --lib internal_node_dns_policy_rejects_whitespace_selector --features tun,ring`、`cargo test -p clash-lib --test dns_config_tests --features tun,ring -- --test-threads=1`（30/30）、`cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring -- -D warnings`、`cargo fmt --all`。未进行 macOS 网络变更或抓包；Mihomo 的完整规则选择语义仍待运行时对照。

### 2026-11-06：TUN + Fake-IP 节点 DNS 引导路由隔离（L2 待审）

- 开发基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy` 的 `b9e90c0b95a2ca5a4aed752f249f6150a5e0ea61`；固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。参考 `config/config.go::parseDNS` 使用 `parseNameServer(cfg.ProxyServerNameserver, false, ...)`，节点 DNS 不应依赖业务代理规则；Chimera 对特定 DNS 上游允许旧式 `#proxy`，并不自动继承 Mihomo 的引导安全保证。
- 在 `tun.enable && dns.enable && enhanced-mode: fake-ip` 下，`dns.proxy-server-nameserver` 明确拒绝 `#proxy` 代理路由（防止节点解析依赖自身）与 `dhcp://` 系统网络服务 DNS 发现（可能绕过 utun DNS 劫持）；`dns.proxy-server-nameserver-policy` 的选中上游也拒绝 `dhcp://`。在内部配置/热重载的 `Config::validate` 执行相同门禁。普通非 TUN 配置的旧 `#proxy` 语法仍保留。该切片不改变 `dns.nameserver` 的旧业务出口配置。
- 先写 `dns_config_tests::fake_ip_tun_proxy_bootstrap_rejects_proxy_routing_and_dhcp` 否定测试，修复前实际失败；随后实现并加入 `internal_tun_fake_ip_rejects_proxy_bootstrap_dialer_and_dhcp`、策略 DHCP 否定测试和非 TUN 兼容测试。
- **边界**：本切片阻断两种已知的危险引导方式，但未证明其他 DNS 上游的物理 NIC 出口均受控；`default-nameserver`、DNS policy 上游的 bootstrap、macOS service-scoped resolver、真实 NIC/utun 抓包和 Mihomo 二进制互操作仍需后续验证。没有改动宿主机 DNS、路由、TUN、Network Extension 或提升权限。

## 2026-11-06 P0: internal default DNS bootstrap validation (local isolated branch)

- Baseline: `codex/macos-tun-fakeip-dns-privacy` at `db728d5`; fixed read-only Mihomo submodule gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, compared with `config/config.go::parseDNS` (default nameserver must be IP-based).
- `Config::validate` now enforces nonempty, IP-literal `dns.default-nameserver` without `#proxy` or DHCP even for internal configuration and reload, closing a path that bypassed YAML conversion checks. IP-literal DoH remains accepted. This is stricter than accepting system resolver discovery and is deliberate for bootstrap isolation.
- Regression: `internal_default_nameserver_bootstrap_rejects_non_ip_and_proxy_dialers` first failed to compile with the missing validator, then passed after implementation. DNS config integration and strict Clippy pass. This is configuration-level fail-closed, **not** proof of no macOS system DNS leakage; physical NIC/utun capture and L2 review remain required.

## 2026-11-07 P0: DNS policy selector fail-closed validation

- Pinned read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Source comparison: `config/config.go::parseNameServerPolicy` splits comma-delimited keys and validates each raw token through `component/trie/domain.go::ValidAndSplitDomain`. It rejects leading/trailing whitespace and malformed wildcard placement. The Mihomo validator does not itself reject embedded whitespace; Chimera explicitly rejects that extra case because it would create a trie key that silently misses the intended DNS name. This is a conservative privacy divergence, not a claim of byte-for-byte Mihomo equivalence.
- Root cause: both Chimera `dns.nameserver-policy` and `dns.proxy-server-nameserver-policy` stripped whitespace before validating tokens. The permissive Rust trie validator also accepted partial/misplaced wildcards. These accepted keys could bypass intended per-domain/per-node DNS routing. An internal `Config` could bypass YAML expansion and put a comma-delimited node policy key directly into the runtime trie.
- Negative tests were added before production changes. `nameserver_policy_rejects_selector_ambiguity_before_runtime_trie` failed on a leading-space key rewritten to `example.com`; `proxy_nameserver_policy_rejects_selector_ambiguity_before_node_dns` failed on rewritten `node.example`; `internal_proxy_server_policy_rejects_malformed_domain_selectors` failed on a comma-delimited internal key. All three passed after the shared selector validator and internal config guard were fixed. Existing valid keys (`example.com`, `*.example.com`, `.example.com`) remain supported, and comma lists without whitespace still expand.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: 1046 passed, 0 failed, 11 ignored; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1`: 35 passed, 0 failed; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, `cargo fmt --all -- --check` and `git diff --check` passed. The unrelated pre-existing legacy golden `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` still failed (12 passed, 1 failed) because `respect-rules` now requires dedicated node DNS bootstrap; this change did not touch that rule.
- No host DNS, routing, TUN or Network Extension changes, no elevated operations and no real physical NIC/utun packet capture. L2 independent review, maintainer decision and real Mihomo runtime parity remain outstanding. Non-TUN/other-platform checks must be reported separately.

## 2026-11-07 P0: selective unknown DNS/TUN privacy fields

- In a `serde(default)` configuration, unknown YAML keys silently disappear. That can disable requested DNS policy, Fake-IP filtering, DNS hijack or TUN strict route semantics. The pinned read-only Mihomo gitlink remains `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. This guard is a Chimera privacy hardening policy, not a demonstrated equivalent to every Mihomo unknown-key parser behavior.
- Added negative tests before production edits. `unknown_privacy_shaped_dns_field_names_fail_closed` failed initially on `dns.nameserver-polcy`; `unknown_privacy_shaped_tun_field_names_fail_closed` failed initially on `tun.dns-hijak`; `fallback_filter_unknown_privacy_fields_fail_closed` failed initially on `dns.fallback-filter.geoiip`. All pass after repair. Also tested merged YAML anchors and `Config::Str(...).try_parse()` for actual runtime-entry rejection.
- The raw YAML guard (after `apply_merge`, before serde deserialization) rejects privacy-shaped unknown fields and one-edit near-misses in `dns`, `tun` and nested `dns.fallback-filter`. Error messages identify the bad key, not DNS values. Existing supported keys and aliases, plus unrelated vendor keys, stay accepted. This guard is intentionally selective, not a universal ban on all unknown keys. It also does not claim coverage for arbitrary spellings far from known controls.
- Current-source tests: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> 1050 passed, 0 failed, 11 ignored; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> 36 passed, 0 failed; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` and Cargo fmt/diff checks passed. With TUN disabled and ring enabled, `config::def::tests::` -> 18 passed, 0 failed. DNS S01 and S02 integration groups -> 17/17 and 14/14 passed.
- The pre-existing `dns_legacy_golden_tests` failure remains: 12 passed, 1 failed (`s00_respect_rules_and_legacy_proxy_modifier_are_preserved`) because `dns.respect-rules` requires dedicated `proxy-server-nameserver`; this slice does not modify that constraint. Optional Linux cross-check was attempted but stopped in `cc-rs` because `x86_64-linux-gnu-gcc` is not installed; it is an environment block, not proven source failure. No real NIC/utun capture or host network changes; L2 independent review, maintainer decision and Mihomo runtime interoperability remain pending.

## 2026-11-07 P0: macOS TUN Fake-IP DHCP egress fail-closed

- Fixed read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Mihomo `config/config.go::parseNameServer` accepts `dhcp://` for DNS service discovery. Chimera's `clash-lib/src/app/dns/dhcp.rs::probe_dns_server` opens DHCP UDP sockets on the physical interface, then makes clients for the discovered DNS IPs without a proved TUN-isolated egress path. Since scoped macOS DNS ownership and physical-NIC egress cannot be verified without permission and a real packet capture, this slice deliberately **rejects** DHCP in macOS TUN + Fake-IP high-privacy mode instead of claiming Mihomo runtime equivalence.
- Prior to production changes, `macos_fake_ip_tun_rejects_dhcp_in_all_dns_egress_pools` failed because `Config::Str(...).try_parse()` accepted `dns.nameserver: [dhcp://en0]`; `internal_macos_fake_ip_tun_rejects_service_scoped_dhcp_dns_egress` separately failed through direct internal config mutation/re-validation. Both red tests became green after macOS-only `Config::validate` rejected DHCP in four DNS egress scopes: `dns.nameserver`, `dns.fallback`, `dns.direct-nameserver`, and `dns.nameserver-policy`. The existing dedicated node DNS and per-node policy DHCP blocks remain in place.
- Compatibility controls: under macOS non-TUN configuration, DHCP remains parseable in all four pools. TUN with `enhanced-mode: normal` also retains the previous DHCP behavior. No DHCP probe, TUN, system DNS, network route, Network Extension, or elevation was used; these are pure configuration tests.
- Final validation from current source: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1051 passed, 0 failed, 11 ignored**; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> **39 passed, 0 failed**; DNS S01/S02 integration tests -> **17/17 and 14/14 passed**; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` and Cargo fmt/diff checks passed. No-feature `ring` build: `internal_macos_dhcp_cannot_mask_missing_tun_feature` ran red-before-green and now passes; an unsupported TUN configuration reports the missing `tun` feature first, before any DHCP-specific check. The TUN-dependent tests are feature-gated so this non-TUN matrix does not spuriously fail. These checks cannot establish real host DNS leak freedom.
- Risk / next step: refusing intentionally configured DHCP is a documented high-privacy compatibility divergence from Mihomo, required until macOS service-scoped resolver traffic is measured under an explicitly authorized physical NIC/utun test. Consider replacing the refusal with a genuinely managed transport only after packet captures, rollback and L2 review establish its egress behavior.

## 2026-11-07 P0: explicit DNS interface override fail-closed on macOS

- Pinned read-only Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`: `config/config.go::parseNameServer` retains URL fragment parameters, including `#interface`; Chimera's `Config::parse_nameserver` materializes `#interface` into `NameServer.interface`, which `app/dns/helper.rs::make_clients` passes to `DnsClient::new_client` as a forced socket interface. A physical NIC override can bypass network-path-managed DNS egress. The new explicit refusal is a *macOS TUN + Fake-IP security divergence*, not a claim that all Mihomo fragment semantics are equivalent.
- First added offline negative test `internal_macos_fake_ip_tun_rejects_physical_dns_interface_overrides`, using a **synthetic** `OutboundInterface` with no actual interface lookup, socket creation or host network mutation. It failed on `dns.nameserver` before the change. Then extended the existing macOS-only high-privacy validation to refuse `#interface` for all seven pools: `dns.nameserver`, `dns.default-nameserver`, `dns.fallback`, `dns.direct-nameserver`, `dns.nameserver-policy`, `dns.proxy-server-nameserver`, and `dns.proxy-server-nameserver-policy`. The test passed afterwards for every case. Existing bootstrap/DHCP isolation checks remain in place.
- Compatibility: synthetic interface-bound `dns.nameserver` and `dns.default-nameserver` remain valid with TUN off; also valid with TUN on but `enhanced-mode: normal`. These control tests pass. The non-TUN `ring` feature combination passes the non-TUN control; TUN-dependent tests are feature-gated.
- Current-source validation: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1054 passed, 0 failed, 11 ignored**; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> **39 passed, 0 failed**; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, fmt and diff checks passed. The older legacy golden failure `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` is tracked above and not resolved by this slice; other-platform compilation and live system DNS capture remain outstanding.
- This only blocks explicit upstream `#interface` overrides under the named macOS privacy configuration. It **does not guarantee** that an unspecified DNS socket cannot use a physical NIC, that macOS service resolver ownership is correct, or that all host DNS packets enter TUN. Before allowing `#interface` again, a managed egress mechanism, authorized physical NIC/utun packet capture, L2 independent review and maintainer approval are necessary. No host DNS, route, TUN, Network Extension or permissions were changed here.

## 2026-11-07 P0: macOS TUN Fake-IP DNS #interface egress override

- Pinned read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; inspected `config/config.go::parseNameServer` (`u.Fragment` params) and Chimera `app/dns/helper.rs::make_clients` (`NameServer.interface` forwarded as `Opts.iface`), `app/net/mod.rs::OutboundInterface`. An explicit DNS `#interface` can bind sockets to a physical network service and bypass the verified managed DNS path. This is a **deliberate high-privacy restriction** rather than a claim of exact Mihomo compatibility.
- Added `internal_macos_fake_ip_tun_rejects_physical_dns_interface_overrides` using a synthetic `OutboundInterface` and all seven DNS upstream scopes (`nameserver`, `default-nameserver`, `fallback`, `direct-nameserver`, `nameserver-policy`, `proxy-server-nameserver`, `proxy-server-nameserver-policy`). It failed first because internal `Config::validate` accepted `dns.nameserver` with a physical interface, then passed after fail-closed validation. No real NIC or socket was accessed by this test.
- Compatibility: `non_tun_dns_interface_override_keeps_legacy_compatibility` passes both TUN-enabled and no-TUN builds, and `tun_normal_mode_dns_interface_override_keeps_legacy_compatibility` passes. Existing DNS fields without explicit interface bindings remain unaffected.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1054 passed, 0 failed, 11 ignored**; DNS config integration -> **39 passed, 0 failed**; strict Clippy TUN+Ring `--all-targets -D warnings` passed; strict no-TUN Ring `--lib -D warnings` passed. S01/S02 integration tests rerun on this source -> **17/17 and 14/14 passed**. This is config-level isolation only; independent L2 review and physical NIC/utun capture under separate authorization remain required.

## 2026-11-07 P0: adjacent-transposition privacy field diagnostics

- Fixed read-only Mihomo reference gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; Mihomo's `config/config.go::parseNameServer` and DNS policy handling were checked read-only. This is a Chimera configuration safety gate, **not** evidence of Mihomo runtime equivalence.
- YAML's permissive legacy field handling previously ignored a transposed `tun.strcit-route`, potentially disabling an intended strict-routing guarantee. Added it to the existing negative test **before** implementation: `unknown_privacy_shaped_tun_field_names_fail_closed` failed with `strcit-route was ignored` (1 passed, 1 failed). `dns.edns-clinet-subnet` is a control for the existing prefix-based guard.
- `clash-lib/src/config/def.rs::within_one_edit` now also detects a single adjacent-character swap when comparing known DNS/TUN security keys; unknown unrelated vendor keys remain accepted. Errors identify the field, not its value. No host DNS, routes, NIC, TUN or permissions were touched.
- `cargo test -p clash-lib --lib --features 'tun ring' unknown_privacy_shaped` -> 2 passed, 0 failed; full `--lib` -> 1054 passed, 0 failed, 11 ignored; `dns_config_tests` -> 39 passed, 0 failed; `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` passed. Physical NIC/utun capture and L2 independent review remain outstanding.
- Next: test and close DNS bootstrap socket egress bypasses with offline resolver/path tests; separately validate scoped macOS resolver ownership under explicit host-network authorization.

## 2026-11-07 11:13 PST: node DNS transport resolver isolation on protected branch

- Read-only pinned Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, comparison `config/config.go::parseDNS` and `parseNameServer`: dedicated `proxy-server-nameserver` / per-node policy transports are distinct from general DNS and must not be silently delegated to libc/system DNS. Also reviewed the previously isolated signed local implementation `ff737ef70ed48dfa3365ef405fff8f9974708b65` on `codex/macos-node-dns-rebuild-guard-20261106`; only the minimal transport wiring and invariant were reimplemented here, not its independent lifecycle/reset changes.
- Test-first **red**: `app::dns::helper::tests::node_dns_group_fails_closed_without_explicit_transport_resolver` accepted a literal-IP node DNS upstream with missing outbound resolver (even when a separate bootstrap resolver is provided), which can cause the `dns_stream_builder` transport to choose `SystemResolver` when opening or rebuilding its stream. This is a DNS-egress isolation flaw even though the upstream IP itself needs no initial lookup.
- Production change: `helper.rs::make_clients` now requires a nonempty dedicated `proxy_server` group to have an explicit outbound transport resolver. `resolver/enhanced.rs::new` passes its managed `default_resolver` into both dedicated `proxy_server_nameserver` and `proxy_server_nameserver_policy` client groups rather than `None`. Empty node DNS groups remain a legacy no-op; an IP-literal upstream with a managed transport continues to initialize. **Green**: both dedicated group tests passed (2/2), including under `--no-default-features --features ring`.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: **1056 passed, 0 failed, 11 ignored**. `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1`: **39 passed, 0 failed**. DNS S01 and S02 suites: **17/17 and 14/14 passed**. Strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` passed; `cargo fmt --all -- --check` and `git diff --check` passed.
- Scope: configuration and offline client construction, not a physical NIC or utun packet-capture proof and not a complete Mihomo runtime parity claim. A parent node bootstrap resolver is **not** used as a substitute for a transport resolver. Pending separately: bounded network-path reset/cancellation, host system DNS ownership, L2 independent review, maintainer decision and authorized physical NIC/utun capture.

## 2026-11-07 11:20 PST: managed node DNS reset and rebuild isolation

- Read-only pinned Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` and comparison with the prior independent Chimera branch `codex/macos-node-dns-rebuild-guard-20261106` signed commits `ff737ef70ed48dfa3365ef405fff8f9974708b65`, `9258fc544dc2b07559763313ad5e23f0771b458d`, and `4f399ddfe21669cf134f423fb08a2451c3999013`. This is a locally verified network-lifecycle safety hardening step, **not** a complete Mihomo binary parity or packet capture result.
- Test first, **red**: `reset_transport_resets_distinct_managed_outbound_resolver` expected both bootstrap and a distinct transport resolver to reset on network-path change, but the old implementation returned `3` instead of `7` and failed to reset the transport resolver. The caller must never reuse old-path DNS transport sockets after a network transition.
- Production fix in `app/dns/dns_client.rs::DnsClient::reset_transport`: first close local active stream/background and mark upstream address for re-resolution; run both *distinct* managed resolver resets concurrently with `tokio::join!`, dedup a shared `Arc`, saturate reset counts, preserve failures for both roles and return an error (fail-closed). The outer `EnhancedResolver` bounds reset attempts. The stall fault injection verifies one hanging bootstrap cannot prevent outbound cleanup from being attempted, while error aggregation keeps both failure reasons observable.
- Green: 9 reset-transport-related unit tests and the separately filtered `stalled_bootstrap_reset_cannot_prevent_outbound_reset_attempt` passed; network bootstrap timeout recovery `network_reset_bootstrap_timeout_fails_before_transport_rebuild` passed without network I/O and retained pending refresh. With `--no-default-features --features ring`, the 9 reset tests also passed. Full `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: **1062 passed, 0 failed, 11 ignored**. DNS config integration: **39 passed, 0 failed**. DNS S01/S02: **17/17 and 14/14 passed** (before extra timeout-only test). Strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` passed.
- No host DNS/TUN/routes, macOS Network Extension, permission changes, or DHCP/physical NIC probes. Do not infer zero leakage without authorized physical NIC and utun captures, managed egress ownership and cancellation tests. L2 independent review and maintainer decision remain pending; the known old DNS golden test requiring legacy `respect-rules` without dedicated proxy bootstrap still conflicts with current fail-closed policy.

## 2026-11-07 11:27 PST: IP-only default bootstrap without SystemResolver fallback

- Pinned read-only Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`: `config/config.go::parseDNS` requires `default-nameserver` upstream addresses to be IP literals (excluding Mihomo's special `system` notation, which Chimera separately rejects under the applicable bootstrap contract). `EnhancedResolver::new_with_network_path_source` previously passed `outbound_resolver=None` when constructing Chimera's `bootstrap` group, so `dns_client::dns_stream_builder` would instantiate `SystemResolver` as the transport resolver even though DNS server IP addresses required no hostname bootstrap. That left an unnecessary hidden OS resolver in the recursive DNS chain.
- Test first, **red**: `bootstrap_dns_group_requires_managed_literal_transport_resolver` showed that a nonempty IP-literal `bootstrap` client group still initialized without any transport resolver. The same test verifies that explicit managed transport and empty legacy groups remain accepted. Production change: `make_clients` now demands an explicit transport resolver for nonempty `bootstrap` as well as `proxy_server` groups. Bootstrap construction passes an instance of the existing `execution::LiteralOnlyResolver` (`Default`, no pins), which can only resolve literal IPs and fails on unpinned hostnames; `LiteralOnlyResolver` becomes crate-visible for reuse. This prevents this constructor from selecting the implicit system resolver without changing the general non-bootstrap legacy dialer behavior.
- Test after fix, **green**: `bootstrap_dns_group_requires_managed_literal_transport_resolver` passed with both `tun,ring` and `--no-default-features --features ring`. The existing `s03b_hostname_bootstrap_and_unimplemented_wire_fail_closed` test proves the reused literal-only resolver rejects unpinned domains and accepts literal IPs. Whole `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1063 passed, 0 failed, 11 ignored**; DNS config **39/39**, S01 **17/17**, S02 **14/14**, strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, Cargo fmt and diff checks all passed.
- This is code-path isolation, not proof of macOS service-resolver ownership or physical NIC/utun zero leakage. The literal-only transport restriction for the bootstrap chain is a hardening measure, and other intentionally legacy `SystemResolver` uses remain. L2 independent review, maintainer decision and authorized live packet capture remain outstanding.

## 2026-11-07 11:33 PST: fail closed on nested DNS listener and TLS key typos

- Reference baseline remains the untouched Mihomo submodule `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. The `dns.listen` mapping and its TLS listener variants are existing **Chimera** extensions, not a claim that Mihomo supports the same object schema. They are a DNS ingress privacy/readiness boundary: a misspelled protocol key can produce an empty or incomplete listener set despite YAML appearing to configure TCP/DoH/DoT; silently ignored TLS certificate/key fields can conceal unusable encryption settings.
- Tests first, **red**: `dns_listener_privacy_typos_cannot_silently_disable_listener` accepted `dns.listen.tpc` instead of `tcp`; `dns_tls_listener_certificate_typos_fail_closed` accepted `dns.listen.doh.ca-kye` rather than `ca-key`. Both returned precise failures after implementation. Production `config/def.rs` now checks security-shaped unknown protocol keys and nested `addr` / `ca-cert` / `ca-key` / `hostname` misspellings (and unsupported `dot.hostname`) after YAML merges but before permissive Serde. Errors include only the field path, not its potentially secret value. Ordinary vendor extension keys remain accepted.
- The `Config::Str(...).try_parse()` integration `dns_listener_privacy_typos_fail_before_any_listener_is_started` passes, showing that both a listener-protocol typo and a nested TLS key typo are rejected before runtime. No real listener or TLS certificate was opened for this test.
- Verification: `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` -> **1065 passed, 0 failed, 11 ignored**; `cargo test -p clash-lib --features 'tun ring' --test dns_config_tests -- --test-threads=1` -> **40 passed, 0 failed**. Strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings` and `cargo fmt --all -- --check` / `git diff --check` passed. A focused no-TUN + Ring listener typo test passed; broader platform matrices and macOS physical NIC/utun validation remain pending.
- This is conservative compatibility hardening, not an assertion that all unknown YAML keys are rejected. L2 independent review and maintainer decision remain required; do not claim macOS service-scoped system DNS ownership or zero leakage without authorized live captures.

## 2026-11-07 11:40 PST: parallel DNS and outbound recovery cleanup

- P0 network-path change recovery, offline-only. The fixed read-only Mihomo baseline is still `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; this particular recovery orchestration is Chimera-specific, so parity with Mihomo's platform networking cannot be claimed. Caller: `runtime/components.rs::reset_resources_report`, resetting the DNS resolver and outbound-manager connection pools after a path change. Previously `app/network.rs::reset_resources_report` waited for DNS cleanup (up to half the 15-second recovery budget) **before** polling the independent connection-pool reset, despite the comment promising that each component gets an attempt. If the outer recovery operation was cancelled early while DNS was stalled, outbound pools remained stale with no reset attempt.
- Test first, **red**: `cancelled_network_recovery_still_attempts_outbound_pool_reset` used a pending DNS reset and a short bounded outer cancellation, demonstrating the outbound future was never polled. Production fix uses `tokio::join!(attempt(dns), attempt(pools))` to start both independently, retaining the existing per-component bounded `attempt` timeout and typed `RecoveryReport` fields rather than swallowing failures.
- **Green**: both symmetric cancellation tests and `concurrent_network_recovery_retains_both_failure_causes` passed; `app::network::tests::` suite -> **18 passed, 0 failed** before adding the latter two tests (final total 20 expected). The existing long-stall test still passes: both components get an attempt, but a stalled DNS cleanup remains timed out and reported, not marked successful.
- Final `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1`: **1068 passed, 0 failed, 11 ignored**; strict `cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`, Cargo fmt and diff checks passed. No-TUN + Ring focused cancellation test passed. Existing DNS S01/S02/config integration results are tracked in preceding entries and should not be mistaken for post-change retests.
- This is offline lifecycle cleanup hardening, not validation of actual route selection, macOS DNS service ownership, or physical NIC / utun no-leak behavior. L2 independent review and maintainer approval remain pending. No system DNS, TUN, route, Network Extension, or permission modifications occurred.

## 2026-11-07 P0: explicit empty node DNS bootstrap on internal reload

- Fixed read-only Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; reference `config/config.go` DNS parsing and dedicated node resolver. This change is a Chimera fail-closed boundary, not a claim of complete Mihomo runtime parity.
- Internal configuration/reload could set `dns.proxy-server-nameserver = Some([])` without a policy or `respect-rules`, pass `Config::validate`, and defer failure until resolver construction. A negative test first failed with `explicit empty node DNS silently accepted`; now validation rejects an explicitly empty pool while retaining `None` as the legacy unspecified configuration.
- No system DNS, routing, TUN, Network Extension or privileged operations. L2 review and real physical NIC/utun egress capture remain outstanding.

## 2026-11-07 12:55 PST: node DNS outbound isolation regression probes

- Fixed read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; compared `config/config.go::parseDNS` dedicated `ProxyServerNameserver` and `ProxyServerPolicy` construction with Chimera `resolver/enhanced.rs::ip_exchange`.
- Added two offline regression tests at the **dedicated outbound resolver** boundary: mixed-case DNS wire QNAME must select node policy rather than default node DNS; when that node policy fails, neither default node DNS nor general fallback is queried. These use synthetic DNS clients, not physical NIC/TUN.
- Initial failure of the second test was caused by the test fixture querying `proxy.example.com` rather than the policy's `node.example.com`; corrected the fixture and both tests passed **without production changes**. This is additional verified coverage, **not** a newly demonstrated or repaired production leak.
- Still pending: transport-level fallback/bootstrap socket path fault injection, macOS NIC/utun capture, independent L2 review, and actual Mihomo interoperability.


## 2026-11-07 P0: internal DNS policy case-collision fail-closed (L2 pending)

- Starting isolated worktree HEAD `83442073799f4e4b189cf1f395978c202e044485`; another local signer advanced the same isolated branch to `1aad10916f4a7cac77adc289de503ca55c342b79` during this run with separate node-DNS synthetic probe tests. No user changes in the main checkout were touched. The read-only ref-mihomo baseline is `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; `config/config.go::parseNameServerPolicy` identifies case-insensitive domain matching, while Chimera's YAML parser already lowercase-normalizes/rejects duplicates.
- **Red before fix:** `internal_nameserver_policy_rejects_case_insensitive_duplicate_selectors` showed `Config::validate` accepting distinct `Private.Example` and `private.example` keys in an internal `HashMap` with different DNS upstreams. `EnhancedResolver::new` lowercase-inserts the keys into one trie, allowing nondeterministic replacement based on HashMap iteration order. A reload could therefore silently select the wrong privacy-domain upstream.
- **Fix:** internal validation now rejects case-folded duplicate `dns.nameserver-policy` selectors and reports only the field-level conflict, not domain or server values. It leaves single-key legacy settings and the YAML normalization path intact. This is a deliberately fail-closed choice where the old internal representation was ambiguous, not a claim of full Mihomo nameserver-policy parity.
- **Tests:** first negative unit test failed (0/1), then passed (1/1). `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` => 880 passed, 0 failed, 11 ignored; `cargo test -p clash-lib --test dns_config_tests --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` => 40 passed, 0 failed; TUN+Ring strict all-targets Clippy, Cargo fmt check and diff check passed. Non-TUN+Ring strict lib-only Clippy and exact new test passed; all-targets strict Clippy fails on pre-existing `connection_chain_tests.rs` unused import `Socks5UdpSession` and unused helper `wait_for_rule_interface_failure` in no-TUN feature builds; not waived or changed.
- **Additional regression:** offline DNS policy S01 suite 17/17, S02 suite 14/14 passed. Public GitHub read (not local fetch): remote master `e5606456ccb51a699dba5b29401cf2aad70fdb54`, its push CI and Windows Network Regression succeeded; open PRs #104, #85, #58 are unrelated. The cached local `origin/master` ref is older, so no synchronized-branch claim is made.
- **Scope:** offline config/runtime-entry validation only. Node DNS transport fallback, DNS Proxy Extension/service-scoped macOS ownership, physical NIC/utun captures, Mihomo runtime comparison, and independent L2 review remain unverified. No system DNS, routes, TUN, Network Extension, privilege changes, remote pushes, PR edits, or shared-history rewriting.


## 2026-11-07 13:28 PST: live proxy-provider node DNS registration and cache isolation (L2 pending)

- Fixed read-only Mihomo baseline: `63bd52ec794b7051569b76ede2f6cdbf4c091fda` (`config/config.go::parseDNS` builds `ProxyServerNameserver` / `ProxyServerPolicy`); our implementation uses Chimera's per-provider revision model, not a literal transplant. Existing `resolver/enhanced.rs` computed `proxy_server_domains` from only startup plain outbounds. Later provider `server_name()` hostnames were absent, so an actual proxy endpoint dial through `Dispatcher` / `DirectConnector` could resolve with normal `dns.nameserver` or `dns.fallback` instead of the separately configured proxy-node DNS.
- **Test-first red:** `refreshed_proxy_provider_host_uses_dedicated_node_dns_not_public_main` returned a synthetic public DNS `192.0.2.10` instead of the dedicated node DNS `192.0.2.11` (0/1). `protected_provider_registers_new_proxy_host_before_publishing_refresh` recorded zero registrations for two accepted provider revisions (0/1); both now pass. A further cache repro `provider_node_dns_never_reuses_public_answer_cached_before_registration` initially returned the previously cached public DNS answer rather than node DNS (0/1), fixed by bypassing the shared positive/negative cache for live provider-owned A/AAAA QNAMEs.
- **Implementation:** `ClashResolver::replace_proxy_provider_dns_domains` is a backward-compatible optional trait hook. `EnhancedResolver` stores provider-keyed, case-normalized exact node hostnames and selects the dedicated node upstream/policy before normal policy, main and fallback. The `ProxySetProvider` accepted-revision updater registers endpoints via `HealthCheck` / `ProxyManager` before publication under the provider revision write lock; competing revisions cannot invert DNS ownership and visible proxy state. An empty refresh removes only that owner's domains. Static startup proxy matching and legacy resolvers are unchanged. Registration applies to any provider when an EnhancedResolver has an explicit node DNS pool, including non-TUN configurations.
- Additional test-first failures and fixes: `provider_node_dns_registration_is_not_limited_to_tun_fake_ip` (0/1) confirmed legacy non-TUN provider registration had been mistakenly gated, now passes. `provider_node_dns_normalizes_unicode_hostname_to_wire_idna` (0/1) confirmed Unicode provider hostnames were not equal to ASCII-wire QNAMEs, now canonicalized through URL IDNA before registration and passed. `provider_node_dns_ownership_is_per_provider_and_removed_on_empty_refresh` tests overlapping providers and complete removal (passed).
- Verification after primary change: TUN + Ring `--lib` **883 passed / 0 failed / 11 ignored** before adding the last two tests; TUN + Ring strict all-targets Clippy passed; DNS config integration 40/40; no-TUN + Ring strict lib Clippy passed and two focused provider/cache tests passed. After the final IDNA/non-TUN cases, the focused tests and TUN + Ring strict Clippy again passed. Refer to final run log for full post-change counts.
- **Final feature-matrix check:** after Unicode/legacy cases, TUN + Ring core library 886 passed, 0 failed, 11 ignored; S01 17/17 and S02 14/14 passed. Additional TUN + Ring + WireGuard strict all-target Clippy passed, with 2 provider WireGuard unit tests passing. No-TUN + Ring full core library: 846 passed, 7 failed, 9 ignored; the 7 known feature-gating failures are all in `config/internal/convert/mod.rs` where TUN-enabled fixtures are run against a build compiled without `tun`, not in new provider isolation tests. No-TUN strict lib-only Clippy passed; full all-targets no-TUN Clippy remains blocked by unrelated unused import/helper in `tests/connection_chain_tests.rs`.
- **Final post-change core retest:** TUN + Ring 887 passed, 0 failed, 11 ignored; DNS config 40/40 passed. A synthetic registrar fault test also passed and verifies that the last visible proxy revision is preserved if node DNS ownership registration fails. `dns_legacy_golden_tests` returned 12 passed / 1 failed: the already documented `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` fixture has `respect-rules` without a dedicated node DNS pool, which the pre-existing fail-closed Mihomo-compatibility validation now rejects. The failure predates this slice, remains unresolved, and must not be described as all-legacy-golden green.
- **Boundaries and risks:** no permission to activate or capture macOS NIC/utun, DNS service ownership or Network Extension; thus offline proof only. When no dedicated `proxy-server-nameserver` exists, legacy ordinary DNS behavior is retained, not advertised as leak-proof. The provider fetcher persists content/hash before its asynchronous updater; a hypothetical registrar error retains the old visible provider revision and logs a warning but may leave a newer cached source/hash. Resolving that error propagation/retry atomicity is a distinct review task. Cross Linux offline `cargo check --target x86_64-unknown-linux-gnu` blocked by missing `x86_64-linux-gnu-gcc` required by `ring`, not a code diagnostic. Independent L2 review and parity/live captures remain pending; no host network, permission, remote Git/PR or shared-history operations.


## 2026-11-07 13:36 PST: proxy-provider DNS registration failure remains retryable (L2 pending)

- Follow-up to signed local `9236b73` dynamic proxy-provider node DNS isolation; fixed, untouched Mihomo reference gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. This entry concerns Chimera's provider fetch/update consistency, not a claim that Mihomo uses the same updater implementation.
- **Red regression before fix:** expanded `provider_dns_registration_failure_preserves_last_visible_revision` with two accepted-source attempts and a synthetic registrar failure. The failed refresh incorrectly returned `Ok(())` after the fetcher had already committed a new cache/hash, preventing same-content retries. The test initially failed with `a failed DNS node registration must not report successful provider refresh`. **Green:** registrar error now reaches the provider caller, the last-good cached YAML and visible proxy revision remain unchanged, and an identical subsequent source refresh successfully registers and publishes the node.
- **Fix:** Fetcher update hooks return a fallible async result. Manual, watcher and periodic updates use one serialized `update_inner` path: read/parse, apply the provider/rule revision, then persist new cache and content hash. A failed hook cannot advance the hash and is retried. Initial provider publication must succeed before `start_polling` enables periodic fetching, preventing an initial poll from overtaking the first node-DNS registration. Rule provider hooks retain their previous successful behavior.
- **Startup negative test:** `provider_initial_dns_failure_rejects_startup_without_polling` verifies that an initial DNS registration failure propagates, leaves no visible proxy revision, and does not start the poller (bounded offline read counter). This is fail-closed readiness, not evidence about macOS physical egress.
- **Verification on this follow-up:** `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` -> **888 passed, 0 failed, 11 ignored**; `dns_config_tests` **40/40**, `dns_policy_s01_tests` **17/17**, `dns_policy_s02_tests` **14/14**. Strict `cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring --locked -j 6 -- -D warnings` and variant `tun,ring,wireguard` passed; no-TUN+Ring strict `--lib` Clippy and both focused failure tests passed. The known no-TUN all-target and full-unit feature-gating limitations remain as recorded above.
- **Remaining limit:** on a rare disk cache-write failure *after* successful registration and in-memory publication, the visible revision can be newer than its persisted source; the next refresh can retry cache persistence. Cross-process atomic rollback and live packet-capture evidence are not provided by this test slice. Independent L2 review, service-scoped DNS ownership verification, physical NIC/utun captures, and full Mihomo interop remain pending. No host networking, permissions, remote Git, PRs or shared-history operations were performed.


## 2026-11-07 14:03 PST: provider DNS query snapshot routing (L2 pending)

- **Read-only reference:** Mihomo fixed submodule `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, `config/config.go::parseDNS` creates separate `ProxyServerNameserver` and `ProxyServerPolicy`, `dns/resolver.go` constructs its dedicated proxy resolver. This is a Chimera-specific concurrency hardening of that routing intent, not a claim of identical Mihomo locking semantics. The local isolated branch began at signed `e1821d434c02584460ff4c30fb48fa942e2a4f80` and was clean.
- **Issue:** `EnhancedResolver::exchange` checked provider ownership once to bypass shared public DNS caches, but `ip_exchange` checked the mutable provider registry again. A concurrent provider removal could occur between those awaits, changing an already classified proxy-node query to the generic `nameserver`/`fallback` path. An in-flight lookup should keep its initially selected dedicated node DNS destination.
- **Negative regression:** `provider_node_dns_snapshot_survives_concurrent_owner_removal` registers a provider host, snapshots ownership, removes the owner, then asserts that an already classified request still reaches the dedicated node DNS (synthetic `192.0.2.11`) without querying the public main DNS (`192.0.2.10`). Initial compile failed because the snapshot-aware exchange path was absent; after implementation it passed. The test deterministically models the interleaving, not a probabilistic stress test.
- **Fix:** thread the provider ownership decision through `exchange_no_cache_with_policy` into `ip_exchange_with_provider_snapshot`, keeping dedicated node DNS for the entire in-flight query. Existing static node matching, live provider matching for direct calls, node policy precedence, negative/positive shared-cache bypass and normal DNS fallback semantics are preserved. A new provider appearing after the initial cache decision still needs an independent registration/cache race review.
- **Validation:** `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` => **889 passed, 0 failed, 11 ignored**; `dns_config_tests` **40/40**, `dns_policy_s01_tests` **17/17**, `dns_policy_s02_tests` **14/14**. Strict TUN+Ring all-target Clippy and TUN+Ring+WireGuard all-target Clippy passed; no-TUN+Ring strict lib Clippy and the exact snapshot test passed. `cargo fmt --all -- --check` and `git diff --check` passed.
- **Boundaries:** no physical NIC/utun capture, no host DNS/routes/TUN/Network Extension changes, no real Mihomo binary interoperability. Service-scoped macOS resolver ownership and DNS Proxy activation remain blocked on separately authorized signed host testing. Independent L2 review/maintainer approval remain pending. Local `origin/master` is stale (`286941f`); read-only `git ls-remote` reports remote master `e5606456ccb51a699dba5b29401cf2aad70fdb54` on this date, without fetching or changing the branch. PR/CI status could not be verified from the available CLI/search results.


## 2026-11-07 14:28 PST — P0 provider startup cache acceptance ordering (L2 pending)

- Starting isolated branch HEAD: `1c487b0884ff92242f8e7a5293db9cf96b6d736c`, clean before editing; read-only Mihomo gitlink remains `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. In that baseline `config/config.go::parseDNS` constructs the dedicated `ProxyServerNameserver` / policy, and requires a nonempty proxy bootstrap pool for `respect-rules`. Chimera's provider persistence is a local implementation detail, not a literal Mihomo port.
- **Failing negative test before fix:** extended `provider_initial_dns_failure_rejects_startup_without_polling` to assert that a failed *first* node-DNS registration leaves no persisted cache. It failed: `initial()` saved downloaded YAML/cache hash before the provider updater registered node DNS, so a rejected provider could survive a process restart. This can undermine the expected fail-closed startup lifecycle.
- **Implementation:** `Fetcher::initial` now parses, invokes its fallible updater (including node-DNS domain registration and publication), **then** commits accepted cache/hash and schedules initial polling eligibility. Both `ProxySetProvider::initialize` and rule-provider initialization use this single path rather than a second, post-cache updater call. Initial cache timestamps are captured on first read and not re-read after the updater (no fallible metadata access after publication).
- **After-fix checks:** same failure test is green; new `failed_initial_dns_registration_preserves_corrupt_cache_until_accepted_recovery` verifies that a corrupt cached provider is not replaced when a remote repair fails node-DNS registration, and a subsequent successful initial registration atomically replaces that cache and publishes the recovered node. Existing `invalid_cached_provider_recovers_remote_content_atomically` test still passes.
- **Verification:** `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` **890 passed, 0 failed, 11 ignored**; `dns_config_tests` 40/40, `dns_policy_s01_tests` 17/17, `dns_policy_s02_tests` 14/14. `cargo fmt --all -- --check`, strict Clippy (`-D warnings`) for `tun,ring` and `tun,ring,wireguard` all-targets, plus `ring` lib-only and one no-TUN focused startup recovery test passed.
- **Unrelated inherited conflict:** `cargo test -p clash-lib --test dns_legacy_golden_tests --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1` yields 12 passed, 1 failed. `s00_respect_rules_and_legacy_proxy_modifier_are_preserved` expects `respect-rules: true` without `proxy-server-nameserver` to parse, whereas the existing `Config::validate` rejects it to prevent proxy bootstrap loops (consistent with the above fixed Mihomo baseline). Neither the failing test nor the validator was modified in this iteration; this existing semantic/legacy-contract conflict needs an explicit governance decision, not a weakened privacy guard.
- **Additional failing tests then fix:** `startup_staging_failure_prevents_node_registration_publication` and `refresh_staging_failure_prevents_node_registration_publication` both failed before the change (callback was invoked even though the destination parent was a regular file and cache persistence would necessarily fail). Fetcher now writes and fsyncs a `NamedTempFile` in the destination directory **before** invoking the provider/rule update hook; the accepted revision is atomically renamed only after a successful updater. Both tests now pass. Existing provider registration failure tests also assert the staged file is cleaned up, leaving no rejected endpoint data on disk. TUN+Ring core tests after staging: **892 passed, 0 failed, 11 ignored**; DNS config/S01/S02: **40/40, 17/17, 14/14**; strict Clippy for TUN+Ring and TUN+Ring+WireGuard passed.
- **Remaining risk:** an atomic rename can still fail *after* a successful updater, e.g. if the destination directory is replaced concurrently; this run does not establish cross-process rollback across DNS registration, in-memory provider state and disk persistence. Next step is a deterministic commit-time failure injection plus an explicit compensation/rollback or retry policy. No macOS DNS service takeover, route modification, TUN/Network Extension activation, privilege change or NIC/utun capture was undertaken. Independent L2 review and actual Mihomo runtime parity remain pending. Remote `master` observed by read-only GitHub API as `e5606456ccb51a699dba5b29401cf2aad70fdb54`, with recent CI and Windows regression successful; open PRs #104, #85, #58 were not modified.


## 2026-11-07 14:43 PST — P0 provider insertion during DNS query must not poison ordinary cache (L2 pending)

- Starting isolated branch HEAD `16de7fb0db060d8ec2059d93e523eadd1fdd5d88`; fixed, read-only ref-mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` builds separate node DNS pool/policy via `config/config.go::parseDNS`. Chimera's live provider registry and asynchronous DNS answer cache are implementation-specific, so the test verifies the intended separation rather than exact Mihomo lock behavior.
- **Red before fix:** `provider_registration_during_query_never_caches_node_answer_as_public_dns` captures a query initially classified as ordinary DNS, registers `proxy.example.com` as a provider node, then lets the lookup select the dedicated node upstream. With the provider subsequently removed, the next ordinary DNS lookup incorrectly reused the node-only synthetic `192.0.2.11` from the shared cache rather than obtaining the ordinary upstream's `192.0.2.10`; initially 0/1.
- **Fix:** `exchange_no_cache_with_policy` carries a per-exchange indication of which upstream role actually won after any awaited live-provider lookup. Results resolved through a **dynamic provider** node DNS pool/policy cannot populate generic positive/negative caches, even when registration/removal interleaves with the initial classification. Static startup proxy domains retain their prior cache behavior. The first implementation incorrectly disabled static node caching, causing `proxy_server_nameserver_precedes_nameserver_policy_without_leaking` to fail; this regression was caught and corrected before final validation.
- **Green:** TUN+Ring core lib `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 6 -- --test-threads=1`: **893 passed, 0 failed, 11 ignored**. `dns_config_tests` 40/40, S01 17/17, S02 14/14. Strict TUN+Ring all-target Clippy passed. Inherited S00 golden mismatch `respect-rules` without dedicated bootstrap remains as documented in the previous entry; this slice did not modify it or weaken privacy validation.
- **Follow-up ordinary DNS lock regression:** `ordinary_dns_without_node_pool_does_not_wait_for_provider_registry` holds the live provider registry's write lock and runs an ordinary A lookup with no proxy-node DNS configured. Before the change it timed out at 150 ms because normal DNS needlessly acquired the provider read lock; after short-circuiting when `proxy_resolver.is_none()`, it passed without waiting. The earlier provider-insertion cache isolation test remained green. TUN+Ring core tests after this guard: **894 passed, 0 failed, 11 ignored**; TUN+Ring+WireGuard strict all-targets Clippy, fmt and diff checks passed.
- **Limits:** the regression models ownership insertion at a deterministic continuation point; it does not demonstrate host-wide packet nonleakage, run Mihomo binary comparison or exhaustively test all lock interleavings. Remaining P0 questions include provider registration racing with a simultaneous *cache hit*, system-service DNS ownership, and bootstrap egress after path changes. No system DNS, routes, utun, Network Extension, privileges, shared Git history, remote PRs or pushes were modified. Independent L2 review and final macOS NIC/utun capture pending.


## 2026-11-07 14:58 PST — provider cache destination type preflight (L2 pending)

- Starting local signed HEAD `0262dcef14dc5715b33b030d4d9a04535991dbd0`; fixed, read-only Mihomo baseline `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. This is a Chimera-specific provider cache lifecycle guard and does not imply a Mihomo cache implementation match.
- **Test-first negative repro:** `directory_cache_destination_must_not_publish_new_proxy_revision` made the cache destination a real directory, then invoked a synthetic refresh. The existing staging step wrote a temporary file successfully, then the provider updater published a new node before the final rename failed. The regression observed the updater's publication counter as **1 instead of 0** (0/1).
- **Fix:** `stage_cache_write` rejects a cache destination that already exists but is neither a regular file nor a symlink, before creating the staged provider cache or invoking any provider node-DNS publication callback. It does not alter existing regular-file/symlink atomic replacement compatibility, does not remove user files, and avoids logging path or private node content.
- **Post-fix:** same negative test passes; `startup_staging_failure_prevents_node_registration_publication` and `refresh_staging_failure_prevents_node_registration_publication` 2/2. Core TUN+Ring library test matrix: **895 passed, 0 failed, 11 ignored**. Strict Clippy TUN+Ring all-targets and no-TUN+Ring lib-only passed; new regression passes in no-TUN+Ring. Cargo fmt/diff validated in this slice.
- **Legacy symlink compatibility:** added Unix `staged_cache_keeps_legacy_symlink_replacement_semantics` regression. Atomic cache replacement replaces the symlink *pathname* with a regular cache file without following it or mutating the pointed-to original file; the new destination preflight permits this historical behavior. Test passed in TUN+Ring.
- **Boundary:** preflight is not an atomic commit transaction. A concurrent process can replace the destination between the type check and final rename, and system-wide atomic rollback across provider visibility, node DNS ownership and cache persistence remains unproven. Independent L2 review and macOS physical NIC/utun leakage captures remain pending; no host DNS/routes/TUN/NE, privilege, push, PR or shared-history change was authorized/performed.


## 2026-11-07 15:09 PST — local validation matrix and unresolved system acceptance (L2 review pending)

- **Scope since this cycle's starting `1c487b0884ff92242f8e7a5293db9cf96b6d736c`:** provider initial cache acceptance, pre-staged and fsynced refresh persistence, malformed destination fail-closed, rejection cleanup, Unix symlink compatibility, live provider node-DNS answer cache isolation, and no-pool DNS lock avoidance. These are implementation and offline runtime tests, *not* proof that macOS service-scoped DNS cannot leave on a physical NIC. Fixed Mihomo submodule `63bd52ec794b7051569b76ede2f6cdbf4c091fda` remained untouched.
- **Latest clean offline matrices:** `clash-lib` TUN+Ring lib **896 passed / 0 failed / 11 ignored** after the added symlink test; TUN+Ring+WireGuard full lib **919 passed / 0 failed / 11 ignored** including symlink and destination checks; TUN+Ring+AnyTLS full lib **936 passed / 0 failed / 11 ignored**. `chimera-dns --all-features` **7 passed / 0 failed**. DNS config **40/40** each in TUN+Ring, TUN+Ring+WireGuard and TUN+Ring+AnyTLS, S01 **17/17**, S02 **14/14** in TUN+Ring; no-TUN+Ring S01 **17/17**, S02 **14/14**, and two managed node resolver tests **2/2**. Strict `-D warnings` Clippy TUN+Ring, TUN+Ring+WireGuard, TUN+Ring+AnyTLS all targets; no-TUN+Ring lib-only; Cargo fmt and diff checks passed.
- **Known failures and toolchain prerequisites (not suppressed):** `dns_legacy_golden_tests` **12 passed / 1 failed** due to existing S00 `respect-rules: true` fixture lacking `proxy-server-nameserver`, rejected by the pre-existing privacy guard. No-TUN+Ring full core **856 passed / 7 failed / 9 ignored**, seven inherited `config/internal/convert/mod.rs` fixtures enable TUN despite the `tun` feature being off. `cargo check -p clash-lib --all-features` blocked by absent `clash-dashboard/dist` assets; did not run npm/install, touch UI assets, or claim compiler parity for all features. These failures are separate from the successfully verified provider/DNS P0 regressions and must be handled explicitly through repository governance.
- **Next concrete P0 slice:** model a destination *rename* failure after a staged provider revision and successful DNS registration, and verify compensation/rollback for both visible provider revision and provider-owned DNS domains (including overlapping providers). Do not claim full atomicity from the current destination preflight, since a concurrent path replacement can still cause the final rename to fail. Then arrange an independent L2 review; system DNS Proxy activation, macOS resolver ownership and physical NIC/utun packet capture remain blocked on separately approved signed-host testing.

### 2026-11-07 DNS 系统 hosts 选项近似拼写失效关闭（L2 待审）

- 本地隔离分支基线 `50135450f5a95f33916c0b9a875e996fb6dbf595`；只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，`config/config.go::RawDNS.UseSystemHosts` 使用 `yaml:"use-system-hosts"`，Chimera 尚未实现此字段。
- 先新增 `use_system_hosts`、`use-system-host` 否定用例，证实前者会被静默忽略（测试失败）；再扩展未知敏感 DNS 字段的前缀诊断。保持无关 vendor 字段可用，不打印输入值。
- 验证：目标单测 1/1、`dns_config_tests` 40/40、`cargo fmt --all -- --check`、`cargo clippy -p clash-lib --lib --no-default-features -- -D warnings`、`git diff --check` 通过。严格 `--all-features --all-targets` Clippy 因未构建 Dashboard dist 阻塞；`--no-default-features --all-targets` 因既有 `connection_chain_tests` 未使用导入和 dead_code 失败，不能称为全矩阵通过。
- 只处理字段拒绝，不宣称 Mihomo 系统 hosts 语义已实现；没有执行 macOS 网络变更、抓包、互操作或独立 L2 审查。

## 2026-11-07 DNS 隐私字段下划线误拼防静默忽略

- 固定只读 Mihomo 基线：`ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，本机主 checkout 的 `ref-mihomo/config/config.go` 声明 `proxy-server-nameserver-policy`、`direct-nameserver-follow-policy`（连字符）；隔离工作树的 submodule 未初始化，未修改参考树。
- 新增否定用例：`dns.proxy_server_nameserver_policy`、`dns.direct_nameserver_follow_policy` 不应被当作不相关 vendor 字段忽略。修复前定向单测失败，确认前者静默通过；修复后对 `proxy_server`、`direct_name`、`default_name` 下划线前缀执行相同未知隐私字段诊断，错误只包含字段名、不包含配置值。保留非隐私 vendor 扩展兼容。**这不是新增对下划线配置名的支持**。
- 不涉及 macOS 网络状态操作。物理 NIC/TUN 抓包及 Mihomo 运行互操作仍未验证；L2 独立审查仍待完成。

## 2026-11-08 P0: use-hosts typo guard (L2 pending)

- Read-only pinned Mihomo gitlink: 63bd52ec794b7051569b76ede2f6cdbf4c091fda; config/config.go RawDNS has use-hosts and use-system-hosts.
- Added a negative case for dns.use-hosts-enabled: before the fix, 0 passed / 1 failed because the key was silently ignored. Added use-host/use_host privacy prefixes. After the fix: target 1/1, config::def::tests 20/20 and dns_config_tests 40/40 with tun,ring. Vendor extensions remain accepted and diagnostics exclude values.
- Cargo fmt check, strict lib Clippy (tun,ring) and git diff --check passed. No-feature DNS integration suite had 30 passed / 8 failed because tests require TUN or crypto provider; the appropriate tun,ring suite passed 40/40.
- No system network modifications, real NIC/utun capture, runtime Mihomo interoperability or independent L2 review.

### 2026-11-08 P0: DNS IPv6/listener/enable typo fail-closed（L2 待审）

- 开始时隔离工作树 HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`，已有 `clash-lib/src/config/def.rs` 和本文档未提交改动，均保留；本次仅在对应代码/文档追加增量。`master=e42dabe74282c77245da1023de0b828830928216`；本地 `origin/master` 以当次 `git rev-parse` 为准。固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；只读核对 `config/config.go::RawDNS` 的 `ipv6` / `listen` 等字段（参考源码位于主 checkout，隔离 worktree 子模块未初始化）。
- 修复前否定测试证明 `dns.ipv6-enabled` 会被忽略，导致用户以为启用了 DNS IPv6 控制；同一测试还覆盖 `dns.listen-udp` 和 `dns.enable-dns`。现在对这些敏感前缀的未知字段 fail-closed，错误仅含字段名、不含 DNS 配置值；已有合法字段和无关 `vendor-extension` 仍保留。此为 Chimera 的保守诊断策略，**不等于 Mihomo 运行时功能已对齐**。
- 未修改主机 DNS、路由、TUN、Network Extension、远端或固定参考源码。真实 NIC/utun 抓包、独立 L2 审查和维护者批准仍待完成。

### 2026-11-08 P0: Fake-IP underscore aliases must not silently disable privacy controls (L2 pending)

- Baseline: isolated branch `codex/macos-tun-fakeip-dns-privacy` at `50135450f5a95f33916c0b9a875e996fb6dbf595`; pinned read-only Mihomo submodule `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, `config/config.go::RawDNS.FakeIPFilterMode` declares the hyphenated `fake-ip-filter-mode` key.
- Test-first: `dns.fake_ip_filter_mode` and `dns.fake_ip_range` were added as negative cases. Before the fix, `fake_ip_filter_mode` was silently accepted (0/1). Added the `fake_ip` sensitive prefix to reject these near-misses, without accepting underscore aliases or logging DNS values; unrelated vendor keys remain accepted.
- Post-fix: focused test 1/1, `dns_config_tests` 40/40, Cargo fmt check, strict `clash-lib` TUN+Ring lib Clippy and `git diff --check` passed. This is a config-layer fail-closed guard only, not runtime Mihomo parity or proof of physical NIC DNS isolation. No system network changes or remote Git actions; independent L2 review pending.

## 2026-11-08 P0: multi-question proxy-node DNS isolation (L2 pending review)

- Baseline: isolated `codex/macos-tun-fakeip-dns-privacy` HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`; fixed read-only Mihomo `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` (source checked from the primary checkout, not changed). Mihomo `config/config.go::parseDNS` creates a dedicated proxy-server nameserver pool; this is a Chimera-specific fail-closed protection against ambiguous DNS multi-question packets, **not** an asserted Mihomo wire-level parity result.
- Before fix, a DNS packet with ordinary QNAME first and a known proxy-node QNAME second was routed to the public main upstream because selection examined only the first question. New `multi_question_with_later_proxy_node_must_not_reach_public_dns` regression failed before implementation (0/1), then passed (1/1). The resolver now rejects mixed-question packets containing a static or live-provider node domain before cache lookup or any DNS upstream selection, without logging the node name. Ordinary single-question requests remain unchanged.
- Test scope: offline mocked upstreams only. No system DNS, route, utun, Network Extension, privilege or physical NIC changes. Real macOS packet capture, provider concurrent-refresh race verification, cross-platform CI, Mihomo binary comparison and independent L2 review remain outstanding. Revert the isolated `enhanced.rs` change to roll back this slice.

## 2026-11-08 P0: provider registration race in multi-question DNS (L2 pending)

- Baseline: isolated worktree HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`; fixed read-only Mihomo `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Mihomo `config/config.go::parseDNS` separates proxy node DNS; this conservative Chimera multi-question rejection is not claimed as wire-level Mihomo parity.
- Red test `multi_question_with_node_pool_must_fail_closed_before_provider_registration`: two initially ordinary QNAMEs, with a dedicated node pool available but no registered provider node yet, were sent to public DNS (0/1). A provider may register the second QNAME after a preflight lookup, so checking only the current registry cannot close the race.
- Fix: reject all multi-question DNS packets when a dedicated proxy node DNS pool exists, before cache lookup and upstream selection. Standard single-question requests and deployments without a dedicated node pool remain unchanged. This deliberately reduces support for uncommon multi-question requests in privacy-sensitive configurations; independent L2 compatibility review required.
- Not system-level leakage proof: physical NIC/utun captures, provider concurrent mutation stress, macOS service-scoped DNS ownership, Mihomo binary comparison and L2 review remain outstanding. No host network or remote Git operations performed.
- Verification: red focused test 0/1; after fix `multi_question_` focused set 4/4; `clash-lib` TUN+Ring full library 898 passed / 0 failed / 11 ignored; `dns_config_tests` 40/40; strict `clash-lib` TUN+Ring lib Clippy (`-D warnings`), Cargo fmt check and `git diff --check` passed. No commit made; existing dirty files retained.

## 2026-11-08 P0: 专用节点 DNS 传输引导多 Question 策略隔离（L2 待审）

- 工作树 `Chimera_Client-715e28ad`，开发前 HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，从主 checkout 只读核对 `config/config.go::parseNameServerPolicy` 与 `ProxyServerNameserverPolicy`。Mihomo 的多 Question 线上行为未做二进制互操作，本次是 Chimera 保守的 fail-closed 防护，不声明完全等价。
- 发现 `proxy_node_resolver=true` 的 DNS 传输引导解析器没有 `proxy_resolver` 池，因此此前多 Question 检查不会触发；它根据首个 QNAME 选定策略，第二个 QNAME 可能绕过专用 `proxy-server-nameserver-policy`。先新增 `dedicated_bootstrap_policy_rejects_multi_question_before_upstream`，修复前 0/1 并确认普通节点 DNS 上游被错误调用；随后将该检查扩展到专用传输引导解析器，修复后 1/1，相关多 Question 测试 5/5。
- 仅在有专用节点 DNS 池或 `proxy_node_resolver` 时拒绝多 Question；普通单 Question 及未配置专用节点 DNS 的旧路径不变。尚未进行真实 macOS NIC/utun 抓包、L2 独立审查或 Mihomo 二进制运行时互操作；不声称系统级零泄漏。

### 2026-11-08 17:55 PST — non-address node bootstrap policy

- Fixed ref-mihomo submodule baseline: `63bd52ec794b7051569b76ede2f6cdbf4c091fda` (read-only). This slice tightens Chimera's dedicated bootstrap context; it does not claim full Mihomo runtime equivalence.
- Regression: `non_address_bootstrap_question_respects_dedicated_node_policy` proves a TXT query for a node-specific hostname previously reached the bootstrap default rather than `proxy-server-nameserver-policy` (red 0/1), then reaches the policy resolver only (green 1/1).
- Implementation: `exchange_no_cache_with_policy` now routes non-A/AAAA questions in `proxy_node_resolver` through its dedicated node policy/default pool, not the generic `nameserver-policy` branch. No cross-pool fallback on policy errors. Existing A/AAAA bootstrap handling remains unchanged.
- Verification: `cargo fmt --all -- --check`, `cargo clippy -p clash-lib --lib --features tun,ring -- -D warnings`, `cargo test -p clash-lib --lib --features tun,ring` (1092 passed, 11 ignored), `git diff --check` all passed. System DNS/TUN/route, live packet capture and independent L2 review not performed.

### 2026-11-08 19:03 PST — P0 non-address bootstrap internal entry preflight (L2 pending)

- Baseline: isolated branch `codex/macos-tun-fakeip-dns-privacy` HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`; read-only Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Mihomo's `config/config.go::parseDNS` has a dedicated proxy-server nameserver policy. This guard is a Chimera-specific conservative restriction, not a claim of wire-level Mihomo parity.
- A direct call to `exchange_no_cache_with_policy` with TXT followed by SRV previously selected the first-name bootstrap default without rejecting multiple questions (red test 0/1). The public `exchange` path already rejected the same packet; the internal entry point lacked equivalent protection. Add `reject_mixed_proxy_node_questions` at the internal entry before cache/upstream policy selection; green focused test 1/1. Existing ordinary single-question behavior is unchanged.
- No system DNS, routes, TUN, Network Extension, privilege changes, Git push or PR updates. macOS NIC/utun capture, binary Mihomo comparison and independent L2 review remain outstanding.
- Verification (macOS, TUN+Ring): initial public `exchange` regression 1/1 green but internal direct-entry negative test red 0/1; after guard direct-entry test 1/1 green, full `clash-lib --lib` 901 passed / 0 failed / 11 ignored, `dns_config_tests` 40/40, strict lib Clippy, Cargo fmt check and `git diff --check` passed. This proves internal entry-point policy selection isolation only, not live network nonleakage.

### 2026-11-08 19:55 PST — P0 provider endpoint TXT/SRV DNS pool isolation (L2 pending)

- Isolated worktree `Chimera_Client-715e28ad`, initial HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`; pinned Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` checked read-only from primary checkout. Mihomo has a distinct proxy-server nameserver/policy; this is Chimera's conservative extension for non-address node DNS, not verified Mihomo binary parity.
- Regression `provider_node_txt_query_must_not_use_public_dns_or_shared_cache` was red (0/1): registered provider TXT request went to generic DNS. Now provider node classification and cache bypass cover all QTYPEs, and non-A/AAAA registered provider node queries use dedicated proxy node DNS and its policy. They cannot fall back to generic main/fallback if the dedicated upstream fails. Dedicated answers are not inserted into generic shared caches; after provider removal ordinary DNS is used again.
- Legacy compatibility: static proxy endpoint TXT/SRV queries retain their existing generic nameserver behavior (covered by `test_proxy_server_nameserver_only_handles_ip_queries`); this remains a privacy/semantics gap for independent L2 review.
- Remaining risks: dynamic provider registration after a generic cache hit is guarded only by the registry snapshot at lookup; live registration/lookup concurrency and pre-existing generic cache semantics require separate review. System DNS/route/TUN/Network Extension untouched; no physical NIC/utun capture, Mihomo binary interoperability or independent L2 approval. Verification results recorded in run report.

### 2026-11-08 20:58 PST — P0 internal DNS empty-question fail-closed and provider TXT policy failure regression (L2 pending)

- Isolated branch `codex/macos-tun-fakeip-dns-privacy` HEAD `50135450f5a95f33916c0b9a875e996fb6dbf595`; existing dirty changes preserved. Fixed read-only Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` (`config/config.go` proxy-server policy). The new malformed-message handling is a Chimera robustness guard, **not** verified Mihomo wire-level parity.
- New negative regression `internal_dns_entry_rejects_empty_question_without_panicking`: direct `exchange_no_cache_with_policy` previously panicked on an empty Question list (red 0/1). Replace `first().unwrap()` with `ok_or_else(|| anyhow!("invalid query"))?` before upstream/cache selection; green 1/1. Public `exchange` already rejected empty questions.
- New `provider_node_txt_policy_failure_never_falls_back_to_public_dns` regression: a registered dynamic provider TXT query with a failing dedicated policy upstream returns an error; neither public DNS nor default node DNS is called (green 1/1 with existing routing). This tests failure isolation but does not establish provider-registration linearizability or physical NIC leak freedom.
- Verification: TUN+Ring core library 1096 passed / 0 failed / 11 ignored; `dns_config_tests` 40/40; strict TUN+Ring lib Clippy, Cargo fmt and diff check passed. No host network, privileged packet capture, Git push/PR/merge or shared history operations. Independent L2 review and macOS service-scoped resolver capture remain pending.

### 2026-11-08 Provider 注册发生于普通 DNS 查询在途期间（P0，L2 待审）

- 只读参考：固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，其 `dns/resolver.go::ReCreateServer` 将 `ProxyResolver` 与主 Resolver 分离；本地参考路径 `/Users/adam/src/Chimera_Client/ref-mihomo` 未修改。此测试验证 Chimera 的额外动态 Provider 生命周期防护，不声称 Mihomo 对同一竞态有完全相同的处理。
- 问题：普通 A 查询已经进入公共上游、尚未返回时，Provider 可将该域名注册为节点；旧实现会把已不再授权的公共 DNS 响应返回给调用方并可能写入共享缓存。
- 新增确定性 `PausedClient`/`Notify` 测试 `provider_registered_during_public_query_must_not_receive_public_answer`，先让普通查询阻塞，注册 Provider 后释放。修复前 0/1，返回公共 `192.0.2.10`；修复后使用专用节点解析器重试，返回 `192.0.2.11`，且专用节点上游被调用一次。
- 在 `exchange_no_cache_with_policy` 收到上游响应后、共享缓存写入前重新检查 Provider 所有权；若该域名新近成为节点，则丢弃旧公共响应，通过相同内部入口以节点快照执行一次专用解析（包括非 A/AAAA）。不会无限递归：重试时显式设置节点快照，且禁用共享缓存填充。
- 边界：注册发生前已发出的公共 DNS 包无法撤销；该切片确保注册后不返回该在途公共答案，也不缓存它。Provider 注销与重新注册的 ABA 生命周期、静态节点非地址记录、macOS NIC/utun 实机出口、独立 L2 审查仍未完成。未修改系统网络、Git 远端或参考子模块。

### 2026-11-08 23:03 PST — P0 Provider 注销期间专用 DNS 在途响应失效（L2 待审）

- 只读参考基线：固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本地 Provider 生命周期隔离属于 Chimera 特有实现，不声称 Mihomo 存在相同机制。
- 新增确定性 `provider_removed_during_node_query_must_not_return_stale_node_answer`：TXT 专用节点 DNS 请求暂停后注销 Provider，再释放响应。修复前 0/1，错误返回已经失去 Provider 所有权的专用响应；修复后 1/1，返回显式错误且不回退普通 DNS。
- 实现：`EnhancedResolver::exchange` 对起始时为 Provider 节点的查询，在返回结果前复核当前所有权；若已注销则 fail closed。内部快照接口和旧版静态节点行为不变。
- 限制：尚未覆盖同域名注销后重新注册的 ABA 代际变化、最终复核后至调用方使用结果之间的竞态，以及系统级物理 NIC/utun 抓包。需要独立 L2 审查与维护者批准；未触碰系统网络。

### 2026-11-09 00:04 PST — P0 Provider DNS remove/re-add ABA generation guard (L2 pending)

- Fixed Mihomo reference gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; read-only source available in the primary checkout `~/src/Chimera_Client/ref-mihomo`. The registry generation guard is a Chimera-specific lifecycle safety measure, not a claim of exact Mihomo ABA behavior.
- Deterministic negative test `provider_removed_and_reregistered_during_node_query_rejects_old_generation` pauses an in-flight TXT node DNS response, removes and re-registers the same provider hostname, then releases the old response. Before the fix 0/1 passed (stale answer accepted); after the fix 1/1 passed (explicit failure).
- `EnhancedResolver` now maintains a monotonic provider registry epoch, incremented only when a provider's effective domain set changes, while holding its registry write lock. `exchange()` snapshots the epoch before provider classification and rejects a node response if the epoch changed during the lookup, including remove/re-add ABA. This conservative global epoch may invalidate unrelated in-flight provider lookups when another provider changes; the safe response is an error, not public DNS fallback. Existing static node behavior remains unchanged.
- Remaining limitations: a public DNS request sent before a provider is registered cannot be unsent; a provider update immediately after the final check can still race with return; generation counter is global rather than per-host; independent L2 review, actual macOS NIC/utun capture and Mihomo binary interoperability remain pending. No system DNS/TUN/route or reference submodule changes were authorized or made.

### 2026-11-09 01:08 PST — P0 shared DNS cache hit reclassification (L2 pending)

- Pinned read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; main checkout `ref-mihomo/dns/resolver.go` separates `ProxyResolver` from the ordinary resolver. This is a Chimera-specific conservative lifecycle safeguard, not verified Mihomo binary parity.
- A provider can register its endpoint between the initial registry lookup and a positive/negative public cache return. Previously both cache-hit branches returned directly, without rechecking ownership; a newly protected hostname could receive a stale public DNS answer. Added `revalidate_public_cache_hit` and applied it to both branches; when ownership has changed, discard the public answer and resolve through dedicated node DNS without populating the shared cache. Dedicated failure propagates, never falls back to ordinary DNS.
- Added deterministic unit regression `cached_public_answer_must_be_reclassified_after_provider_registration`, modeling a public cache candidate selected before registration. It verifies the dedicated response replaces the public candidate. This does **not** prove atomicity of the final ownership check with the caller's use of the answer; provider changes after that check remain a race. An actual concurrent cache-read interleaving and negative-cache path need further instrumentation.
- Verification: targeted 1/1, `clash-lib --lib --features tun,ring` 1100 passed / 0 failed / 11 ignored, `dns_config_tests` 40/40, strict `clash-lib` lib Clippy, Cargo fmt check and diff check passed. No physical NIC/utun capture, network-state changes, remote Git operations, independent L2 review or maintainer approval.

### 2026-11-09：Provider 注册后负向缓存候选答案隔离回归（L2 待审）

- 固定只读 Mihomo 基线：`63bd52ec794b7051569b76ede2f6cdbf4c091fda`；对照 `config/config.go::parseNameServerPolicy` 中专用节点策略的配置入口。本次没有进行 Mihomo 二进制互操作，不宣称负缓存行为逐字节等价。
- 新增 `cached_negative_answer_must_be_reclassified_after_provider_registration`：模拟公共 DNS 的 NXDOMAIN 缓存候选在 Provider 注册后才准备返回，确认重新分类转到独立节点 DNS，而不是返回公共 NXDOMAIN。现有 `revalidate_public_cache_hit` 已满足该测试，因此不增加无必要的生产代码。
- 限制：该用例为确定性候选答案重分类测试，并非完整并发交错调度；Provider epoch 最终校验与返回之间的竞态、系统 DNS ownership、物理 NIC/utun 抓包、独立 L2 审查仍未完成。未修改宿主网络或参考子模块。

## 2026-11-09 缓存重分类后的 Provider ABA 防护（L2 待审）

- 固定只读参考 gitlink：`ref-mihomo=63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本轮参考子模块目录未检出，无法进行新的源码或二进制对照，因此不声称该切片已通过 Mihomo 互操作。
- `EnhancedResolver::revalidate_public_cache_hit` 在命中公共缓存、识别新注册 Provider 后，会通过专用节点 DNS 重新查询。此前此路径缺少 Provider 代际复核：若专用查询期间注销并重新注册相同域名，旧代际结果会被接受。
- 新增 `cache_reclassification_rejects_provider_aba_during_node_lookup`：暂停专用 DNS 响应，在暂停期间注销并重新注册同域名，修复前失败，修复后拒绝旧结果且不回退公共 DNS。生产代码在重新查询前后比较 `provider_dns_epoch` 并复核域名所有权。
- 剩余限制：全局 epoch 可能因无关 Provider 更新而保守失败；最后一次校验与响应返回之间仍有不可原子化窗口。该测试是隔离内存模拟，并非 macOS NIC/utun 抓包或系统 DNS ownership 验收。

### 2026-11-09 03:19 PST — Provider 等价刷新在途 DNS 兼容性回归（P0，L2 待审）

- 固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本轮未能在隔离工作树检出参考目录，故不声称二进制运行语义等价。
- 新增确定性 `identical_provider_refresh_does_not_invalidate_inflight_node_dns`：暂停 TXT 专用节点 DNS，使用大小写和末尾点不同但规范化后相同的 Provider 域名集合刷新，随后释放响应；验证等价刷新不应误增全局代际或使在途请求失败。当前实现通过该回归测试（1/1），因此无需改变生产代码。
- 该用例仅证明等价刷新行为，不解决无关 Provider 更新触发全局 epoch 过度拒绝，也不能消除最终所有权校验与响应返回之间的竞态。macOS NIC/utun 抓包、系统 DNS ownership、独立 L2 审查仍未完成；未更改系统网络或远端 Git。

### 2026-11-09 03:33 PST — P0 无关 Provider 更新不应误拒绝节点 DNS（L2 待审）

- 固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本轮为 Chimera Provider 生命周期特有的保守安全策略，不宣称与 Mihomo 二进制逐项等价。
- 新增确定性否定测试 `unrelated_provider_refresh_must_not_invalidate_inflight_node_dns`：暂停 Provider A 的 TXT 专用节点 DNS，更新不相关 Provider B，随后释放响应。修复前全局 epoch 使 A 错误失败（0/1），修复后通过（1/1）。
- 实现：保留全局单调 epoch 作为版本号分配器，新增 `provider_domain_generations`；仅为实际变化的 Provider 域名更新对应代际。专用节点查询与公共缓存重新分类路径在查询前后比较目标域名代际，避免无关 Provider 更新导致过度拒绝；注销/重新注册同域名仍改变版本。
- 验证：`cargo test -p clash-lib --lib --features tun,ring` 1104 通过、0 失败、11 忽略；`dns_config_tests` 40/40；严格 Clippy（lib，tun,ring）、Cargo fmt 和 Git diff 检查通过。尚未验证跨 Provider 同名所有权重叠、最终校验至返回的竞态或 macOS NIC/utun 抓包。独立 L2 审查待完成；未修改系统网络或远端 Git。

### 2026-11-09 04:00 PST — P0 共享 Provider 节点域名的在途 DNS 所有权（L2 待独立审查）

- 只读 Mihomo 基线仍为 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，核对 `config/config.go` 的 `ProxyServerNameserver` / `ProxyServerNameserverPolicy` 声明和解析；动态 Provider 所有权版本是 Chimera 特有的并发防护，不声称 Mihomo 存在等价版本结构。
- 新增否定测试 `removing_one_of_two_owners_does_not_invalidate_inflight_node_dns`：两个 Provider 共享 `proxy.example.com`，暂停专用 TXT DNS 请求，注销其中一个 Provider，再释放响应。修复前 0/1（错误地拒绝仍被拥有的域名），修复后 1/1。
- `enhanced.rs::replace_proxy_provider_dns_domains` 对域名代际只在全体 Provider 的域名所有权并集发生 `0 ↔ >=1` 变化时更新。单个 Provider 删除但另一个仍拥有同一域名，不应拒绝已在途的专用 DNS 响应。完整注销、注销后重新注册仍使代际改变并拒绝过时响应。保留先前对无关 Provider 更新的隔离。
- 实际验证：`cargo test -p clash-lib --lib --features tun,ring` 1105 通过、0 失败、11 ignored；`cargo test -p clash-lib --test dns_config_tests --features tun,ring` 40/40；严格 `cargo clippy -p clash-lib --lib --features tun,ring -- -D warnings`、`cargo fmt --all --check`、`git diff --check` 通过。
- 仍待：`provider_domain_generations` 的长期空间回收、Provider 大规模变更时的集合扫描性能、最终校验与返回之间的并发窗口、静态节点非地址查询、macOS NIC/utun 抓包。未改变本机系统网络；未推送、未合并；本轮 L2 尚无独立 Reviewer/维护者审批。

### 2026-11-09 06:05 PST — P0 静态代理节点非地址 DNS 查询隔离（L2 待审）

- 固定 Mihomo 只读参考为 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；参考 `config/config.go` 的 `ProxyServerNameserver` / `ProxyServerNameserverPolicy` 以及 `dns/server.go::ReCreateServer`。Chimera 原实现只为静态节点的 A/AAAA 查询选择专用 bootstrap 上游，TXT/SRV 等非地址查询仍会进入普通 `nameserver`；此行为不满足严格节点域名隔离目标。
- 先将既有 `test_proxy_server_nameserver_only_handles_ip_queries` 改成否定测试 `static_proxy_server_non_address_query_uses_dedicated_node_dns`，修复前 0/1（TXT 被公共上游处理），修复后 1/1；增加 `static_proxy_txt_bootstrap_failure_must_not_use_public_dns`，对 TXT/SRV 注入专用 DNS 故障，证明 `main` 和 `fallback` 均未被调用。
- `clash-lib/src/app/dns/resolver/enhanced.rs::exchange_no_cache_with_policy` 在静态节点域名命中时也选择专用节点 DNS 或 `proxy-server-nameserver-policy`，不再把非 A/AAAA 查询交给普通 DNS；只在配置了专用节点解析器时生效，其他域名及未启用此功能的旧配置不变。原有 A/AAAA 路径保持不变。此项是有意收紧先前静态节点 TXT/SRV 的出口语义，可能影响依赖普通 DNS 的旧部署；需 L2 独立审查。
- macOS、Rust 1.99.0，`--features tun,ring` 核心单测 **1126 passed / 0 failed / 11 ignored**；`dns_config_tests` **43/43**；`clippy -p clash-lib --all-targets --features tun,ring -- -D warnings`、`cargo fmt --check`、`git diff --check` 均通过。未进行真实 macOS 物理 NIC/utun 抓包、Mihomo 二进制互操作、Rust 1.99.1 工具链和独立 L2 Review。
- 保留此前工作树 `enhanced.rs`、`config/def.rs`、本矩阵中的未提交修改，不擅自把混合工作提交或推送；未改系统 DNS/TUN/路由、参考子模块、远端 Git。下一最小切片：为静态节点非地址请求增加 `proxy-server-nameserver-policy` 特定上游失败时绝不回退的测试，并核查静态节点命中共享缓存时是否可能返回过时公共答案。

### 2026-11-09 07:16 PST — P0 静态节点公共 DNS 缓存隔离与非地址专用策略故障（L2 待审）

- 固定只读参考 `ref-mihomo` 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；检查 `dns/resolver.go::ExchangeWithoutCache` 的 DNS policy 路径。本切片针对 Chimera 静态节点的独立 bootstrap 上游与共享缓存交叉，不能把它描述为 Mihomo 的逐行等价实现。
- 新增否定测试 `static_proxy_node_must_not_return_preexisting_public_cache_answer`：静态节点 QNAME 已有公共缓存候选时，必须重新通过专用节点 DNS 查询；修复前返回 `192.0.2.10`（0/1），修复后返回 `192.0.2.11`（1/1）。`exchange` 直接跳过静态节点共享正/负缓存，`revalidate_public_cache_hit` 对晚到的静态节点缓存候选也改走专用 DNS；`ip_exchange_with_provider_snapshot_and_source` 把静态节点 DNS 响应标记为专用，禁止写入未分区的共享缓存。
- 新增 `static_proxy_txt_specific_policy_failure_must_not_fallback`：静态节点 TXT/SRV 命中 `proxy-server-nameserver-policy` 特定上游后故障，不能回退默认节点、公共 main 或 fallback（2 个记录类型均通过）。原 `proxy_server_nameserver_precedes_nameserver_policy_without_leaking` 的缓存命中断言从 1 次更新为 2 次专用查询：这是明确的安全性收紧和性能权衡，避免缓存来源混淆，需 L2 审查及后续设计专用缓存分区。
- 验证：macOS Rust 1.99.0 `cargo test -p clash-lib --lib --features tun,ring --locked` **1128 passed / 0 failed / 11 ignored**；`dns_config_tests` **43/43**；`cargo clippy -p clash-lib --all-targets --features tun,ring --locked -- -D warnings`、`cargo fmt --all --check`、`git diff --check` 均通过。未验证实际系统 NIC/utun 抓包、真实 Mihomo 二进制互操作或 Rust 1.99.1；没有修改宿主 DNS、路由、TUN 或远端 Git。原工作树仍有多个早于本轮的未提交更改，本轮不混合提交。

## 2026-11-09 Provider 注册 ABA 与公共 DNS 在途请求（P0，L2 待审）

- 基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`（本工作树参考子模块未检出，因此本轮未能独立核对 Go 源码，不宣称已验证 Mihomo 的 ABA 行为）。
- 新增确定性否定测试 `provider_registration_aba_during_public_query_rejects_stale_answer`：公共 DNS 请求暂停后，同名 Provider 节点注册又移除，再恢复公共上游；修复前 0/1 通过，公共答案错误地返回。
- 修复：普通 DNS 在途查询记录节点域名所有权代际，若发生 ABA，拒绝旧答案，且不把旧结果写入共享缓存；保持原有 Provider 专用查询代际检查。该严格失效关闭属于 Chimera 隐私保护强化，不能等同 Mihomo 已实现相同策略。
- 未验收：macOS 物理 NIC/utun 抓包、系统 resolver 优先级、Mihomo 二进制互操作与独立 L2 审查；未经授权不改变本机网络状态。

### 2026-11-09 09:03 PST — P0 公共缓存候选 Provider ABA 失效关闭（L2 待审）

- 固定只读 Mihomo gitlink：`63bd52ec794b7051569b76ede2f6cdbf4c091fda`。本隔离工作树参考子模块未检出，因此本轮仅核对 gitlink 与既有参考记录；这是 Chimera 特有的保守并发保护，不宣称 Mihomo 二进制等价。
- 新增否定测试 `public_cache_candidate_rejects_provider_registration_aba`：模拟普通 DNS 缓存命中候选已选出、Provider 同域名注册再移除，随后交付旧公共缓存结果。修复前目标检查接口不存在，编译失败；修复后 1/1 通过。该测试不是实线程调度覆盖，不能将编译失败表述为运行时红测。
- `EnhancedResolver::exchange` 在选取缓存候选之前捕获 Provider 域名代际，并传入 `revalidate_public_cache_hit_with_generation`。即使交付时 Provider 已移除，只要代际发生变化便拒绝旧候选，防止缓存命中路径 ABA 漏检。原测试使用仅测试期的 `revalidate_public_cache_hit` 包装器，保持已有定向测试语义。
- macOS Rust 1.99.0 `--features tun,ring --locked`：核心 1130 passed / 0 failed / 11 ignored；`dns_config_tests` 43/43；严格 Clippy `--all-targets -D warnings`、Cargo fmt、Git diff check 通过。未修改本机 DNS/TUN/路由，未推送或提交，未做真实 NIC/utun 抓包或独立 L2 审查。
- 剩余风险：缓存选择前后的代际采样仍非原子事务；最后一次校验与上层使用结果之间仍有窗口。下一切片应在真实缓存读路径设置可控屏障，验证 Provider 注册/注销发生于候选选取与校验之间时的正负缓存行为，并评估同名静态节点和 Provider 的所有权重叠。

### 2026-11-09 10:04 PST — P0 RFC 2308 负缓存 Provider ABA 回归（L2 待审）

- 固定只读 Mihomo 参考 SHA 63bd52ec794b7051569b76ede2f6cdbf4c091fda；只读核对主工作树 ref-mihomo/dns/resolver.go 的 Resolver 与 dnsCache 定义。Provider 代际是 Chimera 特有防护，不声称 Mihomo 二进制同等实现。
- 新增 negative_cache_candidate_rejects_provider_registration_aba：真实写入/读取 RFC 2308 NXDOMAIN 负缓存候选，在候选选取后注册/移除同名 Provider，验证旧负缓存答案必须拒绝。首次运行 1/1 通过；这是新覆盖而非修复前失败测试。
- 仍待：真实 exchange 负缓存路径的可控并发屏障、最后校验到交付之间的原子性、macOS NIC/utun 抓包及独立 L2。未修改系统网络或远端 Git。

## 2026-11-09 — respect-rules 引导隔离黄金测试纠偏（本地 L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，`config/config.go::parseDNS` 明确拒绝 `respect-rules: true` 而 `proxy-server-nameserver` 为空的配置。此项为已存在安全校验的测试契约纠偏，不是新实现 DNS 引导路径。
- 先新增 S00 否定测试，断言即使 `nameserver` 使用 `#proxy=PROXY`，缺失专用节点引导 DNS 仍须拒绝；初次运行 1 passed / 1 failed，失败的是旧黄金测试把不安全配置误判为有效。随后只为正例加入 `proxy-server-nameserver: [9.9.9.9]`，保留 `#proxy` 和 `respect-rules` 行为断言；复测 14 passed / 0 failed。
- `cargo fmt --all -- --check`、`cargo clippy -p clash-lib --no-default-features --features tun,ring --all-targets -- -D warnings`、`git diff --check` 通过。没有运行特权 TUN、系统 DNS 或物理 NIC 抓包；既有工作树的其他改动均保留。后续应在专用 DNS 失败、超时和热重载时对节点 A/AAAA 解析进行故障注入，确认不退回普通 nameserver/policy/fallback，并交由独立 L2 审查。

### 2026-11-09 14:00 PST — P0 节点引导 DNS 真正挂起时的取消隔离回归（L2 待审）

- 只读核对主工作树 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseDNS`，确认 `respect-rules` 必须配置专用 `proxy-server-nameserver`；此测试是 Chimera 的超时取消防泄漏约束，不宣称 Mihomo 逐行相同。
- 新增 `proxy_bootstrap_timeout_cancellation_never_uses_public_dns`：专用代理节点 DNS Client 永久 pending，A/AAAA 请求经 Tokio 100ms 超时取消，确认两个请求都进入专用 Client，公共 main/fallback 均未调用。与既有立即返回错误的故障注入不同，覆盖实际异步挂起和取消路径。新测试首次执行即通过（1/1），是补充覆盖而非已复现的生产缺陷；未改运行时生产逻辑。
- macOS `--features tun,ring --locked`：核心 1146 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 Clippy all-targets、Cargo fmt、Git diff check 通过。未执行真实系统 DNS/TUN/NIC 抓包、热重载并发或独立 L2 审查；未修改系统网络、远端 Git 或固定参考。原工作树已有未提交修改，未混合提交。
- 下一切片：在 bootstrap DNS 查询挂起时并发热更新节点域名所有权与 DNS 上游，使用可控屏障验证旧响应不能写入共享缓存或进入公共 fallback。

### 2026-11-09 16:02 PST — P0 Provider DNS 挂起期间所有权 ABA 与取消（L2 待审）

- 固定只读 Mihomo 基线 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，核对 `config/config.go::parseDNS` 中 `ProxyServerNameserver` 和 `ProxyServerNameserverPolicy` 的约束；Provider 所有权代际和取消安全属于 Chimera 本地强化，不宣称 Mihomo 具有同样的内部机制。
- 新增 `cancelled_provider_bootstrap_during_ownership_reload_never_uses_public_dns`：Provider 的 TXT 引导查询在专用上游永久挂起，待确认已进入上游后注销并重新注册同一域名，取消在途任务；检查没有调用公共 main/fallback，且没有把节点响应写入共享正缓存。
- 本用例只证明任务取消和 Provider ABA 的组合路径；没有真正替换 DNS client pool、没有热重载整个 Resolver，也没有验证物理 NIC/utun 或 macOS 系统 DNS ownership。需要独立 L2 审查和实机验收。

## 2026-11-09 17:04–17:07 PST P0 public DNS handoff ABA regression

- Isolated branch `codex/macos-tun-fakeip-dns-privacy`, baseline `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`; fixed read-only Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. No system DNS, TUN or route changes.
- Added task-local deterministic handoff barrier to `EnhancedResolver::exchange`, after its initial provider generation snapshot but before `exchange_no_cache_with_policy` takes another snapshot. New `public_handoff_provider_aba_rejects_obsolete_public_answer` test registers and removes the same provider hostname during that interval, asserting failure closed, no public/node upstream call, and no shared positive cache insertion. Before the fix, 0/1 failed with a public DNS answer; after the fix, 1/1 passed.
- Added a second provider generation check before no-cache dispatch. This closes the **tested** handoff interval but is not an atomic registry transaction: a further update between this check and the inner snapshot remains theoretically possible. Follow-up must propagate the entry generation through the inner public lookup and validate before cache insertion rather than relying on two independently sampled generations.
- Rust 1.99.1 macOS `tun,ring`: 1148 library tests passed, 11 ignored; 46 DNS config tests passed; strict all-target Clippy, fmt check and diff check passed. This does not establish macOS NIC/utun zero-leak behavior. L2 independent review outstanding.

### 2026-11-09 19:00 PST — P0 Provider ABA 与共享缓存提交窗口（L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；只读核对固定 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go` 专用节点 DNS 字段。Provider generation 是 Chimera 特有的安全机制，不宣称 Mihomo 采用相同并发实现。
- 新增确定性测试 `provider_aba_between_final_check_and_cache_write_rejects_public_answer`：公共 A 响应通过旧的最终 generation 检查后，在共享缓存写入前暂停，注册再注销同名 Provider；修复前 0/1（错误返回公共答案），修复后 1/1。另增 `provider_aba_before_negative_cache_write_rejects_nxdomain`，覆盖 RFC 2308 NXDOMAIN 的共享负缓存路径，修复后 1/1。
- `enhanced.rs::exchange_no_cache_with_policy_and_generation` 在缓存提交前再次验证 Provider 域名 generation，并持有 `provider_domain_generations` 的读锁跨越正、负缓存同步写入；Provider 更新需要同一锁的写锁，因而不能在验证和插入之间提交新 generation。锁内不执行 `.await`。原有已进入公共网络的 DNS 查询无法撤销，修复防止晚到结果被接受和污染缓存。
- 限制：最后释放锁到上层使用答案之间仍可能发生 Provider 更新；此项不证明系统级 DNS 零泄漏、macOS resolver 接管或 Mihomo 二进制互操作。独立 L2 Reviewer、维护者批准与物理 NIC/utun 抓包待完成；未改系统网络或远端 Git。

### 2026-11-09 19:59 PST — P0 公共 DNS 缓存提交后返回前的 Provider ABA（L2 待审）

- 固定只读 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本隔离工作树的 `ref-mihomo` 未检出，不能据此声称 Mihomo 二进制具有同一 Provider ABA 语义。本切片是 Chimera 自身的 fail-closed 竞态保护。
- 先增加确定性屏障测试 `provider_aba_after_public_cache_commit_must_reject_returned_answer`，在内部 DNS 查询和缓存提交完成后、外层 `exchange` 返回前注册并注销同名 Provider；修复前 0/1（过时公共答案错误返回），修复后 1/1。
- 外层 `exchange` 在内部查询返回后复核原始 Provider generation。若发生变化且域名已无 Provider owner，拒绝返回旧公共结果；若当前有 owner，则不信任可能来自公共上游的未标记结果，使用专用节点 DNS 重新查询并再次验证 generation。已有“公共查询期间新注册 Provider”测试由一次专用查询变为两次，这是安全性优先的可观测性能成本，需 L2 评审后优化来源标记，避免冗余节点 DNS 请求。
- 此检查仍不能保证最终复核与调用方实际使用答案之间的原子性；Provider 改变后旧公共 DNS 查询已发生的网络出口不可撤销。macOS 系统 DNS ownership、NIC/utun 抓包、独立 L2 审查与真实 Mihomo 互操作尚未验收。未修改系统网络或远端 Git。

### 2026-11-09 21:04 PST — P0 Provider ABA 公共缓存污染否定断言（L2 待审）

- 在已有 `provider_registration_aba_during_public_query_rejects_stale_answer` 中启用真实 `ResponseCache`，并断言 Provider 注册/注销发生于公共上游查询期间时，过期公共 A 响应既不得返回，也不得写入共享正缓存。该断言首次执行即通过，属于增强回归覆盖，**不是新发现或修复的生产缺陷**。
- 固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本隔离工作树未检出 `ref-mihomo/config`，故本轮未能重新进行 Go 源码对照。Provider generation/ABA 是 Chimera 的本地防泄漏保护，不宣称与 Mihomo 内部实现相同。
- 验证：`cargo test -p clash-lib --features tun,ring --lib provider_registration_aba_during_public_query_rejects_stale_answer` 1/1；`cargo test -p clash-lib --features tun,ring --test dns_config_tests` 46/46；`cargo clippy -p clash-lib --all-targets --features tun,ring -- -D warnings` 通过；`cargo fmt --all`、`git diff --check` 通过。
- 未实现来源标记，尚不能消除 Provider 重新分类时重复的专用 DNS 查询。未修改系统 DNS、路由、TUN 或远端 Git；L2 独立审查、CI 和物理 NIC/utun 抓包待完成。

### 2026-11-09 21:57 PST — P0 Provider ABA 非地址查询共享缓存隔离回归（L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`。固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 未检出，故本轮没有重新完成 Go 源码对照；本测试针对 Chimera 自身 Provider generation 隔离机制。
- 扩展 `provider_registration_aba_during_public_query_rejects_stale_answer`：分别对 A、TXT 运行独立的暂停公共查询、同域名 Provider 注册再注销、恢复查询场景，验证旧公共响应被拒绝且对应 QTYPE 未写入共享正缓存。首次扩展测试即通过，属于覆盖增强，**不是新发现的生产缺陷**；没有改动生产运行时。
- 验证：`cargo test -p clash-lib --features tun,ring --lib provider_registration_aba_during_public_query_rejects_stale_answer --locked` 1/1（内部覆盖 A/TXT 两种场景）；`cargo test -p clash-lib --features tun,ring --test dns_config_tests --locked` 46/46；严格 `cargo clippy -p clash-lib --all-targets --features tun,ring --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。未执行完整核心库测试或真实 NIC/utun 抓包。
- 后续：在内部查询结果引入明确的 Public/DedicatedNode 来源标记，避免注册期间重复专用查询；先以并发屏障验证单次专用 DNS 请求、NXDOMAIN 和重新注册路径，再做 L2 独立审查。没有修改宿主 DNS/TUN/路由或远端 Git。

### 2026-11-09 23:00 PST — P0 节点 DNS 重分类响应来源与重复查询（L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，基线 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo 参考 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，从主检出 `ref-mihomo/config/config.go::parseDNS` 只读核对节点专用 DNS 字段。本次优化是 Chimera Provider ABA 防护的内部实现，不宣称 Mihomo 具有相同的 generation/并发设计。
- 先将 `provider_registered_during_public_query_must_not_receive_public_answer` 的专用上游调用次数预期由 2 改为 1，修复前实际失败（2 != 1）。随后通过内部 `exchange_no_cache_with_policy_and_generation` 的可选来源输出标记，把内部已转向 dedicated node DNS 的结果传回外层；外层在 Provider generation、当前 owner 和 network generation 复核通过后直接使用该结果，避免重复发起节点 DNS 引导查询。未标记结果仍保持 fail-closed 的专用重查询。
- 验证：定向测试修复后 1/1；`cargo test -p clash-lib --features tun,ring --lib` 1184 通过、0 失败、11 忽略；`cargo test -p clash-lib --features tun,ring --test dns_config_tests -- --test-threads=1` 46/46；严格 `cargo clippy -p clash-lib --features tun,ring --all-targets -- -D warnings`、`cargo fmt --all -- --check` 通过。Clippy 首次发现 `needless_option_as_deref`，修正后通过。
- 限制：来源标记仅在当前内部调用链传播，并非所有 DNS Client 的持久来源类型；未验证物理 NIC/utun 抓包、macOS 系统 resolver ownership 或跨平台 CI。L2 独立审查待完成。下一步针对重分类后的 NXDOMAIN/TXT 与 Provider 再注册补充来源及负缓存断言。

### 2026-11-10 — P0 Provider 重分类 TXT/NXDOMAIN 单次专用 DNS 回归（L2 待审）

- 固定 Mihomo 只读基线 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，核对 `config/config.go::parseDNS` 的 `respect-rules` / `proxy-server-nameserver` 约束。Provider generation 与来源标记是 Chimera 本地安全实现，不宣称 Mihomo 内部相同。
- 新增 `provider_reclassification_txt_and_nxdomain_use_dedicated_once`：公共 TXT 或 NXDOMAIN 响应在途时注册同名 Provider，断言返回专用 DNS 的对应结果，且专用 DNS 仅调用一次。测试首次成功编译运行后 1/1 通过，属于新增覆盖，**未复现新的生产缺陷**；没有修改运行时生产代码。
- 仍待覆盖 Provider 再注册/注销 ABA 与 DNS 网络代际切换、真实物理 NIC/utun 抓包、macOS 系统 DNS ownership、L2 独立 Reviewer 和维护者批准。未改变系统 DNS/TUN/路由或远端 Git。
- 本轮 macOS Rust 1.99.1 `tun,ring`：定向测试 1/1；核心库 1185 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；`cargo clippy -p clash-lib --features tun,ring --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 均通过。新增测试最初使用了不适用于当前 Hickory Message 的方法而编译失败，改为 `metadata.response_code` / `answers` 字段后通过。

### 2026-11-10 02:00 PST — P0 Provider ABA 回归恢复验证（L2 待审）

- 复用隔离分支 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，保留原有八个修改文件。固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本轮参考子模块未检出，未重新声称源码级一致性。
- 为恢复前轮磁盘不足导致中断的验证，仅删除本隔离工作树可再生的 `target/debug/incremental`（清理前 4.8 GiB），APFS 可用空间由 1.1 GiB 增至约 4.6 GiB。没有清理其它 worktree、用户源文件或共享历史。
- 使用 `CARGO_INCREMENTAL=0`、`--locked -j 2` 验证此前未完成的 `cache_reclassification_rejects_provider_aba_during_node_lookup`：1 passed；覆盖 A 正响应和 TXT/NXDOMAIN 负响应在 Provider ABA 期间拒绝过期结果。完整 `clash-lib --lib --features tun,ring` 1185 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 all-target Clippy、Cargo fmt check 和 Git diff check 通过。
- 本轮是验证与构建环境恢复切片，未新增生产运行时修改；不能将通过的模拟 DNS 并发测试当作 macOS 物理 NIC/utun 零泄漏证明。L2 独立审查、PR/CI 和真实网络验收仍待完成。下一切片：在 Provider 再注册后并发网络代际切换，断言来源标记失效时拒绝旧专用 DNS 结果和负缓存写入。

### 2026-11-10 04:00 PST — Provider ABA + network reset 负缓存隔离断言（L2 待审）

- 隔离分支 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，从主检出的只读 `config/config.go::parseDNS` 确认 `respect-rules` 必须提供 `proxy-server-nameserver`。Provider ABA 是 Chimera 自身机制，不声称 Mihomo 内部相同。
- 增强 `provider_aba_and_network_reset_during_dedicated_negative_lookup_fail_closed`：开启真实共享 `ResponseCache`，在专用 TXT/NXDOMAIN 响应挂起时模拟 Provider 注销/再注册和 `reset_transports()`，除了拒绝过期返回值，还明确断言旧 NXDOMAIN 不得进入共享负缓存。新断言首次定向执行 1/1 通过，未复现新的运行时缺陷，本轮未改生产代码。
- 此测试未模拟完整 DNS 配置热重载，也不证明 macOS 物理 NIC/utun 零泄漏；仍需独立 L2 审查、维护者批准与真实网络验收。下一步用两个可控上游和屏障证明重置后的新网络查询不会复用旧负响应，并检查网络代际重置期间新查询的进入窗口。

### 2026-11-10 05:03 PST — P0 网络重置后新查询不得复用旧 NXDOMAIN（L2 待审）

- 在既有 `provider_aba_and_network_reset_during_dedicated_negative_lookup_fail_closed` 中加入第二阶段：旧专用 TXT/NXDOMAIN 在 Provider 注销/再注册和 `reset_transports()` 后被拒绝；随后注销旧 Provider owner，并由可计数的新公共上游回答同域名 TXT。断言新查询返回 `NoError` 且确实访问新上游一次，不得命中旧网络 NXDOMAIN 负缓存。新增断言首次运行通过，是回归覆盖增强，**不是新复现的生产缺陷**；未修改生产逻辑。
- 固定 Mihomo 参考 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：只读核对主检出 `ref-mihomo/config/config.go` 中 `respect-rules` / `proxy-server-nameserver` / `proxy-server-nameserver-policy` 的解析约束。Provider ABA / network generation 属于 Chimera 本地安全设计，不能据此宣称 Mihomo 内部采用同一算法。
- macOS `tun,ring --locked -j 2`：定向测试 1/1；核心库 1186 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 all-target Clippy `-D warnings` 通过。最初编译发现测试闭包移动了 `query`，修正测试变量使用后通过。仍未执行实机物理 NIC/utun 抓包、DNS ownership 验收、独立 L2 审查或远端 CI。
- 本切片使用已配置的两个独立 DNS client，模拟网络重置后查询，不代表动态替换 client pool；下一步在 `reset_transports()` 的代际更新窗口使用同步屏障并发启动新查询，验证旧响应不会在重置完成后写入缓存。

### 2026-11-10 06:00 PST — P0 普通公共 TXT/NXDOMAIN 查询跨网络重置（L2 待审）

- 隔离分支 `codex/macos-tun-fakeip-dns-privacy`，基线 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；只读核对主检出 `ref-mihomo/config/config.go` 的 `respect-rules` 配置约束。网络代际是 Chimera 本地隔离机制，不宣称 Mihomo 使用相同算法。
- 先增加 `network_reset_rejects_inflight_public_txt_nxdomain_and_cache_write`：普通公共 TXT 请求等待旧上游 NXDOMAIN，期间 `reset_transports()`，恢复后要求拒绝旧响应且不得污染共享缓存。修复前 **0/1，断言失败：旧 NXDOMAIN 被返回**；修复后 **1/1**。
- 修复 `enhanced.rs`：外层 `exchange()` 的返回前网络代际校验扩展至普通公共 DNS；内部 `exchange_no_cache_with_policy_and_generation()` 在缓存提交前、返回前均检查网络代际，不再只针对历史 Provider 域名。没有修改系统 DNS/TUN/路由。
- 验证：macOS `tun,ring --locked -j 2` 定向测试 1/1；核心库 1187 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 all-target Clippy `-D warnings`、Cargo fmt 检查通过。
- **剩余竞态风险**：网络代际复核与通用缓存写入不是同一锁保护的原子操作；重置与缓存提交精确交错时仍可能产生旧缓存项。此次只证明暂停上游时的重置路径，不能声称已经完成严格网络切换隔离。下一切片应在通用缓存提交窗口加屏障，并以与 reset 协调的锁/代际标记完成原子化。物理 NIC/utun 抓包、独立 L2 Reviewer 与维护者批准未完成。

### 2026-11-10 07:00 PST — P0 公共缓存提交与网络重置互斥（L2 待审）

- 基线：隔离分支 `codex/macos-tun-fakeip-dns-privacy` HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。从主检出固定 Git 对象只读检查 `config/config.go` 的 `RespectRules` / `ProxyServerNameserver` 字段；网络代际及互斥是 Chimera 本地防护机制，不宣称 Mihomo 内部使用同样实现。
- `enhanced.rs`：普通公共正/负缓存写入在 `provider_epoch_cache` 互斥锁保护下检查网络代际，`reset_transports()` 同锁递增代际并清除负缓存和 Provider epoch 缓存。统一锁顺序为 epoch cache → negative cache，避免原先检查与缓存提交间的竞态窗口。
- 新增 `network_reset_serializes_with_public_cache_commit_guard`：通过跨线程屏障验证重置在提交锁被持有时不得推进代际，释放后重置必须清除旧 NXDOMAIN。原有 `network_reset_rejects_inflight_public_txt_nxdomain_and_cache_write` 继续覆盖旧公共响应拒绝。
- 这是 L2 生产变更，仍待独立审查；此测试验证锁与重置顺序，不等于已穷尽所有缓存/重置时序，也不等于 macOS 物理 NIC/utun 零泄漏。公共正缓存跨网络切换的读取策略及系统 DNS ownership 仍需专门核查。

### 2026-11-10 — 网络重置后公共正缓存隔离待验证（P0 / L2）

- 新增 `network_reset_must_not_reuse_public_positive_cache`：预置旧网络 A 正缓存（192.0.2.10），重置后由新上游返回 192.0.2.20，断言不能返回旧缓存。
- 源码检查发现 `reset_transports()` 清理负缓存和 Provider epoch 缓存，但没有清理 Hickory `ResponseCache`；其 `clear()` 是 `pub(crate)`，不可由 Chimera 直接调用。该回归测试预期暴露旧正缓存复用，**尚未运行，不能声称失败或修复**。
- 本轮磁盘剩余不足 1 GiB，`cargo` 未在默认 PATH 中，使用 `~/.cargo/bin/cargo` 可找到工具；因磁盘不足暂不启动大型编译。下一步应在安全释放独立工作树构建产物空间后先运行否定测试，再采用可审查的缓存代际隔离方案；不得将无验证的生产改动视为完成。

### 2026-11-10 09:00 PST — P0 公共正缓存跨网络隔离（L2 待审）

- 固定 `ref-mihomo` gitlink 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；该子模块当前未检出源码，不能声称本轮完成 Go 实现逐行对照。网络代际是 Chimera 自身的安全约束。
- 修正 `network_reset_must_not_reuse_public_positive_cache` 的测试输入：此前 `recursion_desired=false` 导致请求不符合 `cache_safe_request`，测试虽绿但没有实际覆盖缓存命中。设置 RD 后，修复前明确复现旧 `192.0.2.10` 复用（1 失败）；修复后返回新上游 `192.0.2.20`（1 通过），并新增重置前确实命中旧缓存的断言。
- `enhanced.rs`：由于 Hickory `ResponseCache` 无可调用的公共清空 API，网络代际非零时禁止读取及写入未分区的公共正缓存，避免网络重置后旧缓存污染。该保守策略在同一个 resolver 多次重置后牺牲普通正缓存性能，直至 resolver 重建；后续应评估引入可替换的代际化缓存，不得误称性能语义与 Mihomo 完全一致。负缓存和 Provider epoch 缓存仍按现有代际策略处理。
- 清理本隔离工作树 `target/debug/deps` 中超过两天的可再生成构建文件，恢复约 2 GiB 空间，未触及 Git 文件或其他工作树。验证：核心库 1189 通过/0 失败/11 忽略；DNS 配置集成 46/46；严格 Clippy (`tun,ring`, all-targets)、fmt 和 diff check 通过。系统 DNS、路由、TUN 未更改；物理 NIC/utun 抓包及 L2 独立审查未完成。

### 2026-11-10 10:00 PST — 网络重置后公共正缓存重新启用（P0 / L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，基线 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，从主工作树只读确认其对象存在。网络代际缓存是 Chimera 本地安全机制，不宣称 Mihomo 内部算法相同。
- 先写 `network_reset_new_positive_answer_is_cached_within_new_epoch`：两次同域名请求必须只调用新网络上游一次。原逻辑 **0/1 失败**（实际两次上游请求），证明上轮的禁用缓存策略损失性能。
- 新增 `network_positive_cache`：网络代际非零时使用独立的 Hickory 正缓存，按代际惰性替换；代际为零时继续使用旧缓存，保持旧版配置行为。读取候选后仍通过原有网络/Provider 重验证，写入仍在 `provider_epoch_cache` 提交锁内校验代际；不能跨网络复用旧答案。没有改变系统 DNS、路由、TUN 或 Network Extension。
- 修复后定向 1/1；核心库 1190 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 `clippy -p clash-lib --all-targets --features tun,ring --locked -j 2 -- -D warnings`、Cargo fmt、diff check 通过。
- 尚需独立 L2 审查和 macOS 物理 NIC/utun 实机抓包。当前新代际正缓存固定容量 4096，后续需核对缓存容量配置及多次重置、并发读写下的额外回归；不得视为 Mihomo 缓存性能语义完全一致。

### 2026-11-10 11:00 PST — 网络重置立即释放旧代际正缓存（P0 / L2 待审）

- 固定参考 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；此项为 Chimera 自身网络代际隔离机制，不宣称 Mihomo 采用相同缓存算法。参考源码仅只读。
- 先写 `network_reset_eagerly_drops_prior_epoch_positive_cache`：第一次重置后缓存一个正答案，第二次重置必须立即释放旧代际 `ResponseCache`，即使没有后续查询。修复前 **0/1 失败**：旧缓存一直保留；修复后 **1/1 通过**。
- `reset_transports()` 在 `provider_epoch_cache` 提交锁保护下递增网络代际并将 `network_positive_cache` 置空，保持提交锁 → 正缓存锁的顺序；原有惰性重建继续保留。避免长期空闲时保留旧网络的 DNS 答案（内存/隐私生命周期），不改变 DNS 出站策略。
- macOS `tun,ring --locked -j 2`：核心库 1191 passed / 0 failed / 11 ignored；DNS 配置集成 46/46；严格 Clippy `-D warnings`、Cargo fmt 通过。尚未进行独立 L2 审查、远端 CI 或 NIC/utun 实机抓包。
- 下一步：并发屏障测试 reset 与新代际缓存命中/写入交错，检查 reset 期间进入的新查询是否被错误拒绝或读取旧候选。

### 2026-11-10 12:04 PST — P0 新网络正缓存候选与 reset 交错（L2 待审）

- 原隔离分支 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 未检出，本轮不能声称已完成 Go 源码级对照。网络代际缓存为 Chimera 自身安全机制。
- 先新增 `network_reset_rejects_selected_new_epoch_positive_cache_candidate`：通过 task-local 双屏障确保查询已选中新代际正缓存答案，然后执行第二次 `reset_transports()`，再恢复查询。修复前 0/1 失败，确认缓存候选在 reset 后仍返回旧 IP。
- `enhanced.rs` 的新代际正缓存命中路径现于 Provider 重验证返回后复核 network generation，不再直接返回重置前选中的答案；测试暂停点仅在 `cfg(test)` 生效。修复后 1/1 通过。没有修改系统网络、Git 共享历史或 `ref-mihomo`。
- macOS `tun,ring --locked -j 2`：核心库 1192 passed / 0 failed / 11 ignored；`dns_config_tests` 46/46；严格 all-target Clippy `-D warnings`、Cargo fmt check、Git diff check 通过。该测试验证了精确缓存候选交错，但不能穷尽最终代际检查之后的同步竞态，亦不证明 macOS 物理 NIC/utun 零泄漏。L2 独立审查、PR/CI、系统 DNS ownership 验收仍待完成。
- 下一步：检查最终网络代际检查与向调用方交付结果之间的线性化边界；审查新代际缓存容量 4096 与配置容量的对应关系，补充多次 reset 并发压力测试。

### 2026-11-10 12:55 PST — P0 公共 DNS 最终交付边界回归（L2 待审）

- 复用隔离工作树与既有未提交更改；固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，只读核对 `config/config.go` 中 `respect-rules` 与 `proxy-server-nameserver(-policy)` 的约束。网络代际为 Chimera 本地机制。
- 新增 `network_reset_during_public_return_handoff_rejects_positive_answer`：在公共正答案已完成内部解析、外层返回前通过 task-local 屏障暂停，执行 `reset_transports()`，再恢复查询；旧网络正答案必须拒绝。现有代码测试首次即通过，未复现新生产缺陷，未改生产逻辑。此测试不能证明最终原子交付或系统级零泄漏。
- macOS `tun,ring --locked -j 2`：定向 1/1；核心库及 DNS 配置集成回归通过；严格 all-target Clippy、Cargo fmt 与 diff check 通过。首次 Clippy 因磁盘空间不足失败，安全清理本隔离工作树可再生 `target/debug/incremental` 后重跑成功；不触碰其他 worktree 或系统网络。
- 后续：针对最终代际校验之后的不可避免同步边界明确线性化语义，审查容量 4096 与 Mihomo 缓存行为；完成独立 L2 审查、CI 与 NIC/utun 实机抓包。

### 2026-11-10 15:07 PST — P0 DNS transport reset 失败时的缓存隔离测试（待验证）

- 复用隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；只读确认固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。此处网络代际属于 Chimera 本地安全机制，不宣称与 Mihomo 内部算法相同。
- 新增 `failed_transport_reset_invalidates_positive_cache_before_returning_error`：使用故意返回 reset 错误的 DNS client，先填充旧正缓存，要求 `reset_transports()` 报错时仍递增网络代际并释放旧代际正缓存；避免重置失败时继续使用旧网络缓存。此测试尚未成功执行，不能将其标记为通过或认定已复现生产缺陷；本轮未修改生产运行时逻辑。
- 安全删除本工作树 `target/debug/deps` 中修改时间超过两天的可再生成文件，约释放 1.8 GiB；尝试 `cargo test -p clash-lib --lib --features tun,ring --locked -j 2 failed_transport_reset_invalidates_positive_cache_before_returning_error -- --nocapture`，`rustc` 因 `No space left on device` 退出 101。随后仅删除本工作树 `target/debug/incremental`，仍仅余约 405 MiB。`cargo fmt --all -- --check` 和 `git diff --check` 通过；Clippy、完整单测和 DNS 集成测试未执行。
- **下一步**：先在不影响其他工作树的前提下为该隔离工作树提供至少数 GiB 的独立构建空间，再执行新增否定测试；随后检查 reset 在旧 transport 尚未关闭时已递增网络代际的竞态，必要时通过明确的切换中状态和失败关闭测试修复。未经授权不改 macOS 系统网络。L2 独立审查、CI 和 NIC/utun 抓包仍待完成。

### 2026-11-10 15:57 PST — reset 失败缓存测试加强（待运行）

- 保留固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，子模块工作目录为空，本轮未做 Go 源码逐行对照。
- 加强 `failed_transport_reset_invalidates_positive_cache_before_returning_error`：两次相同 RD 查询必须只访问上游一次，确保重置失败测试真实覆盖旧正缓存命中，而不是假阳性。生产代码未变。
- 仅删除本隔离工作树 4 个超过两天的可再生成 Cargo deps 文件（约 1.1 GiB）；重新运行定向测试，`rustc` 再次因 `No space left on device` 失败。新增断言尚未通过编译与运行，不视为验证完成。
- 下一步：在不触碰其他工作树和用户数据的条件下提供至少 4 GiB 可用构建空间，运行该测试和完整回归；再针对 reset 进行中的新查询是否使用旧 transport 建立确定性否定测试。
- **同轮续验（16:00 PST）**：进一步仅删除当前隔离工作树 `target/debug/deps` 中超过一天且大于 20 MiB 的 131 个可再生成文件（约 6.1 GiB），恢复构建空间；强化后的 reset 失败定向测试 **1/1 通过**，`cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -- --test-threads=4` **1003 passed、0 failed、11 ignored**，`dns_config_tests` **46/46 通过**，严格 Clippy（all-targets、tun/ring、`-D warnings`）、Cargo fmt 与 diff check 通过。此前本段的“尚未通过”仅描述首次空间不足时的中间状态。未运行系统网络抓包、跨平台验证或远端 CI。

## 2026-11-10 — DNS transport 重置取消路径（L2 待审）

- 隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，基线 `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。只读核对主工作区该固定 Mihomo `dns/resolver.go::ResetConnection`：它逐一重置 main/fallback/default resolver；本轮的 Rust 异步取消与缓存代际保护属于 Chimera 扩展，不宣称与 Go 的取消机制等价。
- 新增 `cancelled_transport_reset_releases_query_gate_and_invalidates_cache`：预先证明旧正缓存确实命中（两次查询、一次上游）；将 `reset_transport` 停在永不完成的 future，断言重置期间查询失败关闭；取消重置任务后确认门禁计数归零、网络代际已经递增，下一次查询确实重新访问上游（累计两次），而非返回旧缓存。现有实现通过，未修改生产逻辑；未建立修复前失败的否定证据。
- 验证：新增定向测试 1/1；`cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 4` 1005 passed、11 ignored；`dns_config_tests` 46 passed；同 feature 的 all-targets 严格 Clippy、Cargo fmt 与 diff 检查通过。未执行真实 TUN/NIC 抓包、跨平台原生测试或 L2 独立审查。
- 待核对：取消发生在多个底层 transport 部分重置之后时，后续查询是否可能命中处于不一致状态的连接；当前测试仅验证门禁释放与缓存隔离，不证明 transport 可安全复用。应以故障注入验证部分重置失败时是否需要持续阻断出站直至成功重建。

## 2026-11-10 — 部分 DNS transport reset 失败时拒绝后续查询（P0 / L2 待审）

- 固定 `ref-mihomo` gitlink 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；本隔离工作树参考目录为空，本轮无法直接逐行核对 Go 实现。该切片属于 Chimera Rust transport 生命周期安全约束，不代表 Mihomo 使用相同的失败状态机。
- 新增 `partial_transport_reset_failure_must_block_old_upstream_until_recovery`：两个上游中一个 reset 成功、另一个失败，后续 DNS 查询必须失败关闭，不能使用部分重置的上游集合。原实现定向测试 0/1 失败（仍然允许查询）；新增 `transport_reset_failed` 状态，失败时锁定后续查询，成功完成全体 reset 后解除，修复后定向 1/1 通过。
- 本次未修改 macOS 系统 DNS、路由、TUN、Network Extension 或 `ref-mihomo`。尚需覆盖并发 reset 交错、取消后的半重置状态及恢复成功的状态转换；当前取消路径仍保留旧行为，不应宣称全部故障路径都已 fail-closed。L2 独立审查、CI 和物理 NIC/utun 抓包未完成。

## 2026-11-10 20:04 PST — 并发 DNS transport reset 排队与取消（P0 / L2 待审）

- 复用隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，本工作树子模块未检出。此切片验证 Chimera 的异步取消/串行化保证，不将 Rust 状态机等同于 Mihomo 内部实现。
- 新增 `queued_reset_after_cancel_keeps_dns_closed_until_recovery_finishes`：第一轮 reset 永不完成，第二轮排队等待；取消第一轮后，第二轮进入受控暂停；整个过程中公共 DNS 查询必须失败关闭、上游 exchange 次数为零；第二轮成功完成后才允许查询。首次运行 1/1 通过，无新生产缺陷，未修改生产逻辑。
- 尚未证明 DIRECT 子 resolver 与父 resolver 在所有失败/取消交错下状态一致；尚未进行 macOS 物理 NIC/utun 抓包、独立 L2 审查或远端 CI。后续优先为父子 resolver 部分重置失败与恢复添加确定性测试，并只读核对固定 Mihomo 的对应 Go 路径。

## 2026-11-10 20:28 PST — 网络重置后普通负缓存的有界代际隔离（P0/P3，L2 待审）

- **实时基线**：通过连接的 @appledev DevSpace 继续复用隔离工作树 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`、分支 `codex/macos-tun-fakeip-dns-privacy`，开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；8 个原有未提交文件全部保留。固定只读 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`：`dns/resolver.go` 的普通、代理节点、DIRECT 解析器持有各自缓存；Chimera 的 Provider/network generation 是本地失效关闭强化，不声称与 Go 内部算法逐项等价。
- **先失败再修复：普通负缓存缺失**。`network_reset_new_negative_txt_answer_is_cached_only_in_current_epoch` 修复前 **0/1**：网络重置后，两次相同合法 TXT/NXDOMAIN 查询都调用上游（2 次），不能在新代际内复用 SOA 安全负答案。现复用已有 1024 条有界 Provider-epoch 缓存：**仅网络代际非零、Provider 所有权代际为零、符合 `cache_safe_request`、具有有效 RFC 2308 SOA TTL 的 NXDOMAIN/NODATA** 进入普通负缓存；前一次网络缓存随 reset 清空。普通正向回答仍由独立的 `network_positive_cache` 处理，注册中的动态/静态代理节点仍走专用 DNS，未恢复未带代际标识的旧公共缓存。修复后定向 **1/1**。
- **边界测试**：`network_reset_new_nodata_srv_uses_safe_soa_negative_ttl` 覆盖 SRV 的 NOERROR/NODATA、SOA.MINIMUM、事务 ID；`network_reset_new_negative_cache_rejects_selected_old_network_answer` 在缓存候选已选取后进行 reset，要求拒绝旧 NXDOMAIN；`network_reset_negative_cache_candidate_rejects_provider_registration_aba` 在候选选取后执行同名 Provider 注册→注销，要求拒绝旧公共缓存，且专用节点和普通上游没有意外调用；`network_reset_new_negative_cache_rejects_wrong_soa_and_ad_responses` 禁止跨区 SOA 和带 AD 标记的负响应被缓存；`network_reset_new_negative_with_cache_disabled_stays_uncached` 保留旧版关闭缓存行为；`post_reset_negative_cache_does_not_merge_dnssec_or_edns_requests` 保留 CD 与 EDNS 请求隔离、无 Request-only 缓存混用。所有定向用例均通过。
- **先失败再修复：新旧正负响应相互覆盖**。`new_network_positive_answer_invalidates_older_negative_epoch_entry` 修复前 **0/1**：新的正向结果到达后，旧 NXDOMAIN 仍存在于有界缓存中；现于 `provider_epoch_cache` 提交锁内，在插入当前代际正向结果前移除 generation=0 的旧负条目。`new_network_negative_answer_supersedes_older_positive_cache_entry` 修复前 **0/1**：较新的 NXDOMAIN 被更早的 Hickory 正向结果遮盖；现查询顺序优先使用安全的当前代际负条目，新的正向提交会相应移除它。两项修复后 **2/2**；内存锁顺序保持 epoch cache → network positive cache，与 reset 一致，锁不跨 `.await`。
- **兼容与局限**：仅在内存中增加网络代际后负缓存命中，不改变 YAML 字段、旧版 DNS 解析开关、DNS 上游选择、DNS 配置校验或平台系统网络。1024 条缓存与历史 Provider 答案共享容量，可能影响命中率；这不是 Mihomo 性能等价认证。网络 reset 期间的真正操作系统 DNS ownership、物理 NIC/utun 抓包、独立 L2 审查、跨平台原生运行仍待完成。若要回滚本轮，可恢复“post-reset 普通负答案每次查询上游”的旧保守行为，保留原有 Provider/网络代际安全防护。
- **远端只读状态**：`master=0bd95adb038be2f406971e36943de0de2c5af025`；master workflow run `42874626443` completed/success；开放 PR #111、#85、#58。该 CI **不验证**本地未提交修改；未 fetch/rebase、签名提交、推送、更新 PR、合并或改写历史。
- **增强后的跨网络否定测试**：`network_reset_new_negative_txt_answer_is_cached_only_in_current_epoch` 的第二阶段将上游从第一网络的 `NXDomain` 换成第二网络的 `NoError/NODATA`，对比两个独立上游调用次数与响应码，防止“后台也查询了新上游，但向用户返回旧 NXDOMAIN”的测试假阳性。验证正常负答缓存符合 SOA.MINIMUM 到期及 DNS 事务 ID 回填；新网络两次请求也只需一次上游调用。
- **完整验证结果（Rust 1.99.1，macOS ARM64）**：`cargo +1.99.1 fmt --all -- --check`、`cargo +1.99.1 clippy -p clash-lib --features tun,ring --all-targets --locked -j 2 -- -D warnings` 均通过。目标组合核心库 **1209 通过、0 失败、11 忽略**，最小 `--no-default-features --features tun,ring` 核心库 **1017 通过、0 失败、11 忽略**，两种组合均通过严格 all-target Clippy。DNS 配置 **46/46**、S00 **14/14**、S01 **17/17**、S02 **14/14**（目标和最小组合分别复测）；`chimera-dns` 组件库 **7/7**，`clash-lib` API 集成 **12/12**（普通 loopback 服务测试，TUN 禁用）。对 reset 后缓存候选与 Provider ABA 的两项确定性并发测试，各重复 **20 次**全部通过；`git diff --check` 通过。构建缓存使用 `CARGO_INCREMENTAL=0`，没有实际运行需要公网 DNS 的两项 `#[ignore]` 测试，也未执行跨平台目标测试、网络权限操作或独立 L2 Review。DNS listener/API 日志中故意触发的端口冲突、安全配置拒绝均属预期测试路径。
- **交接**：隔离工作树既有 8 个已修改文件继续保留，HEAD 未提交/推送；远端成功的 CI 不覆盖本地修复。下一轮需评估共享 epoch LRU 中普通 NXDOMAIN 与历史 Provider 答案之间的容量竞争、DNS rule hot reload 期间的缓存策略变化，以及 Mac 物理 NIC+utun 实机捕获（必须另获授权）。

## 2026-11-10 — DIRECT 子解析器重置失败与父解析器恢复边界（L2 待审）

- 复用隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；保留原有 8 个未提交文件。固定只读参考 `ref-mihomo` 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，在主工作区检出目录核对 `dns/resolver.go::ResetConnection`。Go 参考逐一重置解析器；Rust 的失败关闭状态机属于 Chimera 的额外安全保证。
- 新增 `direct_child_reset_failure_keeps_parent_closed_until_child_recovers`：父上游重置成功而 DIRECT 子上游注入失败，要求父与子都拒绝 DNS 查询，且实际 exchange 计数为零；撤销故障并完整重置后，父与子各恢复一次查询。此测试首次运行即通过，未证明新的生产缺陷，因此没有修改生产运行时逻辑。
- 这只覆盖子重置返回错误的确定性路径，不覆盖 DIRECT 子解析器在部分重置时遭取消、热更新替换子解析器或平台系统 DNS ownership；不能宣称 macOS 零泄漏。仍需 L2 独立审查、远端 CI 和另行授权的物理 NIC/utun 抓包。
- **本轮验证**：Rust 1.99.1，macOS ARM64，`--no-default-features --features tun,ring --locked -j 2`：新增测试 **1/1**；核心库 **1018 passed / 0 failed / 11 ignored**；`dns_config_tests` **46/46**；严格 `clippy --all-targets -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。没有真实系统网络操作。测试首次即通过，不能作为先红后绿的生产缺陷复现证据。

## 2026-11-10 23:05 PST — DIRECT 独立恢复不得解除父解析器失败关闭（P0 / L2 待审）

- 原隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；保留已有未提交改动。固定 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`，只读核对主工作区 `dns/resolver.go::ResetConnection`；此 Rust 父子恢复所有权约束属于 Chimera 的扩展，不能直接宣称 Go 语义相同。
- 新增 `independent_direct_recovery_must_not_reopen_failed_parent`：父子先失效关闭，再仅独立 reset DIRECT 子解析器；父解析器仍必须拒绝查询，父上游 exchange 计数为零；完整父 reset 成功后才恢复。新增测试首次 1/1 通过，没有复现生产缺陷，未修改运行时逻辑。测试明确不保证持有 DIRECT 子解析器句柄的调用方在子独立 reset 成功后仍被父所有权门禁阻断：**这是尚未解决的跨解析器所有权风险**。
- 下一切片应建立父 reset 等待/取消与独立 DIRECT reset 交错的否定测试，要求子句柄不能在父未恢复时访问上游；如测试失败，设计父子共享恢复代际/所有权门禁，避免仅用子自身成功标志放行。L2 独立审查、CI、真实 macOS NIC/utun 抓包均未完成；本轮没有修改系统网络。

## 2026-11-10 23:11 PST — DIRECT 子解析器父级恢复门禁与所有权失效关闭（P0 / L2 待审）

- **实时工作区与对照**：继续复用 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`，分支 `codex/macos-tun-fakeip-dns-privacy`，开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，原有 **9 个未提交文件**全部保留，未 checkout、stash、rebase 或改写用户工作。固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 仅只读；`dns/resolver.go::ResetConnection` 分别遍历 main/fallback/default，`Resolvers.ResetConnection` 分别重置普通、代理节点、DIRECT。**Rust 的父级所有权门禁是 Chimera 防泄漏强化，未宣称 Mihomo 内部具有相同状态机。**
- **否定测试 A — DIRECT 独立恢复逃逸**：`independent_direct_recovery_cannot_escape_failed_parent_gate` 修复前 **0/1**：父级 `invalidate_transports()` 后，DIRECT 子 `reset_transports()` 成功就能绕开父级失败状态并访问上游。现父级的 `transport_reset_failed: Arc<AtomicBool>` 与 DIRECT 子的 `parent_transport_failed` 共享，正常 `EnhancedResolver::new_with_network_path_source` 构造时也显式接线；`exchange` 前、查询完成后均复核父级恢复状态。修复后 **1/1**。
- **否定测试 B — 多个父级重置排队**：`queued_parent_reset_window_must_keep_independent_direct_closed` 修复前 **0/1**：前一个重置清除失败标志但另一个重置仍在等待时，子句柄可访问上游。现共享 `transport_resets_in_progress: Arc<AtomicUsize>`，DIRECT 查询还必须确认父级待重置数为零。修复后 **1/1**。已有 `queued_reset_after_cancel_keeps_dns_closed_until_recovery_finishes` 增强了 DIRECT 子独立 reset/查询的失败关闭断言；取消、排队与成功完整恢复均通过。未改系统网络。
- **否定测试 C — 反向映射异步交付**：`parent_failure_during_direct_reverse_cache_write_rejects_stale_reply` 在 `ClashResolver::exchange` 的反向映射缓存写锁处挂起，在父级失效后再释放锁。修复前 **0/1**（旧回答通过）；现在 trait 层缓存写入后再次确认父级门禁，修复后 **1/1**。`direct_reverse_cache_must_not_expose_old_mapping_during_parent_failure` 修复前 **0/1**（旧 IP→域名映射仍可读），现在 `cached_for` 在异步获取缓存前、后都复核父级状态，修复后 **1/1**；完整 reset 原有逻辑会清空反向缓存。
- **否定测试 D — 孤儿 DIRECT 句柄**：`orphaned_direct_handle_must_not_query_after_owner_is_dropped` 修复前 **0/1**：外部克隆的 DIRECT 句柄在其父解析器析构后仍能查询（即使子独立 reset）。增加 `Drop for EnhancedResolver`，在释放父解析器时将其**共享的** `transport_reset_failed` 置为 true；子句柄不持有父对象强引用，因此不会形成引用环，也无法自行清除父状态。`owner_drop_during_direct_query_rejects_old_dns_response` 验证父级在子查询中途析构时旧响应被拒。首次尝试显式 `Weak<()>` 生命周期标记后严格 Clippy 报 unused field，已舍弃这套冗余标记、改用共享失败标志与 Drop；重新执行严格 Clippy 和定向回归通过。
- **正常失败与生产配置联通**：`parent_invalidation_during_inflight_direct_query_rejects_old_answer`、`direct_resolve_v4_cannot_bypass_parent_failure_via_independent_reset`、`failed_parent_reset_keeps_healthy_direct_child_closed` 覆盖进行中查询、实际 `resolve_v4` trait 句柄和父上游失败但子上游已成功重置的场景；`configured_direct_resolver_inherits_parent_owner_gate` 使用实际 `Config` 构造链，DIRECT 指向 `127.0.0.1:9`，只检查失败关闭错误，**不发出公网 DNS 查询**。相关测试全部通过。DIRECT 三类代表性并发回归各重复 **20 轮全部通过**。
- **局限与审查要求**：L2 运行时生产变更尚待独立 Reviewer/维护者按治理政策审查。子解析器独立 handle 的父级 Drop 保护已实测，但完成态仍无法建立跨线程“最终检查到调用者收到回复”完全原子的线性化；父级热更新/更换 DIRECT 后所有旧 handle 的实际归属、DNS health 视图与缓存治理需要继续审查。未更改配置语法、Mihomo 参考、macOS 系统 DNS/路由/TUN/Network Extension，未提权、推送、改远端 PR、合并或签发提交；NIC+utun 的零泄漏实机抓包、跨平台原生运行、Mihomo 二进制互操作依旧未验收。回滚本轮可恢复 `EnhancedResolver` 的独立状态字段并移除 DIRECT 父级共享门禁，但会重新暴露测试已证实的逃逸风险，不应未经审核回滚。
- **配置替换补充测试**：`replacing_dns_owner_retires_old_direct_without_closing_new_owner` 创建两个相互独立的 resolver 所有者，验证旧父销毁后旧 DIRECT 句柄不可再发起 DNS，但新所有者 DIRECT 仍返回新 IP、新父销毁后也能关闭对应句柄；首次运行即通过，没有新的生产缺陷。它不覆盖旧父对象**仍被其他 Arc 引用**时的外层配置热更新：这需要由重载管理器明确触发旧所有者失效，不能只依赖 Drop。
- **全套离线测试（Rust 1.99.1、macOS ARM64、`CARGO_INCREMENTAL=0`）**：`cargo fmt --all -- --check`、`git diff --check` 与严格 `cargo clippy -p clash-lib --all-targets --locked -j 2 -- -D warnings` 对目标 `tun,ring` 和最小 `--no-default-features --features tun,ring` 均通过；目标核心 **1223 passed/0 failed/11 ignored**，最小核心 **1031 passed/0 failed/11 ignored**。DNS 配置 **46/46**、S00 旧版金标准 **14/14**、S01 **17/17**、S02 **14/14**；API loopback 集成 **12/12**、`chimera-dns` 组件 **7/7**。DIRECT 恢复相关三个并发/取消测试各重复 20 轮全部通过。端口占用、非法 DoH 证书和未授权 API 监听的 `ERROR` 日志来自预期故障注入，通过结果没有忽略这些检查。没有运行需要公网 DNS 的 ignored 用例，也没有执行 macOS 真实 DNS ownership、物理 NIC/utun 抓包或远端 CI。
- **下一最小验证**：在外层 reload 管理器仍保留旧 resolver Arc 引用时，确认旧 DIRECT 句柄能否越过新的 DNS 策略；检查 `nameserver-policy` 热更新与缓存代际一致性。只有获得用户明确许可后才能做真实 macOS 物理 NIC/utun DNS 抓包与系统 DNS ownership 接管。

## 2026-11-11 00:04 PST — 保留旧 owner 引用时的 DIRECT 显式退休边界（P0 / L2 待审）

- 复用既有隔离工作树 `codex/macos-tun-fakeip-dns-privacy`，开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，保护 9 个既有未提交文件；未重置、rebase、提交或推送。只读核对主工作区固定 `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `dns/resolver.go::ResetConnection`：Mihomo 依次重置普通、代理和 DIRECT 解析器；Chimera 的显式 owner 失效门禁属于本地防泄漏增强，不代表 Go 使用同样状态机。
- 新增 `retained_old_dns_owner_requires_explicit_retirement_on_reload`：模拟热更新后仍保留旧父解析器 `Arc`，新旧 DIRECT 各有独立可计数上游。旧 owner **明确调用** `invalidate_transports()` 后，即使旧 DIRECT 自行 `reset_transports()` 成功，也不得重新向旧上游发送 DNS；新 owner DIRECT 应正常工作。此测试验证失效接口的必要调用契约，而**没有**证明实际 reload 管理器已在发布新解析器之前调用它。
- 尚未闭合的 P0 集成风险：外层热更新路径若仅替换 resolver 但保留旧 owner 引用，且未调用 `invalidate_transports()`，旧 DIRECT 仍可能查询旧上游；需追踪实际 reload coordinator，建立发布顺序与旧 owner 退休的集成测试，再决定是否需要生产代码变更。系统 DNS ownership、NIC/utun 抓包、L2 独立审查和远端 CI 均未完成。
- **本轮实测**：macOS ARM64 / Rust 1.99.1，最小 `--no-default-features --features tun,ring`：新增定向测试 **1/1**；核心库 **1032 passed / 0 failed / 11 ignored**；`dns_config_tests` **46/46**；严格 `clippy --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。监听端口冲突的 ERROR 日志是故障注入测试的预期输出。未执行物理网卡/utun 抓包、跨平台原生测试或独立 L2 审查。

## 2026-11-11 00:06-00:28 PST - P0 DNS dispatch fail-closed and proxy policy matching (L2 review pending)

- **Workspace/reference**: Reused @appledev isolated worktree `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`, branch `codex/macos-tun-fakeip-dns-privacy`, unchanged HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202` and all 9 preexisting modified files. Read-only Mihomo reference `63bd52ec794b7051569b76ede2f6cdbf4c091fda`; inspected `dns/resolver.go` reset/fallback and normal/proxy/DIRECT resolver creation. Rust asynchronous transport ownership checks are Chimera-specific safety features, not a claim of identical Go internals.
- **Red/green P0: old transport still saw a QNAME after fail-closed**: `parent_invalidation_before_direct_dispatch_does_not_send_qname_upstream`, `parent_invalidation_during_internal_handoff_must_not_send_qname`, and `own_invalidation_before_dispatch_must_not_send_qname_upstream` each failed 0/1 before the fix: query eventually errored, but an obsolete upstream was actually invoked. New `ensure_transport_dispatch_ready` and `batch_exchange_if_transport_usable` check own and parent failure/in-progress gates directly before the **15 upstream dispatch sites** across main, fallback, normal nameserver policy, proxy-node and per-node policy routing. Both entry and result delivery also recheck own transport state. All 3 tests now pass 1/1. `owner_invalidation_between_main_and_fallback_must_not_send_qname` confirms the fallback pool gets 0 queries if the transport is invalidated after the main upstream already started. `invalidated_dns_policy_and_node_dispatch_stay_isolated_until_recovery` checks ordinary policy, dynamic Provider and static node paths: zero post-invalidation dispatches, and each selected pool recovers once following successful full reset without silently downgrading to generic DNS. Four deterministic groups passed in 20 repetitions each using 16 test threads.
- **Red/green proxy node DNS policy case mismatch**: Existing trie keys were compiled in lowercase, but all four `proxy-server-nameserver-policy` match call sites used the original mixed-case QNAME. `mixed_case_proxy_server_nameserver_policy_selects_specific_dns_for_a_and_txt` failed 0/1 before the fix: specific pool saw 0 instead of 2 requests, with unintended node default fallback. Four call sites now normalize lookup QNAME to lowercase. Test passes 1/1 with specific hits=2, node default=0, public=0. `mixed_case_dedicated_outbound_resolver_preserves_node_policy_for_a_and_txt` also verifies the separate `proxy_node_resolver` bootstrap mode for A and TXT.
- **Red/green direct internal Config policy validation**: YAML parser already rejects invalid selectors, but direct `app::dns::Config` construction bypassed that check, and ignored `StringTrie::insert` failure. `direct_dns_constructor_rejects_unmatchable_proxy_node_policy_selectors` and `direct_dns_constructor_rejects_unmatchable_public_policy_selectors` each failed 0/1 before the fix and pass 1/1 afterward. Runtime constructor now uses existing selector validation, rejects unsupported GeoSite/RuleSet and comma-unexpanded selectors, checks trie insertion success and prevents policy entries with no usable upstream from silently falling through to main/default DNS. No YAML feature was added or previously supported selector removed.
- **Verification**: macOS ARM64, Rust +1.99.1, `CARGO_INCREMENTAL=0`, `cargo fmt --all -- --check`, strict `cargo clippy -p clash-lib --all-targets --locked -j 2 -- -D warnings` for both `--no-default-features --features tun,ring` and `--features tun,ring`, all passed. Minimal feature library: **1041 passed, 0 failed, 11 ignored**. Target feature library: **1233 passed, 0 failed, 11 ignored**. Each feature combo passed `dns_config_tests` **46/46**, `dns_legacy_golden_tests` **14/14**, `dns_policy_s01_tests` **17/17** and `dns_policy_s02_tests` **14/14**; `git diff --check` passed. Expected loopback DNS listener port-conflict fault-injection logs are not unexpected failures.
- **Remote read-only**: GitHub master `0bd95adb038be2f406971e36943de0de2c5af025`, run `42874626443` completed/success, open PRs #111/#85/#58. This remote CI **does not validate local dirty worktree**. No commits, pushes, PR edits, merges, shared history rewrites, system DNS/route/TUN/Network Extension changes or privilege escalation.
- **Residual limitations**: Checking a gate before dispatch does not make the check and first physical packet one atomic transaction; already in-flight packets cannot be recalled by rejecting responses. A separate L2 reviewer, parent/default/bootstrap DNS lifecycle review, true macOS NIC/utun capture and system DNS ownership verification (requires separate authorization), cross-platform tests and new-final-SHA CI are pending. Do not claim system-wide zero DNS leaks. Next: test default/bootstrap resolver lifetime and cache/policy reload interaction with failure/recovery.


## 2026-11-11 — DNS reload 成功发布前显式退休旧 resolver（P0 / L2 待审）

- **现场基线**：仅操作隔离工作树 `codex/macos-tun-fakeip-dns-privacy`（开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`）；之前 9 个未提交文件保留。固定 Mihomo gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；只读核对主工作区同 SHA 的 `dns/resolver.go::ResetConnection`，其分组重置 main/fallback/default 连接和普通/代理/DIRECT resolver，但**不是** Chimera 的 `Arc` 热更新旧所有权回收算法。
- **发现的发布缺口**：`clash-lib/src/runtime/lifecycle.rs` 成功重载时，`active_components.stop_all_and_join(false)` 只停止 DNS/TUN/入站 listener，接着启动新数据面并发布 `new_components`。旧主 DNS 与控制面 DNS 的 `Arc` 可仍被连接器/旧控制对象保留，未观察到显式 `invalidate_transports()`；此前 `retained_old_dns_owner_requires_explicit_retirement_on_reload` 仅证明调用者**自行**退休旧句柄有效，不证明 reload coordinator 会调用。
- **切片**：新增 `runtime/components.rs::retire_dns_owners`，同步使旧主 DNS 和旧控制面 DNS 失效；`runtime/lifecycle.rs` 在新数据面 `wait_initial_ready()` **成功之后、发布新组件之前**调用。任何准备、API 就绪、数据面就绪失败的回滚分支均不会执行此动作，保留原 owner 供 rollback 复用。新增 mock 契约测试确保两个旧 resolver 均失效且新 resolver 不受触碰。
- **边界**：测试直接覆盖退休 helper，但不构成真实运行时热更新端到端测试；仍需在无系统网络副作用的集成环境覆盖成功/失败 reload 的旧 `Arc` 与 DIRECT 句柄、控制面引用，以及旧数据面停止至新数据面就绪之间的短暂窗口。旧控制面 DNS 的 `invalidate_transports` 是 Chimera fail-closed 增强，不宣称 Mihomo 内部行为完全相同。不得将此当成 macOS service-scoped DNS ownership 或物理 NIC/utun 零泄漏验收。
- **尚未关闭的永久撤销风险**：`EnhancedResolver::reset_transports()` 成功时会清除 `transport_reset_failed`，因此被显式 invalidated 的旧 resolver 若仍有 `Arc` 调用方能对它再次 reset，理论上可重新开放旧上游。此切片只保证正常成功切换时同步触发失效关闭，**不保证失效不可逆**。下一轮优先写“保留旧 owner → reload 成功退休 → 旧 owner 独立 reset → 旧 DIRECT 查询必须失败”的否定测试，并设计与可恢复网络重置明确区分的永久 owner retirement 门禁。
- **本轮已验收范围（Rust 1.99.1、macOS ARM64、`CARGO_INCREMENTAL=0`）**：最小 `--no-default-features --features tun,ring` 的 helper 定向单测 1/1、完整核心库 1044 passed / 0 failed / 11 ignored、DNS 配置 46/46；默认特性 + `tun,ring` 核心库 1236 passed / 0 failed / 11 ignored；S00 旧版金标准 14/14。两种 feature 组合的严格 `clippy --all-targets -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均通过。严格 Clippy 首轮因测试模块位置触发 `items_after_test_module`，移至文件末尾后重新执行通过。真实热更新生命周期的所有分支、macOS 网络和跨平台原生验证仍待审。
- **只读远端核对**：`git ls-remote origin refs/heads/master` 返回 `0bd95adb038be2f406971e36943de0de2c5af025`，本地 `origin/master` 尚为 `f304da17...`；未 fetch/rebase。GitHub PR #111 尚为 open，其 HEAD `6cf2a545...` 的已列工作流中 CI 和 Proxy Throughput Tests 为 failure（Spelling、Commit Email Check 为 success）；#107 已合并，#85/#58 仍 open。上述远端状态均不验证本地未提交 DNS 改动，亦不是全部仓库工作流的穷尽清单。
- **审查与回滚**：L2 待独立 Reviewer 与维护者批准；本轮未修改固定 Mihomo、Git 共享历史、远端 PR/CI 或 macOS 系统网络。回滚时仅移除成功发布前的旧 resolver 退休调用和 helper，但会重新开放被识别的旧句柄继续查询风险，不应在未经审核情况下回滚安全约束。


## 2026-11-11 — 热更新旧 DNS owner 永久退休状态与并发 reset 隔离（P0 / L2 待审）

- **基线与授权**：复用原隔离工作树 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`、分支 `codex/macos-tun-fakeip-dns-privacy`，开工 HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，原有 11 个修改文件保留。只读参考 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda`；`dns/resolver.go::ResetConnection` 负责连接重置，但 Chimera 的旧 Rust `Arc` owner 永久撤销是额外的防泄漏保证，不能视作 Mihomo 内部算法等价。
- **先红后绿的否定测试**：`retired_dns_owner_cannot_be_reopened_by_old_parent_or_direct_reset`，保留旧父 DNS 和旧 DIRECT 子解析器句柄，模拟新配置发布后退休旧 owner，并尝试重置旧父和子再继续查询。修复前 **0/1 失败**：旧父 `reset_transports()` 意外成功；修复后 **1/1 通过**，旧父和 DIRECT 仍拒绝查询，新 owner 可独立 reset 并查询。
- **生产修复**：`ClashResolver::retire()` 与原有可恢复 `invalidate_transports()` 分离；默认实现委托给原有失效方法以避免破坏外部老式 resolver，`EnhancedResolver` 实现单调 `retired: AtomicBool`，同步拒绝新查询和退休后的 reset，并递归退休 DIRECT 子解析器。热更新的 `runtime/components.rs::retire_dns_owners` 现在在成功提交发布前调用永久 `retire()`；旧 runtime 准备失败、API 就绪失败及新数据面就绪失败回滚时，仍不会永久退休活跃 owner。
- **并发测试**：`retirement_during_inflight_reset_cannot_reopen_old_dns_owner` 使用两个可控 Notify 同步点，让旧 transport 重置挂起 → 退休旧 owner → 完成重置。测试 **1/1 通过**：即使底层 reset 成功，待返回的旧任务仍必须报错，后续查询和 reset 继续失败关闭。现有完整重置恢复路径不能被单纯替换为永久 retirement。
- **剩余风险**：需要完整 `runtime/lifecycle.rs` 热更新端到端测试以证明多类 `Arc` 持有者、旧/新 controller 和回滚状态；`ClashResolver` 默认 `retire` 仅提供兼容层失效，对非 `EnhancedResolver` 的第三方实现不自动保证不可逆；退休前已发出的 DNS 包无法收回，必须将真正物理 NIC/utun 零泄漏另行验收。L2 独立 Reviewer/维护者决定、跨平台原生运行、macOS DNS ownership / route 防绕行均待完成。未提交、推送、合并、修改系统 DNS/路由/TUN 或提权。


## 2026-11-11 02:03-02:07 PST - Retired Fake-IP ownership gate (P0, L2 review pending)

- Reused isolated worktree `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad` on `codex/macos-tun-fakeip-dns-privacy`, HEAD `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`; preserved all 11 existing modified files. Read-only fixed Mihomo reference `63bd52ec794b7051569b76ede2f6cdbf4c091fda`: `component/fakeip/pool.go::Lookup/LookBack` and `dns/resolver.go::ResetConnection`. Permanent retirement of an old Rust Arc owner is a Chimera-specific privacy guarantee, not identical to Mihomo internals.
- Red/green regression `retired_owner_must_not_return_old_fake_ip_mapping`: failed 0/1 before the change because a retired resolver still returned an old fake IP; passed 1/1 afterward. Added `ensure_not_retired` checks at early-return paths in `resolve`, `resolve_all`, `resolve_v4`, `resolve_v6`, and after asynchronous Fake-IP allocation. `should_fake_ip`, `is_fake_ip`, `reverse_lookup`, and `fake_ip_for_host` now reject retired-owner mappings before and after awaits.
- New concurrency regression `retirement_while_fake_ip_pool_is_locked_must_not_return_old_mapping`: holds the Fake-IP pool write lock, queues a lookup, retires the resolver, then releases the lock; passed 1/1. No separate red baseline was established for this additional regression. Previous in-flight reset retirement regression also passed 1/1. Ordinary network resets remain recoverable; permanent retirement is reserved for successful runtime replacement.
- Verification: macOS ARM64, Rust 1.99.1, `CARGO_INCREMENTAL=0`; `cargo fmt --all -- --check` and `git diff --check` passed. Strict Clippy `--all-targets -- -D warnings` passed in both minimal `--no-default-features --features tun,ring` and typical `--features tun,ring` profiles. Minimal library: 1047 passed / 0 failed / 11 ignored; DNS config: 46/46; legacy golden: 14/14. Typical library: 1240 passed / 0 failed / 11 ignored. The last added pool-lock regression was run separately and is not included in those full-suite counts. Expected port-binding ERROR logs arose from fault-injection tests.
- Pending: independent L2 review, full reload rollback state-machine integration, native cross-platform tests, and real macOS physical NIC/utun zero-leak capture. Next slice: prove rollback never permanently retires active DNS owners before the irreversible successful swap. Remote master read-only observed at `0bd95adb038be2f406971e36943de0de2c5af025`. No fetch/rebase, commits, push, PR mutation, system DNS/route/TUN changes, or privilege escalation.

## 2026-11-11 — P0: Candidate DNS policy cannot publish before reload commit (L2 pending)

- Baseline: isolated worktree Chimera_Client-715e28ad, codex/macos-tun-fakeip-dns-privacy, HEAD 3292ca7b4d100cfaf04fc8f84f86d2abc476a202. All prior uncommitted work is preserved. Read-only Mihomo reference 63bd52ec794b7051569b76ede2f6cdbf4c091fda (dns/resolver.go ResetConnection). Chimera runtime publication and rollback are Rust-specific safety guarantees; not Mihomo internal equivalence.
- First established real loopback-only HTTP PUT /configs and UDP Fake-IP tests in clash-lib/tests/api_reload_tests.rs: controller port bind failure preserves original 198.18.0.0/24 DNS state; candidate SOCKS bind failure rolls back without losing old Fake-IP allocation; direct successful reload and fail-then-success reload switch to a new 198.19.0.0/24 Fake-IP pool. Checks DNS transaction ID, QNAME, response code and A record. No TUN or machine-wide DNS/route changes.
- Red-phase P0 proof: while the new SOCKS listener was still failing readiness, an uncommitted candidate DNS listener served an actual 198.19.0.2 answer over loopback, before the reload returned HTTP 500 and rolled back. Concurrent in-flight test failed 0/1 with explicit candidate policy leak. The path was candidate start_all -> DNS bind succeeds -> inbound wait_initial_ready fails -> rollback.
- Production repair 1: clash-lib/src/app/dns/server/mod.rs keeps a per-runner Tokio watch publication gate. A candidate may bind for readiness, but DnsMessageExchanger awaits the successful commit before answering or dispatching to the resolver; cancellation terminates pending waits. Runtime lifecycle pauses candidate DNS publication before any listener starts, publishes only after every data-plane readiness check and old owner retirement. Old and rollback-fresh DnsRunner remain immediately usable. Concurrent integration test passes after repair, retaining old mappings and allowing a later successful reload.
- Production repair 2: new ClashResolver pause_publication/publish lifecycle hooks, default no-op for legacy implementations, implemented by EnhancedResolver with a staged publication AtomicBool. Its existing fail-closed query checks now reject unpublished owners, and the DIRECT child receives the same stage/publish transitions. Candidate primary and control-plane resolvers are suspended until commit. uncommitted_dns_owner_and_direct_child_must_not_query_upstream failed 0/1 before implementation (a staged parent called upstream); passed after implementation. Old retired owner remains retired even if publish is called again.
- Added deterministic DNS listener tests: staged_dns_listener_waits_for_commit_without_querying_upstream and cancelled_staged_dns_listener_never_queries_upstream. These exercise waiting/publishing and cancellation without real DNS sockets or external traffic; both pass. Existing full runtime reload integration verifies successful DNS publishing and rollback.
- Remaining risk: during a failed reload, deferred queries may timeout or receive SERVFAIL on cancellation, and a macOS service-scoped resolver might try an uncontrolled fallback; a process-local gate is not a substitute for OS DNS ownership, physical NIC/utun packet capture or egress blocking. In-flight packets already sent before retirement cannot be recalled. Third-party ClashResolver implementations still use default no-op publication hooks for legacy compatibility; the production SystemResolver is explicitly gated as described below. Other new inbound data-plane listeners and the exact commit linearization merit separate L2 review. No remote changes, history edits, system DNS, routes, TUN, Network Extension or privilege escalation. Independent L2 review, actual NIC+utun proof, cross-platform native validation and final-SHA CI are pending.


### Same-run P0 follow-up — SystemResolver candidate bypass closed

- Control-plane DNS may fall back to SystemResolver when its auxiliary nameserver pool is empty. Simply staging EnhancedResolver left the libc getaddrinfo path potentially callable from an uncommitted new controller. Added test staged_system_resolver_must_not_bypass_publication_with_ip_literals: **red 0/1** before implementation because a paused SystemResolver still returned 127.0.0.1 immediately; **green 1/1** after implementing publication and permanent retirement on SystemResolver.
- SystemResolver now defaults to published, preserves prior normal/IPv6 semantics, rejects all resolve/resolve_all/v4/v6 paths before lookup while staged, rechecks after asynchronous lookups, and cannot be reactivated after retirement. No public or OS-managed DNS queries were performed by this new test (only IP literals). This closes a concrete candidate control-plane bypass without relaxing config compatibility.
- The fixed Mihomo Go baseline does not define this Rust object-lifecycle publication contract. macOS service-scoped ownership, DNS fallback outside the process, preexisting in-flight system queries, and direct external lookup paths remain independent verification work.

### Final verification and API entrypoint audit (same P0 slice)

- In-flight failed reload test additionally probes the candidate controller GET /dns/query while the SOCKS bind is pending, and rejects any successful HTTP body with the uncommitted 198.19.* address. The candidate UDP listener test already established the red phase; the API probe expands ingress coverage. A repeated run of the combined controller + UDP rollback test completed 10/10 passes without candidate policy exposure.
- Rust 1.99.1 on macOS arm64; minimal no-default-features/tun/ring: strict all-targets Clippy -D warnings passed; core unit 1052 passed, 0 failed, 11 ignored; API reload 7/7; DNS config 46/46; legacy golden 14/14; S01 policy 17/17, S02 policy 14/14. Typical default features + tun/ring: strict all-targets Clippy passed; core 1243 passed before SystemResolver follow-up; API reload 7/7. chimera-dns package tests 7/7. Cargo fmt --all -- --check and git diff --check passed.
- A new SystemResolver staging/retirement regression adds one core test, so rechecking the full typical/minimal unit counts is necessary after this follow-up. The only installed Rust target in this workspace is aarch64-apple-darwin. No native Linux/Windows verification, real macOS NIC+utun capture, L2 independent review, or CI for these local unpublished changes was completed.


## 2026-11-11 03:08 PST — DIRECT 子解析器不得独立发布未提交的父 DNS policy（P0 / L2 待审）

- **范围/基线**：隔离工作树 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`，分支 `codex/macos-tun-fakeip-dns-privacy`，开工 SHA `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`，14 个原有修改文件完整保留；远端 master 只读 `0bd95adb038be2f406971e36943de0de2c5af025`。固定 Mihomo Go `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `dns/resolver.go::ResetConnection` 会独立重置正常/代理/DIRECT resolver，但没有 Chimera Rust Arc 的热更新发布所有权概念。本切片是 Chimera 本地强制 fail-closed 增强，不宣称 Go 内部语义等价。
- **否定测试（先红后绿）**：`direct_child_independent_publish_must_not_bypass_staged_parent` 构造父/子 `Arc` 与计数 DNS Client，先 `owner.pause_publication()`，再通过留存的 DIRECT 句柄调用 `direct.publish()`；修复前 **0/1 失败**：旧上游被提前请求，构成候选策略发布门禁绕行；修复后 **1/1 通过**：上游调用次数为 0，父级正式发布后 DIRECT 查询成功。
- **修复**：`EnhancedResolver::published` 改为 `Arc<AtomicBool>`，新增 `parent_published: Option<Arc<AtomicBool>>` 和 `with_parent_publication_gate`；正常配置创建 `dns.direct-nameserver` 时，DIRECT 子 resolver 会共享父级只读发布状态，`ensure_not_retired` 同时检查自身和父级门禁。父级暂停/退休同步阻止 DIRECT 独立发布；仅父级发布后允许恢复。保留旧的网络重置失败门禁和原有配置字段。
- **构造器验证**：`configured_direct_cannot_publish_without_parent_commit` 使用真实 `Config -> EnhancedResolver::new`（DIRECT 上游仅使用 `127.0.0.1:9`），再次证明子级独立 publish 不能绕过父级，且父级正式发布后本地 IP literal 查询恢复，测试 **1/1 通过**，不发送任何真实 DNS 查询。
- **限制**：DIRECT 的 `publish()` 当前不是用户主动提供的公共管理入口，真实绕行条件需要留存的内部句柄在独立调用路径被触发；这一故障注入用于确立不变量。父级创建期间的 bootstrap/provider 解析仍发生在协调器 `pause_publication()` 之前；是否存在构建期候选隐私策略泄漏需要独立注入测试。OS 级 DNS ownership / fallback、物理 NIC 和 utun 抓包、跨平台原生测试与 L2 独立审查仍未完成。未触及系统 DNS、路由、TUN、Network Extension、Git 共享历史、远端 PR 或 ref-mihomo。


### 03:20-03:24 PST — P0 publication follow-up and final regression results

- Concurrency: parent_pause_during_inflight_direct_query_rejects_old_answer held a DIRECT upstream response with Tokio Notify, paused the parent publication gate, independently published DIRECT and released the response. The stale reply was rejected; 1/1 passed and 20/20 independent repetitions passed. A packet already dispatched before pause cannot be recalled, so this verifies reply rejection, not physical NIC non-delivery.
- Verification (macOS ARM64, Rust 1.99.1): minimal no-default-features/tun/ring core 1056 passed, 0 failed, 11 ignored; typical default features plus tun/ring core 1248 passed, 0 failed, 11 ignored. Both strict all-targets Clippy with -D warnings passed. API reload 7/7, DNS configuration 46/46, legacy compatibility 14/14, S01 17/17, S02 14/14 and chimera-dns 7/7 passed. Parent publication and real config constructor regressions each passed 20/20 independent repetitions before the in-flight test was added. Cargo fmt and git diff --check passed.
- CLI: clash-rs minimal tun/ring check and standard aws-lc-rs without dashboard check passed. The regular default CLI check could not complete because build.rs requires the absent clash-dashboard/dist assets; no frontend install or build was performed. This is an environment/setup blocker, not a DNS diagnostic.
- Remote read-only: local master fb561bde..., local origin/master f304da17..., git ls-remote master 0bd95adb.... PR #111 remains open, and the PR HEAD 6cf2a545... has failed CI and throughput workflows; these statuses do not validate this dirty local branch. Open personal PRs #85/#58 are unrelated. No fetch, rebase, commit, push, PR writes, system networking changes or privilege escalation.
- Remaining P0: reload candidate creation performs provider/bootstrap and MMDB initialization before the coordinator pauses its DNS owner. Build an offline UDP/HTTP failure-injection test that proves whether candidate DNS bootstrap traffic can reach an upstream before commit. OS DNS service-scoped ownership and NIC+utun packet capture still require separately authorized validation, and independent L2 review/final-SHA CI remain pending.


## 2026-11-11 03:34 PST — 受保护候选配置的构建期 HTTP/DNS 出站隔离（P0 / L2 待审）

- **基线与参考**：复用隔离工作树 `/Users/adam/.devspace/worktrees/Chimera_Client-715e28ad`，分支 `codex/macos-tun-fakeip-dns-privacy`，开工 SHA `3292ca7b4d100cfaf04fc8f84f86d2abc476a202`；原先 14 个修改文件全部保留且没有重建/清理 worktree。固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 只读核对 `dns/resolver.go::ResetConnection`，Go 代码并不提供 Rust 候选运行时的发布事务语义。实时远端 master `0bd95adb038be2f406971e36943de0de2c5af025`（仅 `ls-remote`）。
- **发现实际 P0 出站窗口**：`runtime/lifecycle.rs` 在候选 `create_components(..., false)` **完成之后**才暂停候选 DNS；然而 `runtime/factory.rs` 内部的 `OutboundManager::load_proxy_providers` 会同步初始化 HTTP provider，并使用候选 resolver 请求远端；`Router::load_rule_providers` 也会启动 HTTP rule provider 初始化任务，`Mmdb::new` / `GeoData::new` 在缓存缺失或 URL 含 `force=true` 时会立即下载；损坏的 MMDB 还可能先删除旧文件再下载。先前 listener、DIRECT 和 control-plane 发布门禁均无法覆盖构建阶段。
- **先红后绿测试**：`runtime::tests::protected_candidate_http_provider_must_not_fetch_before_commit` 只使用 `127.0.0.1` 回环 HTTP 服务，修复前记录 **1 次**候选 provider 请求（0/1 failed），修复后 **0 次**（1/1 passed），候选返回明确诊断。HTTP rule-provider 构建前拒绝测试修复前 **0/1 failed**（候选已正常完成并调度异步初始化），修复后通过。缺失 Country MMDB 的回环测试修复前同样记录 **1 次**提前下载（0/1 failed），修复后通过；所有测试均未触碰系统网卡、TUN、全局 DNS 或真实外部服务器。
- **生产修复**：`clash-lib/src/runtime/factory.rs::reject_uncommitted_candidate_remote_egress` 在任何数据源初始化前执行。**仅 macOS + tun.enable + dns.enable + Fake-IP + 重载候选（activate_network=false）** 时，对 HTTP proxy-provider 和 HTTP rule-provider 返回显式 `InvalidConfig`；对配置了但本地缓存缺失、URL 含 `force=true` 的 Country/ASN MMDB 或 GeoSite 拒绝加载；预检用 `maxminddb::Reader::open_readfile` 检测 MMDB 损坏以防原流程删除缓存再下载。可用的本地 GeoSite 缓存不受阻断。正常首次启动和其他非受保护配置沿用原行为。
- **兼容性代价与理由**：该受保护热更新中的 HTTP proxy/rule provider 即使已有有效缓存也暂时被拒绝（潜在 polling 和后台 health check 尚未转为提交后激活）；不改变旧 YAML 字段本身，但这是一项明确、有限的 **运行语义兼容性收紧**。原因是构建期存在已复现的提前联网风险，宁可报错并维持旧运行时，也不允许候选静默发出受隐私策略影响的请求。彻底兼容需要把 provider 的缓存验证、首次抓取、健康检测和定时更新重构为“先准备纯本地资源 → commit 后启用”，再用端到端失败/成功热更新测试验证；不能因解析成功宣称兼容。
- **定向兼容测试**：非受保护候选 HTTP 代理提供者继续在回环 HTTP 完成初始化（1/1）；损坏 MMDB 明确拒绝且缓存原字节不被删除；GeoSite 缺失和强制下载被拒绝；有效的本地 GeoSite 缓存可以继续创建候选。所有测试只打开临时目录/127.0.0.1 监听或使用本地文件。
- **剩余 P0 风险**：文件代理提供者的独立 health-check、控制面外部 UI 资源下载、候选 HTTP 客户端的其他构建期操作，以及启动阶段 DNS TUN 真实安全状态尚未全面审计。普通运行时动态刷新、nameserver-policy + node bootstrap、DNS service ownership 回退、macOS NIC/utun 抓包、L2 独立 Reviewer、Linux/Windows 原生编译及最终 SHA 的 CI 都还未完成。没有进行提权、系统网络修改、远端写入、历史改写、提交或 PR 更新。


### 2026-11-11 04:00 PST — 文件代理提供者健康检查 IP-literal 出站旁路（P0 / L2 待审）

- **故障现象、先红后绿**：`runtime::tests::protected_candidate_file_provider_health_check_has_no_precommit_egress` 在受保护候选配置中配置文件代理提供者、`LOCAL_DIRECT` 和 `http://127.0.0.1:<ephemeral>/health` 探测。即使候选的主/控制面 DNS owner 已在 factory 内暂停，`HealthCheck::run_check` 通过 IP 字面量直接连接回环 TCP，修复前 **0/1 失败，观察到 1 次不应发生的连接**。首次 test helper 中 `JoinHandle` 已完成又二次 poll 出现测试自身 panic，已单独修正，不计为生产缺陷。修复后 **1/1 通过**：发布前 350ms 无 TCP 请求、手动 commit 发布 DNS 后调用补偿探测触发 1 次回环 TCP 连接。
- **最小生产修复**：`ClashResolver::permits_background_egress` 新增同步只读接口；`EnhancedResolver` 利用已经存在的 `ensure_transport_dispatch_ready` 检查 staged、retired、父级及 network-reset 门禁；`SystemResolver` 检查本身 publication/retirement，且对原系统解析器回归测试补充 probe gate 断言。`ProxyManager` 仅转发该状态到 `HealthCheck::run_check`，因 IP-literal/TCP 路径不会经过 DNS 解析门禁，在实际 connect 前拒绝尚未发布的探测。原 DNS 处理/规则配置未改动。
- **恢复与范围**：`OutboundManager::resume_provider_health_checks_after_commit` 通过 Tokio spawn 触发已存在提供者的健康检查；`runtime/lifecycle.rs` **只对 macOS + feature tun + 实际 tun_enabled + dns_enabled + Fake-IP** 成功 commit 后调用，失败 rollback 不调用，普通非保护模式没有重复发起恢复探测。文件提供者不会被删去，正常启动仍按原路径执行。
- **防御边界**：其他继承 `ClashResolver` 默认 `permits_background_egress=true` 的第三方实现**没有**获得本地强制保护；状态检查至 TCP connect 之间存在 TOCTOU 竞态，已发出的 socket 无法撤回，未实现 TUN/物理 NIC 级防火墙证明；某些第三方发起的 HTTP/TCP 无法经过 `HealthCheck`。候选 HTTP proxy/rule provider 的受保护热更新仍因缺乏 post-commit fetch 被明确拒绝。对于远端 provider、MMDB、GeoSite 要保留 Mihomo 完整运行行为，后续需独立两阶段提交设计和 L2 审查。
- **文档备注**：本次纯 loopback fixture 验证不等于系统级 DNS/utun 零泄漏；无权限提升、系统 DNS/路由/utun 修改。固定 Mihomo `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 仅提供对照行为，不直接提供 Rust lifecycle 门禁。


### 2026-11-11 final validation of precommit HTTP/healthcheck protection

- Rust 1.99.1 macOS arm64, no system DNS/TUN changes: `cargo clippy -p clash-lib --all-targets --no-default-features --features tun,ring --locked -j 2 -- -D warnings` PASS; same with `--features tun,ring` and defaults PASS. `cargo test -p clash-lib --lib --no-default-features --features tun,ring --locked -j 2`: **1066 passed / 0 failed / 11 ignored**. With defaults `--features tun,ring`: **1258 passed / 0 failed / 11 ignored**. API reload **7/7**; DNS config **46/46**; legacy **14/14**; policy S01 **17/17**; policy S02 **14/14**; chimera-dns **7/7**; full Cargo fmt and git diff --check PASS.
- CLI checked after factory and healthcheck additions: `cargo check -p clash-rs --no-default-features --features tun,ring --locked -j 2` PASS and standard `--no-default-features --features standard,aws-lc-rs` PASS. Regular default CLI cannot be verified without separately building `clash-dashboard/dist` (known existing asset prerequisite); no unrelated frontend work was authorized/performed. Only `aarch64-apple-darwin` target installed, no Linux/Windows native cross-build. The user-required macOS physical NIC and utun packet-capture proof is NOT performed (no authority to alter the system).
- Test-slice facts: country MMDB missing, ASN MMDB missing, MMDB force=true and corrupted cache all reject before fetching; geo-site missing/force=true reject; available local GeoSite cache works. Negative fixture initially used `asn_mmdb` YAML instead of canonical `asn-mmdb`, which was not recognized and made one test fail; corrected test to canonical field. No production bug was inferred from that test-fixture mistake. Precommit primary/control-plane resolver gates are enabled before OutboundManager and Router construction, not just after factory return. Healthcheck gate and postcommit compensation test both pass. Unknown third-party resolvers with default permissive `permits_background_egress` and already-open sockets remain limitations.
- Repository: isolated branch and no commits/pushes/PR writes, protected user edits preserved; 19 modified files in isolated worktree after this slice. Fixed Mihomo gitlink unchanged `63bd52ec794b7051569b76ede2f6cdbf4c091fda`. Real remote master read-only `0bd95adb038be2f406971e36943de0de2c5af025`; local `origin/master` remains stale. L2 Reviewer/maintainer approval and final-SHA CI are still pending; do not merge/release based on this local pass.
- Rollback scope: remove the factory reject/staging gate, background egress permission check and successful commit probe compensation only together, after acceptance of a designed replacement; removing only the restriction reopens precommit HTTP/DNS exits. Next slice should make remote provider/GeoIP/GeoSite bootstrap truly deferred to postcommit with preserved local-cache semantics, and add loopback E2E config reload negative/positive probes plus failed readiness rollback for direct-IP healthchecks.


### 2026-11-11 supplementary no-TUN feature matrix and soak tests

- Protected macOS candidate healthcheck denial and post-commit recovery test ran **20/20** independent repetitions, with zero precommit TCP hits and one expected postcommit loopback hit per run. The protected candidate subtest filter also passed **10/10** repetitions. No OS DNS/TUN, routing, privilege or public DNS changes.
- Feature-off contract: cargo check -p clash-lib --no-default-features --features ring --locked -j 2 PASS and strict cargo clippy -p clash-lib --lib --no-default-features --features ring --locked -j 2 -- -D warnings PASS. **Do not claim no-TUN all-targets passes:** clippy --all-targets failed on connection_chain_tests.rs unused Socks5UdpSession import and unused wait_for_rule_interface_failure function. Full no-TUN cargo test -p clash-lib --lib --no-default-features --features ring reported **1014 passed / 9 failed / 9 ignored**: eight configuration-conversion tests expect a working TUN despite deliberately removing the feature, and proxy::direct::tests::direct_tcp_selected_path_binds_its_source_address lacked a MockClashResolver::ipv6() expectation. These are unaddressed feature-off matrix failures, **not** claimed fixed or waived; do not change unrelated tests merely to make this slice green.
- Final feature-on post-fix results remain: minimal tun,ring 1066 passed / 0 failed / 11 ignored; default+ tun,ring 1258 passed / 0 failed / 11 ignored, two strict all-targets Clippy PASS, API reload 7/7, DNS config 46/46, golden 14/14, S01 17/17, S02 14/14 and chimera-dns 7/7. CLI tun,ring minimal and standard standard,aws-lc-rs without dashboard compile PASS. Final default CLI requires dashboard assets (not built).

### 2026-11-11 — master/DNS rebase candidate integration verification (L2 review pending)

- **基线**：本地 `master` 为 `fb561bde919faab25c8b2500b2f8e5255e120c3f`，远端最新 `origin/master` 为 `0bd95adb038be2f406971e36943de0de2c5af025`，共同祖先为 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`。本地 master 有 7 个已提交提交尚未在远端，且另有用户未提交改动；这些改动保留在原工作树，未复制到候选分支。
- **历史处理**：候选分支先以签名合并提交 `73c9554` 同时接入本地 master 和最新 origin/master，再将 DNS 分支提交线性 rebase 到其上。DNS 分支原 41 个提交中，已有一项被上游包含而自动跳过，其余 40 项按新 SHA 重放；原分支和原 master 均未改写。`git merge-tree` 预检报告 6 个路径有冲突；实际 rebase 中对 `clash-lib/src/app/dns/config.rs` 与 `clash-lib/src/config/def.rs` 做了手工语义合并，其余冲突由逐提交重放化解。
- **合并后的整理**：保留 master 中更严格的敏感字段相似度检查，并让新错误采用不回显域名/selector 的通用提示；去除重放造成的重复配置测试，修正 resolver 测试中已变更的 `Arc` 字段类型。`strict-route: true` 由运行时转换层拒绝，因此原始 YAML 解析测试改为检查真实拼写错误，保留转换层的 fail-closed 回归用例。
- **验证**（Rust 1.99.1、macOS ARM64）：`cargo fmt --all -- --check`、`git diff --check`、最小 `--no-default-features --features tun,ring` 严格 all-target Clippy、`--all-features` 严格 all-target Clippy 均通过；最小特性库单测 **1073 passed / 0 failed / 11 ignored**，全特性库单测 **1447 passed / 0 failed / 11 ignored**；两种 feature 组合的 DNS 配置 **47/47**、API reload **7/7**、S00 legacy golden **14/14** 通过。Dashboard 使用 CI 锁定的 pnpm 11.27.0 安装并构建成功，以满足全特性 Rust 构建所需的嵌入资源。
- **环境与未覆盖项**：全特性测试首次编译因磁盘空间耗尽而未启动；清理本候选工作树的 Cargo 生成物（`cargo clean -p clash-lib`，释放约 8.4 GiB）后，使用 `CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0` 完整重跑并通过。没有 Linux/Windows 原生执行、macOS 真实网卡/utun 抓包、系统 DNS/路由修改或 GitHub CI 验证；这些都不能由本机离线测试替代。
- **状态**：此候选仍待最终 SHA 的独立 L2 Reviewer 和维护者验收。未更新本地 master、未推送、未创建 PR，也未触发 master push 会执行的 `latest` 预发布工作流。回滚可直接放弃该候选分支；若之后推送到 master，则通过对合入 SHA 执行 revert 回滚，并单独处理工作流产生的预发布产物。

### 2026-11-11 — rebase 后 DNS 策略与系统解析边界复核（L2 待审）

- **修复的整合缺陷**：Fake-IP filter 现在验证域名/通配符语法、按 DNS wire IDNA 形式规范化，并检查 trie 插入结果；fallback-filter domain 也会按 wire IDNA 规范化并拒绝不支持的规则表达式。因此错误通配符不会静默失配，Unicode 白名单/过滤条件也不会因 QNAME 转成 punycode 后漏匹配。保留已有 `.domain`、`*.domain`、`+.domain` 语法。
- **策略匹配**：代理节点 nameserver policy 按从根域向左的具体程度比较；精确项胜过 `*`，`*` 胜过 `.` / `+.` 后缀项，规则顺序不再改变结果。`+.` 保留 apex 与子域匹配，`.` 只匹配子域，因此二者同时命中时 suffix-only 的 `.` selector 胜出；apex 仍由 `+.` 处理。普通 `nameserver-policy` 编译前先插入 `+.` 后缀，再插入精确项，确保 `+.example.com` 生成的 apex 别名不会盖过 `example.com`。YAML 与内部 reload 都将 Unicode selectors 规范化并拒绝规范化后的重复项。
- **静态节点与 secondary DNS**：静态代理节点和 `hosts` 域名均统一成与 DNS wire name 一致的 IDNA ASCII 形式，并规范化绝对域名末尾点；`hosts` 别名和无效 trie selector 会显式报错，Internal 配置入口也拒绝未经规范化的公开 hosts trie，避免静默漏匹配。VLESS XHTTP `http/1.1` 的 `upload-settings.address` 现在与已有 download endpoint 一样受 TUN + Fake-IP 检查；静态配置、内部 reload、动态 Provider 刷新都拒绝会走系统 DNS 的域名上传端点，并保留上一版可用 Provider。macOS TUN + Fake-IP 下，`external-controller` bind 也必须是 IP 字面量，避免启动/reload 为本地 listener 调用系统解析器。
- **回归用例**：新增/扩展 malformed Fake-IP filter、fallback filter IDNA/非法 selector、hosts IDNA/根点/别名冲突、DNS selector 规范化别名、普通策略 apex 冲突、节点策略 exact/wildcard/suffix 优先级及 `.`/`+.` 子域/apex 优先级、IDNA + trailing-dot 静态节点、XHTTP 上传静态/reload/provider 失败关闭及 macOS controller hostname 测试。XHTTP 上传和 Provider 用例使用本地/模拟客户端，不访问公网。
- **实际验证**（macOS ARM64，仓库锁定 Rust）：最小 `--no-default-features --features tun,ring --lib` **1095 passed / 0 failed / 11 ignored**；全特性 `--all-features --lib` **1469 passed / 0 failed / 11 ignored**；`--test dns_config_tests` **48/48**。定向策略、IDNA hosts/fallback、Internal hosts trie 绕过、XHTTP upload/provider、Fake-IP filter 及 macOS controller tests 均通过。最小和全特性 `cargo clippy -p clash-lib --all-targets ... -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。完整库回归曾发现 `.domain` 被 IDNA helper 误判为无效、fallback YAML 测试重复了顶层 DNS key；修复后最小与全特性完整库回归均通过。
- **剩余边界**：本轮没有 Linux/Windows 原生运行、macOS 真实 utun/物理 NIC 抓包、系统 DNS 接管验证或远端 CI；不能据离线测试宣称系统级零 DNS 泄漏。当前真实 DNS/Network Extension 的限制仍按本文前述风险记录。本地候选 SHA 改变后必须由独立 L2 Reviewer 按最终 diff 复审并由维护者验收，再决定是否推送；直接更新 master 还会触发 `latest` 预发布流程。

## 2026-11-09 — 批次 6：nameserver-policy 多上游数组与故障隔离（L2 待审）

- 基线：隔离集成分支 `codex/dns-master-batch6-20261109` 创建自 `70c0fc457cd5f61641915be5f38859b4983b1f2e`，本地 `origin/master` 快照 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`。固定、只读 `ref-mihomo` gitlink `63bd52ec794b7051569b76ede2f6cdbf4c091fda` 的 `config/config.go::parseNameServerPolicy` 接受单字符串或字符串数组；本批补齐这项配置到真实解析器的完整数据路径。
- 原始 `dns.nameserver-policy` 值改为无标记枚举 `DnsPolicyUpstreams::{Single(String), Multiple(Vec<String>)}`，保留老 YAML 单字符串语法，同时接受数组。内部配置以 `HashMap<String,Vec<NameServer>>` 保存每个选择器的全部解析上游；多域名选择器仍各自复制同一有序列表；`EnhancedResolver` 为策略选择器一次创建整个 DNS client 集合，匹配后仍只在策略集合内查询。
- 失效关闭：`[]`、仅 `system`、混合 `system`、不支持的上游协议均不接受；不能因跳过上游而悄悄改变 DNS 目标。内部配置/转换的 IPv6 禁用校验现在遍历每个策略上游；显式 DNS egress 冲突检查遍历原始 policy 的每个 `#proxy`/`#interface` 后缀，防止藏在第二个上游；`s02_second_nameserver_policy_upstream_forced_proxy_blocks_explicit_egress` 用第二项 `#proxy` 验证该拒绝路径。
- 测试先行：旧实现对数组的 `nameserver_policy_array_values_keep_all_upstreams_in_order` 先在 YAML 解析阶段失败（`invalid type: sequence, expected a string`）。修复后新增/更新集成测试，验证按序保存两个不同传输的上游、禁用 IPv6 时第二个上游仍受校验、无效数组拒绝；旧版 golden 验证旧单字符串继续可用。独立 mock DNS 故障注入：首个 policy 上游失败、第二个成功，A/TXT 均返回所选结果；两者全部失败时保留两个错误原因，主 nameserver/fallback 调用计数始终为零。
- 本地验证：macOS Rust **1.99.0**，`--no-default-features --features tun,ring` 核心库 **847 pass/0 fail/11 ignored**，默认 features + `tun,ring` 核心库 **1039 pass/0 fail/11 ignored**；两组 `dns_config_tests` **25/25**、`dns_legacy_golden_tests` **11/11**、`dns_policy_s02_tests` **15/15**；严格 `clippy --all-targets -D warnings`、Cargo fmt 和 `git diff --check` 两组均通过。
- 差异/未完成：保留列表配置顺序并不意味着严格串行回退；当前 Chimera `batch_exchange` 会并发请求多个 DNS 上游，首个有效正答优先；负答采取已有时间窗与配置顺序策略。尚未实现 Mihomo orderedmap 规则顺序、GeoSite、RuleSet 的完整匹配，或实测 Mihomo 二进制等价。项目锁定 Rust 1.99.1 在本机缺少有效 manifest，本次测试使用 1.99.0；未执行实机物理 NIC/utun 抓包、远端 required CI 和独立 L2 审查。只本地签名、不推送，不修改系统网络或其他工作树。


## 2026-11-09 — 批次 7：nameserver-policy 域名规则声明顺序（L2 待审）

- 基线：从第 6 批独立提交 `5252b8a408e20c8c0cbd1aaf527819a064167353` 新建 `codex/dns-master-batch7-20261109`；`origin/master` 为 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定只读 `ref-mihomo` 为 `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。
- 固定 Mihomo `config/config.go::parseNameServerPolicy` 使用有序映射保留 YAML 定义顺序，`dns/resolver.go::makePolicy` 按该顺序插入普通域名策略分组；`component/trie/domain.go::Insert` 对 `+.example.com` 同时覆盖 apex 和子域名通配符，后续显式 apex 规则可以覆盖 apex。本批只迁移**已经实现的普通域名 trie 插入顺序**，不启用 `geosite:`、`rule-set:` 或跨动态匹配器的优先顺序。
- 修复前 `dns.nameserver-policy` 采用无序 `HashMap`，当 `example.com` 与 `+.example.com` 指向不同上游时，插入 trie 的先后顺序受随机哈希影响。新增 `nameserver_policy_overlapping_exact_and_plus_follow_yaml_order`，对 YAML 两种声明顺序分别运行 64 次并测试 apex 与子域名；旧版在第一次运行即失败，修复后全部通过。
- 原始配置 `DNS.nameserver_policy`、内部 `dns::Config.nameserver_policy` 和 `parse_nameserver_policy` 输出均改成 `indexmap::IndexMap`，确保从带 YAML 合并的解析直到 live `EnhancedResolver` 依次插入对应 trie；改用工作区既有的 `indexmap 2.14.2`（直接依赖启用 `serde` 特性），同步必要 `Cargo.lock` 和 `runtime/factory.rs` 构造。
- 本地 macOS、Rust 1.99.0，`--no-default-features --features tun,ring`：核心单测 **848/848 通过，另 11 ignored**，`dns_config_tests` 25/25、`dns_legacy_golden_tests` 11/11、`dns_policy_s02_tests` 15/15；默认 features + `tun,ring`：核心单测 **1040/1040 通过，另 11 ignored**，同样三个集成测试均通过。两组 `clippy --all-targets -- -D warnings`、`cargo fmt --all --check`、`git diff --check` 均通过。`clash-rs` CLI `cargo check --no-default-features --features standard,aws-lc-rs --locked` 通过；默认 CLI 构建受隔离工作树缺少 `clash-dashboard/dist` 阻塞，非此次 Rust 配置编译错误，未构建 Dashboard。
- 边界：上述普通域名同组 trie 优先级不是 Mihomo geosite/rule-set 的动态匹配优先级；二者仍严格拒绝，避免静默误路由。没有实际 Mihomo 二进制差异运行、macOS 真实 NIC/utun 抓包、锁定 Rust 1.99.1（本机安装 manifest 缺失）、远端 CI 或独立 L2 Reviewer。仅本地签名提交；不自动推送、合并 `master` 或修改宿主机网络及其他工作树。


## 2026-11-09 — 多上游、有序策略候选合并与旧 API 兼容（L2 待独立审查）

- 基线：本地 master fb561bde919faab25c8b2500b2f8e5255e120c3f；origin/master f304da17b7eaf6a187daf03a96bb1e77a26dd049；固定只读 Mihomo gitlink 63bd52ec794b7051569b76ede2f6cdbf4c091fda。独立候选分支 codex/dns-policy-multiupstream-l2-20261109 上分批签名 cherry-pick：a219f67（多上游）与 053cbb7（规则声明顺序）。
- 本轮接口回归红绿测试：新的多上游改动原本把公开 Config::parse_nameserver_policy 的 HashMap<String,String> 输入、HashMap<String,NameServer> 返回改成了 IndexMap<String,DnsPolicyUpstreams> 与 IndexMap<String,Vec<NameServer>>。新增 legacy_hashmap_policy_api_remains_source_compatible，旧代码出现 E0308 编译失败；修复后保留 legacy 方法的原输入/返回签名与单上游语义；另开 parse_nameserver_policy_ordered 用于 YAML 有序多上游，已有多上游调用全部迁移过去。用户原未提交的空白选择器测试无需修改即可保持编译兼容。
- 实测 macOS Rust 1.99.0、CARGO_INCREMENTAL=0：精简 features(tun,ring) 核心 849 pass/0 fail/11 ignored；默认+features(tun,ring) 核心 1041 pass/0 fail/11 ignored。两组 DNS config 25/25、legacy golden 11/11、DNS policy 15/15，严格 Clippy --all-targets -D warnings、Cargo fmt、git diff --check 均通过。CLI（standard,aws-lc-rs，不带 Dashboard）check 通过。
- 运行语义：单字符串/数组 YAML 经 IndexMap 规范化解析 → 多个 DNS NameServer → 策略的独立 DNS client 组；实际 batch_exchange 是多个上游并发的现有策略，不代表严格串行重试。模拟测试已覆盖 policy 上游失败不落到 public main/fallback、第二个上游以及 IPv6/egress 检查。
- **治理状态：本批是编码 Agent 自检，不是独立 L2 Reviewer。** 独立 Reviewer 或规范规定的仓库所有者针对确切 SHA 的书面豁免、维护者决定、GitHub Verified、远端 required CI、macOS 实机 NIC/utun DNS 防泄漏包级验证仍待完成；本机仓库锁定 Rust 1.99.1 工具链不可用，使用了 Rust 1.99.0。原主工作树及用户未提交文件保留，不推送、不合并远端、不修改宿主机 DNS/TUN/路由。

## 2026-11-09 — 多上游 L2 自查：规范化域名重复选择器的顺序语义

- 证据与审查类型：编码 Agent 源码自查（非独立 Reviewer）。固定 ref-mihomo SHA 63bd52ec794b7051569b76ede2f6cdbf4c091fda 的 config/config.go::parseNameServerPolicy 按有序 YAML 表拆分普通逗号键并依次 append；dns/resolver.go::makePolicy 在相邻普通域名段逐项 DomainTrie.Insert，component/trie/domain.go::insert 以 node.setData 覆盖同一节点。三个顺序规则（example.com,other.test）、（+.example.com）、（EXAMPLE.COM）合法，第三条精确域名应是最后生效的 apex DNS。
- 原缺陷 HIGH（已在候选分支修复）：clash-lib/src/app/dns/config.rs::parse_nameserver_policy_ordered 对展开后的重复规范化域名直接报错，拒绝 Mihomo 可加载的配置。新增 nameserver_policy_colliding_expanded_domain_obeys_last_declaration，起初失败于 duplicate domain selector，修复后通过。采用 IndexMap::shift_remove 后重新插入，不能在原位置简单覆写，否则交错的 +. 通配规则会覆盖本应最后生效的精确域名。新增 nameserver_policy_yaml_collision_keeps_last_declaration_order，覆盖 YAML → IndexMap → 内部 DNS 策略 → trie 的完整顺序及 apex/子域名不同上游；两种不同声明顺序的规则均通过。仍拒绝 malformed/whitespace/未支持的 geosite/rule-set 组合，不再将合法重复 exact 视为歧义。
- 修复后本地矩阵：macOS Rust 1.99.0，CARGO_INCREMENTAL=0。精简 tun,ring 核心 851 pass/0 fail/11 ignored；默认 tun,ring 核心 1043 pass/0 fail/11 ignored；两组 dns_config_tests 25/25、dns_legacy_golden_tests 11/11、dns_policy_s02_tests 15/15。两组严格 Clippy --all-targets -D warnings、cargo fmt --all --check、git diff --check 均通过；不含 Dashboard 的 CLI standard,aws-lc-rs 编译检查通过。
- 审查门禁：本记录是编码 Agent 自查，不能代替独立 L2 Reviewer 或维护者批准；真实 Mihomo 二进制对照、macOS NIC/utun 实机 DNS 抓包、锁定 Rust 1.99.1、GitHub Verified / required CI 尚未验证。需要独立审查或依治理规范由有权仓库所有者针对最终 SHA 留下书面豁免。仅本地签名，不推送、不合并远端，不改系统网络及主工作树未提交测试。
## 2026-11-09 — 批次 8：GeoSite nameserver-policy 运行时匹配与加载隔离（L2 待审）

- 基线：已签名第 7 批 `8d64425f900fa162a1d5dac96acfd22d88d8d049`；远端 `origin/master` 快照 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定只读 Mihomo `ref-mihomo` `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。参考 `config/config.go::parseNameServerPolicy`、`dns/resolver.go::makePolicy` 和 `dns/policy.go`，本轮只完成 **GeoSite**，`rule-set:` 动态 RuleProvider 尚未接入。
- `nameserver-policy:` 现在接受 `geosite:private`、`geosite:private,cn` 的逗号拆分及大小写折叠，保留已支持普通域名和数组上游；空分类、错误混合 `rule-set:`、无效逗号和空白在配置转换阶段拒绝。不把 GeoSite 作为无效的 DNS trie 字面标签。
- 新增 `PolicySegment::{Domains,GeoSite}`：将相邻普通域名合并为一个 trie 段，遇到 GeoSite 则终止该段并插入匹配器；按原始 YAML 顺序遍历，保留普通规则之间的 trie 覆盖语义和动态 GeoSite 相对顺序。复用已存在的路由 `GeoSiteMatcher` 和 `GeoDataLookup`，包括 `Full/Domain/Plain/Regex` 与 `@attribute` 解析；不同传输的 policy DNS upstream 仍由已有 `make_clients` 创建，成功命中后执行现有 `batch_exchange`，出错不会 fallback 到 public DNS。
- 因启动顺序是 DNS Resolver → OutboundManager → GeoData → Router，新增每个内部 DNS Config 独占的 `Arc<OnceLock<HashMap<String,GeoSiteMatcher>>>`；在 GeoData 下载/解析完成、全部声明的 GeoSite 分类及正则 **全部预编译通过后** 一次性发布，DNS 查询路径不再重复编译正则或 trie。匹配器未就绪时所有交由该有序策略集的 DNS 查询必须 fail-closed，不能误落主 `nameserver`；上游传输重置也遍历 GeoSite 段的客户端。未改动操作系统 DNS/TUN 或网络权限。
- 红绿测试：`geosite_policy_selectors_expand_without_becoming_literal_domains` 在旧解析器 0/1，修改后通过。新增运行时 mock GeoData、相邻普通规则与 GeoSite 顺序测试，验证加载前零公共 DNS 调用，加载后命中规则及未命中主 DNS；新增 A/TXT 两种查询的 GeoSite 专用上游故障注入，证明 main/fallback 均无调用。入口集成测试对缺失 GeoSite 数据的真实 startup 确认拒绝；factory 单测验证不存在分类或不合法正则会拒绝整个安装，不能发布部分有效数据。
- macOS Rust 1.99.0、`--no-default-features --features tun,ring`：核心测试 **854 通过，0 失败，11 忽略**，`dns_config_tests` 26/26，`dns_legacy_golden_tests` 11/11，`dns_policy_s02_tests` 15/15；默认 features + `tun,ring` 核心测试 **1046 通过，0 失败，11 忽略**，同样三个集成套件均通过。两组严格 `clippy --all-targets -- -D warnings`、`cargo fmt --all --check` 与 `git diff --check` 通过；`clash-rs --no-default-features --features standard,aws-lc-rs --locked` CLI check 通过。默认 CLI 含 Dashboard 的 `clash-dashboard/dist` 不在隔离 worktree，未构建。
- 兼容性与安全边界：GeoSite 本轮是启动加载后的**静态匹配视图**，不宣称数据库热更新；域名匹配使用现有 GeoSite matcher，没有针对 Mihomo 二进制测试额外对照全部 GeoSite 正则语义；`rule-set:` 仍严格拒绝，因现有 RuleProvider 的异步初始化、刷新与 `try_read()` busy→false 行为不能直接作为 DNS 隐私判断依据。Rust 锁定 1.99.1 安装失效，远端 required CI、独立 L2 Reviewer、NIC/utun 抓包和系统 DNS ownership 端到端验证未完成。本批仅本地签名候选，不代表批准合并主线或已证明系统零 DNS 泄漏。


## 2026-11-09 — 批次 9：内联 Domain RuleSet DNS 策略（L2 待审）

- 基线：第 8 批已签名 `7758f5116079fb5cb9799d2e3a0a3a8979fedc7f`，`origin/master` 快照 `f304da17b7eaf6a187daf03a96bb1e77a26dd049`；固定只读 `ref-mihomo` SHA `63bd52ec794b7051569b76ede2f6cdbf4c091fda`。核对 Mihomo `config/config.go::parseDomainRuleSet` 与 RuleProvider `MatchDomain`。本批只支持 **内联、domain 行为** RuleProvider；网络下载和文件更新的启动引导与刷新仍未安全实现。
- 原始 DNS policy 支持 `rule-set:private-domain` 和同类逗号组（例如 `rule-set:private-domain,other`），保持 YAML 声明顺序。转换阶段验证所引用 provider 名称必须唯一（大小写无歧义）、类型为 `inline`、行为为 `domain`、payload 非空且所有域名语法有效；RuleProvider 构造 DomainSet 时将域名规则统一转为小写 ASCII/IDNA wire 形式，避免大写或 U-label 被接受却无法命中。文件/HTTP、IPCIDR/Classical、缺失或无效域名 payload 立即失败，不把未知规则当“不匹配”。
- `EnhancedResolver` 新增 `PolicySegment::RuleSet` 与共享 `Arc<OnceLock<HashMap<String,ThreadSafeRuleProvider>>>` 注册表，将相邻普通域名 trie、GeoSite 和 RuleSet 匹配器按配置顺序运行。DNS resolver 先于 Router 构建，故注册前即使已有普通域名也拒绝未经确认的 DNS 出口；Router 已验证并同步初始化所引用的内联 domain Provider 后，工厂统一发布注册表，再启动其他规则提供者的后台下载。未引用 DNS 的现有 Router 构造流程保持原异步行为。
- `RuleProviderImpl::match_dns_domain` 采用三态安全结果（匹配、不匹配、不可用错误），只允许初始化成功的 Domain Provider；DNS 不使用原 `search()` 的 `try_read` 繁忙→false 行为，而是等待读锁（最长 5 秒，超时失效关闭）； provider 的内容替换仍在原写锁内原子完成。**本轮不启用 File/HTTP DNS RuleSet，也不声称实现网络 provider 的动态热更新或自动缓存失效**。
- 测试先行：新增 YAML 集成回归在旧代码失败（selector unsupported），改动后通过；新增 Router 初始化红绿测试，揭示一次重构误移除同步初始化，修复前 `DNS rule-set provider is not initialized`，修复后成功匹配。Provider 单测验证未初始化拒绝、更新读锁争用期间不假装不匹配、释放写锁后取得真实匹配结果；另覆盖 `PRIVATE.EXAMPLE` 和 `bücher.example` payload 分别匹配小写 DNS 名与 `xn--bcher-kva.example`，该回归在规范化前失败。DNS Mock 单测验证未注册时无公共上游调用，RuleSet 与域名策略的声明顺序，以及 A/TXT 的 RuleSet 专用上游故障不会回退主/备用 DNS。另以 `start_scaffold_instance` 的真实启动/取消路径验证内联 RuleSet 进入 Runtime（非 DNS 物理网卡抓包）。
- 完整本地验证：macOS **Rust 1.99.0**，`--no-default-features --features tun,ring` 核心库 **859 pass/0 fail/11 ignored**；默认 feature + `tun,ring` 核心库 **1051 pass/0 fail/11 ignored**。两组 DNS 配置 `dns_config_tests` **29/29**、旧版兼容 `dns_legacy_golden_tests` **11/11**、策略 `dns_policy_s02_tests` **15/15**。两组严格 `clippy --all-targets -- -D warnings`、`cargo fmt --all --check`、`git diff --check` 均通过；无 Dashboard 的 CLI `clash-rs --no-default-features --features standard,aws-lc-rs --locked` 检查通过。实际启动测试不修改系统 DNS/TUN/路由；通过可取消的 `start_scaffold_instance` 验证运行时初始化/退出。
- 本次在本地 `master` 冲突整合后的复验（macOS Rust 工具链以 `rustc --version` 为准）：`cargo fmt --all -- --check`、`cargo check -p clash-lib --all-features --locked`、`cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` 通过；`cargo test -p clash-lib --all-features --locked --test dns_config_tests` **55/55 通过**，`cargo test -p clash-lib --all-features --locked --lib` **1492 通过、11 忽略**。另对 DIRECT resolver 继承共享 RuleSet 的独立回归通过。本次没有验证其他平台、Mihomo 二进制互操作或真实 NIC/utun DNS 出口；本地模拟测试不能证明这些环境行为。
- 本次整合验证使用仓库锁定的 Rust **1.99.1**；默认 CLI 的 Dashboard 构建、独立 L2 Review、GitHub required CI、Mihomo 二进制互操作及 macOS 物理 NIC/utun 防泄漏抓包仍待验证。本批只本地签名，不自动推送或合并远端 `master`，不触碰用户其他工作树。
## 2026-11-07 12:00 PST: DHCP network-path reset cleanup and stale-discovery rejection

- The target `codex/macos-tun-fakeip-dns-privacy` was **dirty** (an independent uncommitted `internal_explicit_empty_node_dns_fails_before_runtime_bootstrap` implementation/test), so this P0 change was made in a new clean isolated worktree `codex/macos-dns-egress-audit-20261107`, cut from target HEAD `f23b17354e5607f8bb866db98f03a9bfd4746572`. The main checkout and both existing worktrees were not modified. Read-only Mihomo gitlink: `63bd52ec794b7051569b76ede2f6cdbf4c091fda`, `dns/dhcp.go::ResetConnection` iterates every DHCP-derived DNS child, while its `resolve` refreshes discovered servers. This is a Chimera async lifecycle safety hardening, not a proof of complete Mihomo runtime parity.
- First wrote two offline negative tests. `dhcp_reset_attempts_every_old_transport_even_when_first_fails` failed because the first `?` returned and the second child's reset was never called; `stalled_dhcp_reset_does_not_block_sibling_cleanup` failed because a never-resolving first child prevented a second cleanup attempt. Production now clears the cached clients, concurrently awaits each reset with a five-second per-child bound, sums successful counts using saturation, collects all child error identities, and returns an error if *any* cleanup failed. No DHCP query or real physical interface was used in the tests. Additional post-fix tests cover two failure messages and idempotent reset success.
- Discovery race: `DhcpClient::resolve` previously probed DHCP outside its cache lock and could commit the results *after* a concurrent network reset emptied the client cache. A negative test was written first (`dhcp_discovery_started_before_network_reset_must_not_reinstall_stale_dns`): initially red at compile time because no generation-checked install seam existed. Production tracks `Inner.generation`, incremented at reset; discovery snapshots generation before checking the lease and calls `install_discovered_clients`, which refuses a stale generation with `Interrupted`. Client construction now completes before taking the cache lock. A positive control verifies current-generation discovery and subsequent reset. These tests simulate the commit boundary, not real probe interleaving or physical NIC behavior.
- Current-source checks: 6 DHCP offline unit tests passed with `--no-default-features --features ring`; `cargo test -p clash-lib --lib --features 'tun ring' -- --test-threads=1` **1074 passed, 0 failed, 11 ignored**; DNS configuration integration **40/40 passed**; DNS S01/S02 **17/17 and 14/14 passed**. Strict core Clippy with `ring` only and strict all-targets Clippy with `tun,ring` both passed. `cargo fmt --all -- --check` and `git diff --check` passed.
- The legacy DNS golden suite still reports **12 passed, 1 failed** (`s00_respect_rules_and_legacy_proxy_modifier_are_preserved`, existing `dns.respect-rules` dedicated bootstrap policy disagreement). The DHCP reset/discovery change does not touch or fix this known compatibility conflict.
- Network-scope limitation: macOS TUN + Fake-IP continues to reject DHCP upstream configuration entirely. These changes mainly protect explicitly configured non-TUN/legacy DHCP discovery during network transitions; they do not add DHCP support in protected macOS TUN mode. In-flight calls that already hold clones of stale transport clients are not revoked by the generation guard. L2 independent reviewer, owner decision and explicitly authorized physical NIC/utun captures remain pending. No host DNS, routes, TUN, Network Extension, permissions, push, PR update or release were changed.
