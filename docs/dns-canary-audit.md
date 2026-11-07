# macOS DNS Canary 离线出口审计（P1 测试工具）

> **能力边界**：这是用于审计**事先保存**的 macOS `tcpdump` 文本的只读分析器。它不抓包、不运行 `scutil`、不发起 DNS 请求、不打开 socket、不修改系统 DNS、TUN、路由或 Network Extension。任何输出都**不代表全系统 DNS 零泄漏认证**。

关联：[macOS TUN/DNS 迭代记录](20260928-tun-dns-macos.md) 和 [L2 独立审查要求](ai-development-governance.md)。

## 目标与威胁模型

此阶段专门收集“测试专用 canary QNAME 是否出现在物理接口的明文 DNS 查询（UDP/TCP 目标端口 53）上”的证据，同时观察它是否出现在对应 `utun` 上。

- **物理网卡发现 canary**：报告 `PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED`。这能证明在所提供的抓包里看到该明文查询，但是否属于未授权泄漏仍要结合预期代理/DIRECT 策略判断。
- **物理网卡未发现 canary、utun 在公共采集时段且本次 canary 刺激发出后的合理时间内有 canary，物理网卡同一时段存在端口 53 报文，且清单、日志与时间戳基本一致**：报告 `NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS`。**仅指提供的文本中没有看到**，不证明接口覆盖充分、OS 时钟准确、macOS resolver 优先级或零泄漏。
- **证据不足**：`NOT_VERIFIED`。例如缺少活动物理网卡或 utun 的日志、没有 canary 在公共时段和本次刺激时间之后到达 utun、没有记录刺激时间或共同捕获窗口不足以覆盖整个观察期限、未提供 tcpdump 时间戳的 UTC 偏移、数据包时间戳与声明的采集窗口不符、`scutil --dns` 快照缺失或记录时间不在公共窗口内、快照没有基本的 resolver/nameserver 行、tcpdump 退出统计缺失或显示丢包/记录数不匹配、存在未解码的 DNS 非空载荷，或某份日志没有有效的 53 端口数据包行。
- **始终**输出 `system_zero_leak_verified: false`。DoH/DoT/DoQ、mDNS、服务专属 resolver、DNS Proxy Extension ownership、浏览器自己的 DNS、未抓取网卡、TCP 重组失败和真实代理互操作均不在这项离线验证范围内。

## 本地零网络测试（无需 macOS 特权）

Python 3.9+ 标准库，无第三方依赖：

```sh
python3 -m unittest discover -s tools/tests -p 'test_dns_canary_audit.py' -v

# 完全虚构的示例数据；不会触碰真实网络
python3 tools/dns_canary_audit.py \
  tools/examples/dns_canary/manifest.json \
  --output /tmp/chimera-canary-example.json
```

示例 `manifest.json` 中声明 `en0` 是物理网卡、`utun7` 是 TUN。二者的测试 IP 都来自文档保留地址空间，`scutil-dns.txt` 也明确标注为 **synthetic**；绝不能将样例报告当作实机测试结果。

此外，`tools/examples/dns_canary/manifest-leak.json` 模拟物理网卡出现 canary（退出码 3），`manifest-incomplete.json` 模拟第二个活动物理接口 `en1` 缺失（退出码 4）。三个夹具的可复现结果都由离线单测验证，绝非真实网络采集。

分析器只读取 manifest 同目录下的相对路径，拒绝 `..`、绝对路径、指向外部文件的符号链接、重复接口/文件/统计文件（含指向同一 inode 的硬链接）、未知 manifest 字段和超大输入；如果不同接口的抓包内容 SHA-256 **完全相同**，阴性结论降级为 `NOT_VERIFIED`，避免把同一日志复制成两份后冒充多网卡覆盖（即使确实发生相同的广播报文，也需要重新采集或人工复核）。manifest 最大 256 KiB，每份抓包最大 128 MiB，`scutil` 快照最大 4 MiB，单份 tcpdump 统计最大 64 KiB。必须为各抓包给出 `packet_time_utc_offset`（例如 PST 使用 `-08:00`）；缺少时可报告观察到的外发，但**不能生成阴性结论**。重复运行时默认拒绝覆盖已有报告，显式指定 `--overwrite` 才可替换。输出 JSON 采用同目录临时文件原子落盘，文件权限为 0600；拒绝将报告路径设为 manifest、抓包或 resolver 快照。显式覆盖既有报告时也不会顺着符号链接修改其目标。抓包在分析期间发生变化会中止，而非生成不一致的 SHA-256。

## 独立授权测试 Mac：操作人员采集流程（未在本轮执行）

**前提：** 使用所有者明确批准的隔离测试机与专属 canary 域名；准备原网络配置的恢复记录；确保不会把个人查询或用户订阅写入公开日志。这些命令只是提供给受授权测试人员，代码工具不会自动调用它们。

1. **清点接口**。在独立测试机只读查看 `scutil --dns`、`ifconfig`、`route -n get default`，确定所有活跃物理接口（Wi-Fi、有线、蜂窝等）与 Chimera 当前的 `utun`。确认是否有其他 DNS Proxy/VPN 服务，记录服务作用域 resolver 优先级。**不得仅靠接口名字假定流量已受控。**
2. **启动相同时段的双边抓包**。每个受测物理接口与相关 `utun` 需要分别采集。示例命令中的 `en0` 和 `utun7` 仅为占位符，按测试机实际值替换，并在预定时间手动终止：

   ```sh
   # 以下命令仅供获得授权后在测试机手工执行；不要在日常宿主机自动执行
   sudo tcpdump -i en0 -p -nn -tttt -s0 \
     '(udp dst port 53 or tcp dst port 53)' > en0.txt 2> en0.stats.txt

   sudo tcpdump -i utun7 -p -nn -tttt -s0 \
     '(udp dst port 53 or tcp dst port 53)' > utun7.txt 2> utun7.stats.txt
   ```

   **警告：** 原始 tcpdump 日志可能包含其他用户的 DNS 域名和 IP。应在无个人流量的隔离机器执行。报告默认**不回显其他域名或源/目标地址**，但这不等于原始日志无敏感信息。分析器要求 tcpdump 的单行文本解码格式，**不要使用可能让 DNS 包头和地址跨行输出的 `-vv` 模式**；如有非空 DNS 载荷无法解码，应标记 `NOT_VERIFIED` 并重采，而非判定零泄漏。务必用 Ctrl-C/正常终止结束每个 `tcpdump`，让 stderr 保留 `tcpdump: listening on en0, ...`（替换为各接口真实名称）的**启动行**以及最终 `N packets captured`、`0 packets dropped by kernel`（部分系统还提供 `dropped by interface`）。如果无法从该 stderr 确认对应接口、缺少统计或统计与 stdout 解析包数不匹配，均判为证据不足。启动行仍是用户提供的文本，工具无法独立验证它来自真实系统进程。

   为每个捕获进程手工记录开启和停止时的 UTC 时间（例如执行 `date -u '+%Y-%m-%dT%H:%M:%SZ'`），并记录抓包期间当前系统的 UTC 偏移（例如通过只读 `date '+%z'` 确认后填写 `-08:00`）。不同接口必须存在共同的采集窗口；工具还会尝试将 `tcpdump -tttt` 的本地时间戳转为 UTC，核对数据包自身是否落在各自声明窗口、utun canary 是否在公共时段内出现。**时钟同步、操作者时间声明及固定 UTC 偏移都不是独立证明**；跨夏令时/DST 跳变的采集必须拆成不同 case，不能只给整段一个偏移。

3. **记录系统 DNS 状态和受控 canary**。在捕获时段保存 `scutil --dns > scutil-dns.txt`（只读），并记录该快照采集时的 UTC 时间（对应 manifest 的 `resolver_snapshot_recorded_at_utc`）。工具只核对独立一行的 `DNS configuration` 标题、`resolver #` 与 `nameserver[0]` 等基本文本结构及时间窗口；报告仅显示 resolver/nameserver 数量，不输出其具体 IP。**这种形状检查不证明配置是操作系统的真实快照，更不证明 service-scoped DNS 已被 Chimera 接管。** 工具还会识别 `DNS configuration (for scoped queries)` 区块或 resolver 上的 `flags : Scoped`，统计接口为 `en0` 等非 utun/loopback 的 scoped resolver，并添加 `review_flags: ["physical_scoped_dns_resolver_present"]` 供人工核对；接口名称缺失时标记 `scoped_resolver_interface_unknown`。**这些均是风险提示，不是实际物理出口 DNS 查询的证据，也不会凭该提示改变 canary 判定。** 由所有者控制每次测试**唯一**的专属 canary 域名，先记录 `canary_stimulus_at_utc` 的准确 UTC 时间，再人工发起系统 resolver 查询；`canary_observation_deadline_seconds` 默认 30，可在 1–300 秒内调整，但所有受测网卡的共同捕获窗口必须完整包含 `[刺激时间, 截止时间]`。可选使用 `dns-sd -G v4v6 <专属canary域名>`（需手动停止），它与直接使用 `dig @server` 测试上游不是同一种路径。缓存命中可能导致没有真实 DNS 包，此时应为 `NOT_VERIFIED` 而不是把先前采集的查询冒充本次请求。对于强制 TCP 53、断线、切换 Wi-Fi、休眠唤醒等情境分别创建 case，不能把一个正常 A 查询的结果冒充所有场景通过。
4. **整理 manifest**。将抓包及快照保存在相同证据目录；例如：

   ```json
   {
     "schema_version": 1,
     "case_id": "wifi_up_ipv4_ipv6",
     "canary_qname": "unique-canary.your-controlled-test-domain.example",
     "canary_stimulus_at_utc": "2026-11-06T15:00:00Z",
     "canary_observation_deadline_seconds": 30,
     "expected_physical_interfaces": ["en0"],
     "expected_tun_interfaces": ["utun7"],
     "resolver_snapshot": "scutil-dns.txt",
     "resolver_snapshot_recorded_at_utc": "2026-11-06T15:00:20Z",
     "captures": [
       {"role": "physical", "interface": "en0", "path": "en0.txt",
        "tcpdump_stats_path": "en0.stats.txt",
        "started_at_utc": "2026-11-06T15:00:00Z", "ended_at_utc": "2026-11-06T15:05:00Z",
        "packet_time_utc_offset": "-08:00"},
       {"role": "tun", "interface": "utun7", "path": "utun7.txt",
        "tcpdump_stats_path": "utun7.stats.txt",
        "started_at_utc": "2026-11-06T15:00:00Z", "ended_at_utc": "2026-11-06T15:06:00Z",
        "packet_time_utc_offset": "-08:00"}
     ]
   }
   ```

   清单中的 `expected_physical_interfaces` 必须列出所有受测物理接口，未提交任何一个所列接口的日志即为 `NOT_VERIFIED`。每个接口必须单独保存 `tcpdump_stats_path`；内核或接口丢包、统计不完整及 `captured` 与已解析数据包数不一致时，阴性结果一律降级。缺少 canary 刺激时间、utun canary 早于该刺激，或共同捕获窗口没覆盖整段观察期限，都不得输出阴性结论。`resolver_snapshot_recorded_at_utc` 缺失或不落在公共窗口内，同样为 `NOT_VERIFIED`。macOS TUN 接口须以 `utun` 加数字命名；不能把 `utun` 或 `lo0` 错报为物理出口。每个接口需有有时区的 `started_at_utc` 与 `ended_at_utc`，以及格式为 `±HH:MM` 的 `packet_time_utc_offset`；偏移缺失、时间戳无法换算或日志报文落在声明窗口之外时，不得将“物理接口未观察到 canary”视为通过。但清单与系统时间都来自操作者，并非分析器独立发现活动接口、时钟或抓包持续性的证明。

5. **离线出报告**。这一步不需要管理员权限，也不发起任何网络请求：

   ```sh
   python3 tools/dns_canary_audit.py /path/to/evidence/manifest.json \
     --output /path/to/private/report.json
   ```

   输出 JSON 包含 `case_id`、`verdict`、`coverage_issues`、供人工复核的 `review_flags`、canary 刺激与观察期限、刺激后观察到的 canary 事件计数、manifest SHA-256、声明的接口及公共 UTC 采集窗口、`scutil` 快照结构数量/作用域 resolver 数量和快照时间、各抓包 SHA-256/字节数/解析到的数据包数与对应 tcpdump 统计的 SHA-256/丢包计数、包时间戳的 UTC 归一化与窗口内事件计数，以及与 canary 匹配的 qtype/IPv4/IPv6/TCP/UDP/时间戳及原始行 SHA-256。默认不会在报告中包含源或目标 IP；仅需在本地审计时可显式选择 `--include-endpoints`，但须单独处理敏感数据。

## 退出码和合并验收

| 退出码 | 审计结果 | 应采取的行动 |
| --- | --- | --- |
| `0` | `NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS` | 仅表示提交的文本中未观察到物理网卡 canary；继续人工核实覆盖、时间窗口、resolver ownership |
| `3` | `PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED` | 保存物理出口证据，对照预期路由和 DNS 策略评估是否构成泄漏；禁止标绿 |
| `4` | `NOT_VERIFIED` | 缺少数据或无法解码，不得判为通过；补充抓包/快照与测试步骤 |
| `2` | manifest / 输入文件 / 输出路径错误 | 修正证据数据，重跑离线解析 |

任何结果中的 `system_zero_leak_verified` 都是 `false`。只有独立受权测试完成多场景采集、系统 resolver ownership、DNS Proxy（若部署）、NIC/utun 双面时序及失败关闭证据后，才能考虑形成更高等级的系统级结论。**本次工具与夹具没有实际执行这些系统操作，也没有证明 macOS 全系统零泄漏。**

## 后续验收矩阵（目前均未进行实机验证）

| 场景 | 受控 canary 查询 | 必备数据 |
| --- | --- | --- |
| 正常 Wi-Fi + TUN | 独立 A、AAAA、HTTPS/TXT 请求 | 全部活跃物理接口和 utun 同步捕获、scutil resolver 状态 |
| TCP 53 fallback | 模拟 UDP 截断后 TCP 重试或受控 TCP 查询 | TCP segment 解码/重组证据；未解码非空 DNS 载荷必须标未验证 |
| Wi-Fi ↔ 有线 / 网络服务顺序变化 | 每次切换用不同的专属 canary | 前后 `scutil --dns` 和每个物理 NIC + utun 的采集窗口 |
| 休眠恢复 / 代理 DNS 故障 | 恢复后及失败场景分别产生独立 canary | 预期失败关闭行为与物理出口未授权查询证据 |
| TUN / DNS Proxy 不可用 | 受保护查询必须受控失败而非转系统 DNS | 启停时序、错误日志、所有活动物理接口捕获与 ownership 记录 |
| IPv6 / 自定义安全 DNS | 单独探测对应服务与加密 DNS | 本工具只认识明文端口 53；加密 DNS 需要其他有授权的证据链 |

## 数据保留和回滚

分析器不安装代理、系统扩展或服务，回滚只需删除此测试工具和报告。原始抓包包含潜在隐私数据：最小化采集时长，按测试机组织的数据保留策略管理并及时删除；不要将原始 `tcpdump`、真实私有 `scutil --dns` 快照、订阅或真实 QNAME 直接上传公开 PR。输出结果是**一份经用户控制证据推导的离线报告**，不是独立、完整的系统网络审计。

## 离线多场景汇总（`dns_canary_matrix.py`）

系统级 DNS 验收不能只提交一次普通 Wi-Fi 查询。新增 **只读** 多场景汇总入口，对每个 case 的 manifest、原始抓包及 tcpdump 统计重新运行单场景审核，并汇总输入 SHA-256、缺失场景、人工风险标记和结果计数。每个 case 还输出刺激后 canary 数量及按 **IPv4/IPv6、UDP/TCP、DNS QTYPE** 分组的计数，方便核查具体覆盖；不会复制原始 QNAME、DNS 服务器或网络 IP 到矩阵报告。

```sh
python3 -m unittest discover -s tools/tests -p 'test_dns_canary_*.py' -q

# 预先准备的纯虚构例子：故意只提交 1 个 case，因此退出码应为 4
python3 tools/dns_canary_matrix.py tools/examples/dns_canary/matrix-incomplete.json

# 真正离线汇总、生成权限 0600 的 JSON（须传入由测试人员准备的完整矩阵）
python3 tools/dns_canary_matrix.py /path/to/private/matrix.json \
  --output /path/to/private/summary.json
```

矩阵示例结构：

```json
{
  "schema_version": 1,
  "matrix_id": "macos_egress_run_001",
  "profile": "macos_dns_egress_v1",
  "required_cases": [
    "wifi_a_aaaa", "tcp_53", "ipv6", "network_change",
    "sleep_resume", "dns_upstream_failure", "tun_or_dns_proxy_unavailable"
  ],
  "cases": [
    {"case_id": "wifi_a_aaaa", "manifest": "wifi_a_aaaa/manifest.json"}
  ]
}
```

其中 `cases[]` 每个条目的 `case_id` 必须与对应子目录里单场景 `manifest.json` 的 `case_id` 完全一致。路径均相对矩阵 JSON 所在目录，拒绝外部符号链接、路径穿越、重复 case / 重复底层 manifest。这里的例子特意缺少 6 个实际场景，因此**不是完整验收结果**。

`profile: macos_dns_egress_v1` 是固定的**最低场景清单**：正常 Wi-Fi A/AAAA、TCP 53、IPv6、网络切换、睡眠恢复、DNS 上游故障和 TUN/DNS Proxy 不可用。缺任一场景即 `NOT_VERIFIED`，即使操作人员将 `required_cases` 自行缩减也不能跳过。`profile` 可省略，表示仅按操作人员提供的 `required_cases` 比对——这样的汇总只代表**自定义场景集合**，不能称作内置 macOS 基线验收。未知 profile 被拒绝。

为降低复制旧证据冒充多场景的风险，内置 profile 还检查不同 case 是否重复使用同一 canary QNAME、刺激 UTC 时间戳或完全相同的抓包文件 SHA-256；同时核查 `wifi_a_aaaa` 在 utun 是否实际观测 A 与 AAAA、`tcp_53` 是否观测 TCP 查询，以及 `ipv6` 是否观测经 IPv6 传输的 AAAA 查询。缺少这些内容时输出 `profile_evidence_issues` 并判为 `NOT_VERIFIED`。这些规则不足以排除其他复制、伪造、时间偏差或场景标签错误，**每一场景是否真实执行仍需独立人工和 OS 证据**。切网、休眠和故障用例不会由这个工具自动触发。

整组矩阵的退出码与单 case 一致：`0` 仅代表所列及内置要求的 case 均未在所提供日志中观察到物理 canary；`3` 表示至少一个 case 观察到物理 canary（即使其他 case 不完整，也优先保留正向证据）；`4` 表示缺少 case 或任一 case 不可验证；`2` 表示输入错误或输出文件无法安全创建。`system_zero_leak_verified` 永远为 `false`，需要实际 macOS service-scoped resolver ownership、NIC/utun 同步抓包、DoH/DoT 等额外独立验证。

与单 case 一样，矩阵报告采用私有原子写入、默认禁止覆盖；显式 `--overwrite` 不会顺着符号链接写入目标。禁止用矩阵输出文件路径覆盖它本身、任何子 case manifest、tcpdump 日志、统计 stderr 或 `scutil` 快照；保存前再次逐项比对证据的 SHA-256，以免使用分析后被篡改的材料。
