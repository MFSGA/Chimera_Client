# macOS DNS Canary 离线出口审计（P1 测试工具）

> **能力边界**：这是用于审计**事先保存**的 macOS `tcpdump` 文本的只读分析器。它不抓包、不运行 `scutil`、不发起 DNS 请求、不打开 socket、不修改系统 DNS、TUN、路由或 Network Extension。任何输出都**不代表全系统 DNS 零泄漏认证**。

关联：[macOS TUN/DNS 迭代记录](20260928-tun-dns-macos.md) 和 [L2 独立审查要求](ai-development-governance.md)。

## 目标与威胁模型

此阶段专门收集“测试专用 canary QNAME 是否出现在物理接口的明文 DNS 查询（UDP/TCP 目标端口 53）上”的证据，同时观察它是否出现在对应 `utun` 上。

- **物理网卡发现 canary**：报告 `PHYSICAL_CANARY_PLAINTEXT_DNS_OBSERVED`。这能证明在所提供的抓包里看到该明文查询，但是否属于未授权泄漏仍要结合预期代理/DIRECT 策略判断。
- **物理网卡未发现 canary，utun 有 canary，清单与日志满足基本约束**：报告 `NO_PHYSICAL_CANARY_OBSERVED_IN_SUPPLIED_LOGS`。**仅指提供的文本中没有看到**，不证明接口覆盖充分、采集时间重叠、macOS resolver 优先级或零泄漏。
- **证据不足**：`NOT_VERIFIED`。例如缺少活动物理网卡或 utun 的日志、没有 canary 到达 utun、`scutil --dns` 快照缺失、存在未解码的 DNS 非空载荷、某份日志没有有效的 53 端口数据包行。
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

分析器只读取 manifest 同目录下的相对路径，拒绝 `..`、绝对路径、指向外部文件的符号链接、重复接口/文件、未知 manifest 字段和超大输入；每份抓包最大 128 MiB。重复运行时默认拒绝覆盖已有报告，显式指定 `--overwrite` 才可替换。输出 JSON 采用同目录临时文件原子落盘，文件权限为 0600；拒绝将报告路径设为 manifest、抓包或 resolver 快照。显式覆盖既有报告时也不会顺着符号链接修改其目标。抓包在分析期间发生变化会中止，而非生成不一致的 SHA-256。

## 独立授权测试 Mac：操作人员采集流程（未在本轮执行）

**前提：** 使用所有者明确批准的隔离测试机与专属 canary 域名；准备原网络配置的恢复记录；确保不会把个人查询或用户订阅写入公开日志。这些命令只是提供给受授权测试人员，代码工具不会自动调用它们。

1. **清点接口**。在独立测试机只读查看 `scutil --dns`、`ifconfig`、`route -n get default`，确定所有活跃物理接口（Wi-Fi、有线、蜂窝等）与 Chimera 当前的 `utun`。确认是否有其他 DNS Proxy/VPN 服务，记录服务作用域 resolver 优先级。**不得仅靠接口名字假定流量已受控。**
2. **启动相同时段的双边抓包**。每个受测物理接口与相关 `utun` 需要分别采集。示例命令中的 `en0` 和 `utun7` 仅为占位符，按测试机实际值替换，并在预定时间手动终止：

   ```sh
   # 以下命令仅供获得授权后在测试机手工执行；不要在日常宿主机自动执行
   sudo tcpdump -i en0 -p -nn -tttt -s0 \
     '(udp dst port 53 or tcp dst port 53)' > en0.txt

   sudo tcpdump -i utun7 -p -nn -tttt -s0 \
     '(udp dst port 53 or tcp dst port 53)' > utun7.txt
   ```

   **警告：** 原始 tcpdump 日志可能包含其他用户的 DNS 域名和 IP。应在无个人流量的隔离机器执行。报告默认**不回显其他域名或源/目标地址**，但这不等于原始日志无敏感信息。分析器要求 tcpdump 的单行文本解码格式，**不要使用可能让 DNS 包头和地址跨行输出的 `-vv` 模式**；如有非空 DNS 载荷无法解码，应标记 `NOT_VERIFIED` 并重采，而非判定零泄漏。

   为每个捕获进程手工记录开启和停止时的 UTC 时间（例如执行 `date -u '+%Y-%m-%dT%H:%M:%SZ'`）。不同接口必须存在共同的采集时间窗口；否则审计报告为 `NOT_VERIFIED`。这些时间是操作者填写的证据元数据，**并非分析器自动证明捕获过程真的覆盖了该时段**。

3. **记录系统 DNS 状态和受控 canary**。在捕获时段保存 `scutil --dns > scutil-dns.txt`（只读），由所有者控制专属测试域名并发起一次明确的系统 resolver 查询。可选使用 `dns-sd -G v4v6 <专属canary域名>`（需手动停止），它与直接使用 `dig @server` 测试上游不是同一种路径。对于强制 TCP 53、断线、切换 Wi-Fi、休眠唤醒等情境分别创建 case，不能把一个正常 A 查询的结果冒充所有场景通过。
4. **整理 manifest**。将抓包及快照保存在相同证据目录；例如：

   ```json
   {
     "schema_version": 1,
     "case_id": "wifi_up_ipv4_ipv6",
     "canary_qname": "unique-canary.your-controlled-test-domain.example",
     "expected_physical_interfaces": ["en0"],
     "expected_tun_interfaces": ["utun7"],
     "resolver_snapshot": "scutil-dns.txt",
     "captures": [
       {"role": "physical", "interface": "en0", "path": "en0.txt",
        "started_at_utc": "2026-11-06T15:00:00Z", "ended_at_utc": "2026-11-06T15:05:00Z"},
       {"role": "tun", "interface": "utun7", "path": "utun7.txt",
        "started_at_utc": "2026-11-06T15:00:30Z", "ended_at_utc": "2026-11-06T15:06:00Z"}
     ]
   }
   ```

   清单中的 `expected_physical_interfaces` 必须列出所有受测物理接口，未提交任何一个所列接口的日志即为 `NOT_VERIFIED`。macOS TUN 接口须以 `utun` 加数字命名；不能把 `utun` 或 `lo0` 错报为物理出口。每个接口需有有时区的 `started_at_utc` 与 `ended_at_utc`；任一缺失或窗口互不重叠也为 `NOT_VERIFIED`。但清单本身来自测试人员，并非分析器独立发现活动接口或采集窗口的证明。

5. **离线出报告**。这一步不需要管理员权限，也不发起任何网络请求：

   ```sh
   python3 tools/dns_canary_audit.py /path/to/evidence/manifest.json \
     --output /path/to/private/report.json
   ```

   输出 JSON 包含 `case_id`、`verdict`、`coverage_issues`、manifest SHA-256、声明的接口及公共 UTC 采集窗口、各抓包 SHA-256/字节数/解析到的数据包数、与 canary 匹配的 qtype/IPv4/IPv6/TCP/UDP/时间戳及原始行 SHA-256。默认不会在报告中包含源或目标 IP；仅需在本地审计时可显式选择 `--include-endpoints`，但须单独处理敏感数据。

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
