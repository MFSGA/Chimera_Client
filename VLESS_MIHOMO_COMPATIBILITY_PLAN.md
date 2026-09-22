# Chimera Client 对 Mihomo VLESS 出站完全兼容实施指南

> 基线日期：2026-09-19  
> 目标上游：MetaCubeX/mihomo `Meta` 分支的 `docs/config.yaml`  
> 当前项目：`/home/si/Desktop/mfsga/Chimera_Client`  
> 范围：优先完成 `proxies:` 下 `type: vless` 的客户端出站兼容。Mihomo 文档中的 VLESS inbound 不纳入本轮主线，放在最后单列。
>
> **状态说明（2026-09-20）**：本文前半部分保留最初的差距分析和实施历史。项目当前的支持边界、已完成能力和后续优先级以 **第 20 节** 为准；旧章节中已完成的 TODO 不再代表当前状态。

## 1. 目标定义

“兼容 Mihomo VLESS”不能只理解成 YAML 能被 `serde_yaml` 解析。

本项目真正要达到的目标应分成四层：

1. **配置兼容**
   - Mihomo `docs/config.yaml` 中 VLESS outbound 示例使用的字段可以被 Chimera 正确解析。
   - 字段名称、别名、标量/数组类型、默认值、互斥关系和错误行为尽量与 Mihomo 一致。
   - 对尚未实现运行时语义的字段，不能静默接受后忽略；要么实现，要么在转换阶段给出明确错误。

2. **转换兼容**
   - `OutboundVless` 能完整转换成清晰的运行时配置，而不是让 transport 在运行时猜测配置含义。
   - TLS、Reality、Vision、WS、gRPC、XHTTP 等能力应在 converter 阶段完成组合校验。

3. **线协议兼容**
   - 与 Mihomo/Xray 服务端建立连接时，VLESS 请求头、Vision、TLS、Reality、WebSocket、gRPC、XHTTP 等 on-wire 行为兼容。
   - 仅“成功构造 handler”不算完成。

4. **互操作兼容**
   - 对 Mihomo 文档中的代表性配置建立真实 E2E。
   - 至少验证 Xray 服务端；条件允许时再增加 Mihomo 自身或已知兼容服务端作为交叉基线。
   - 每一类 transport 都要覆盖成功路径和一个明确的错误路径。

因此，后续每个实现切片的 Definition of Done 应至少包含：

```text
配置能解析
+ converter 能校验
+ transport/runtime 行为存在
+ focused test
+ 与真实服务端互操作
```

## 2. 上游 VLESS 配置基线

Mihomo 当前 `docs/config.yaml` 的 VLESS outbound 覆盖以下主要形态：

| 形态 | 关键字段 |
| --- | --- |
| VLESS TCP | `network: tcp`、`servername`、TLS 校验类字段 |
| VLESS Vision | `flow: xtls-rprx-vision`、`tls: true` |
| VLESS Encryption | `encryption: ...`，可在 `tls: false` 下工作 |
| VLESS + Reality + Vision | `reality-opts` + `client-fingerprint` + Vision |
| VLESS + Reality + gRPC | `network: grpc` + `grpc-opts` + Reality |
| VLESS + WS | `network: ws` + `ws-opts` |
| VLESS + XHTTP | `network: xhttp` + `xhttp-opts`，并带独立的 ALPN、padding、placement、reuse、download-settings 等能力 |

基础层还涉及：

- `name`
- `type: vless`
- `server`
- `port`
- `uuid`
- `udp`
- `tls`
- `network`
- `flow`
- `encryption`
- `alpn`
- `servername`
- `skip-cert-verify`
- `name-cert-verify`
- `certificate`
- `private-key`
- `fingerprint`
- `client-fingerprint`
- `ech-opts`
- `shadow-tls-opts`
- `restls-opts`
- `jls-opts`
- `reality-opts`

注意：`Meta` 是移动分支。正式开始实现前，应把当时的 Mihomo commit SHA 记录进本文档，后续所有“完全兼容”均以该 SHA 为验收基线，不能长期只写“跟 Meta 最新版一致”。

## 3. 当前 Chimera 已有能力

当前代码已经具备一部分质量较高的 VLESS 基础能力。

### 3.1 已有配置字段

`clash-lib/src/config/internal/proxy.rs` 当前 `OutboundVless` 已包含：

- `uuid`
- `udp`
- `tls`
- `skip-cert-verify`
- `server-name` / `servername` alias
- `sni`
- `network`
- `xhttp-opts`
- `ws-opts`
- `reality-opts`
- `flow`
- `client-fingerprint`

### 3.2 已有运行时

当前 converter/runtime 已有：

- VLESS TCP
- 普通 TLS
- VLESS UDP datagram
- WebSocket
- Reality
- XTLS Vision framing
- Reality + Vision splice
- XHTTP：
  - `stream-one`
  - `stream-up`
  - `packet-up`
  - 单独 download endpoint
  - TLS/Reality download
  - 部分 XHTTP header / chunk 参数

### 3.3 可复用的 ref 实现

本地 `ref/` 对 VLESS 已经有：

- gRPC transport
- H2 transport
- 对应 VLESS converter 分支
- VLESS gRPC/H2 E2E 测试

因此，**gRPC 不应该重新设计**。后续应优先从当前 `ref/` 迁移，再做 Mihomo 配置层扩展。

## 4. 当前阻断级兼容差异

以下问题应优先解决，否则即便继续扩展 XHTTP，也无法声称兼容 Mihomo 配置。

### 4.1 `fingerprint` 与 `client-fingerprint` 被错误合并

当前：

```rust
#[serde(alias = "fingerprint")]
pub client_fingerprint: Option<String>,
```

这与 Mihomo 语义不兼容。

Mihomo 中：

- `fingerprint`：证书指纹校验，属于 TLS 证书验证语义。
- `client-fingerprint`：TLS ClientHello/uTLS 风格指纹，例如 chrome/firefox/safari/random/none。

这两个字段必须拆开。

建议：

```rust
pub fingerprint: Option<String>,
pub client_fingerprint: Option<String>,
```

并禁止继续把 `fingerprint` alias 到 `client_fingerprint`。

### 4.2 `client-fingerprint` 当前只是“解析了”，没有真正生效

当前 Reality ClientHello 基本是固定 Chrome 风格，普通 rustls TLS 也没有根据 `client-fingerprint` 做切换。

因此当前状态应定义为：

```text
client-fingerprint:
  parse = yes
  runtime semantics = no
```

完整兼容时必须明确决定：

- 普通 TLS 是否实现 Mihomo 允许的 fingerprint 集合。
- Reality 至少支持文档要求的 `chrome`，并对不支持的值明确报错。
- `random`、`none` 的行为必须定义。
- 在不能实现真正 uTLS parity 时，不要静默假装支持。

### 4.3 `flow` 的未知值目前会被静默忽略

`VlessStream::encode_request_addons()` 当前只有：

```text
xtls-rprx-vision -> 编码 Vision addon
其他 flow -> 空 addon
```

这会造成配置“解析成功但语义错误”。

应改为 converter 校验：

- `None` / 空字符串：普通 VLESS。
- `xtls-rprx-vision`：Vision。
- 其他值：在确认 Mihomo 支持列表前直接拒绝。

### 4.4 `network: grpc` 当前不支持

当前 `build_transport()` 仅接受：

- tcp
- ws
- xhttp

Mihomo 文档有完整的 VLESS Reality gRPC 示例。

这一项是高优先级缺口，而且本地 `ref/` 已有实现，可以作为最先补齐的 transport。

### 4.5 XHTTP `host` 类型与 Mihomo 示例不一致

当前：

```rust
pub host: Option<Vec<String>>
```

Mihomo XHTTP 示例：

```yaml
xhttp-opts:
  host: xxx.com
```

这是直接的 YAML schema 不兼容。

建议 XHTTP 独立使用标量：

```rust
pub host: Option<String>
```

不要因为 H2 的 host 是数组，就让 XHTTP 复用数组类型。

如果为了兼容旧 Chimera 配置需要同时接受数组，可用自定义 deserializer 接受：

- string
- one-element sequence

但运行时内部应规范化为单值，并明确多值如何处理；不要默认取第一个而无提示。

### 4.6 XHTTP `mode: auto` 当前固定映射为 `packet-up`

当前：

```text
auto -> PacketUp
```

Mihomo 的实际行为不是固定映射。不同安全层/HTTP 版本下，auto 会选择不同 transport 策略。

因此：

- 不要把 `auto` 当作配置 alias。
- 应保存 `Auto` 为独立 enum variant。
- 在连接阶段依据：
  - TLS / Reality
  - ALPN
  - endpoint/download-settings
  - 目标实现基线
  做最终 mode 决策。
- 必须为 auto 决策建立单测。

### 4.7 XHTTP 当前强绑定 HTTP/2

当前 XHTTP transport 使用 Hyper HTTP/2 handshake，TLS 也默认 ALPN=h2。

Mihomo 文档已经暴露：

- `alpn: [h2]`
- `alpn: [h3]`
- `alpn: [http/1.1]`

因此完整兼容至少需要三种 transport backend：

```text
HTTP/1.1
HTTP/2
HTTP/3
```

建议先把 XHTTP 的“协议逻辑”和“HTTP backend”解耦，再补 H1/H3。不要直接在当前 H2 文件里不断加条件分支。

## 5. TLS / Reality 层缺口

这一层应在 XHTTP 全量扩展之前完成，因为 TCP、gRPC、WS、XHTTP 都依赖它。

### 5.1 `alpn`

当前 `OutboundVless` 没有 top-level `alpn`。

应新增：

```rust
pub alpn: Option<Vec<String>>
```

优先级建议：

1. 用户显式 `alpn`
2. transport 默认值
3. TLS library 默认

并对 transport 做合法性校验。

例如：

- WS 默认 `http/1.1`
- gRPC 默认 `h2`
- XHTTP 默认按 Mihomo 基线
- Reality 不能继续永远写死 `["h2", "http/1.1"]`

### 5.2 mTLS：`certificate` + `private-key`

Mihomo VLESS 支持二者成对开启 mTLS。

项目已有 `common::tls::load_cert_and_key` 和 TLS client-auth 基础，但当前能力被 `anytls` feature 条件绑住，VLESS converter 也没有使用。

建议先做公共 TLS 重构：

```text
TLS client config
  ├── CA/root validation
  ├── skip-cert-verify
  ├── fingerprint pin
  ├── verification hostname
  ├── SNI
  ├── ALPN
  └── optional client certificate/key
```

该构造器不应属于 AnyTLS 专用能力。

校验：

- 只写 certificate -> error
- 只写 private-key -> error
- 两者同时 -> 加载 client auth
- inline PEM / path 都覆盖测试

### 5.3 `fingerprint` 证书 pinning

`DefaultTlsVerifier` 已具备 fingerprint 比对能力，但 VLESS 的 `TlsClient` 当前传的是 `None`。

因此这一项不是从零实现，而是要把参数贯穿：

```text
YAML
-> OutboundVless.fingerprint
-> TLS options
-> DefaultTlsVerifier::new(fingerprint, skip)
```

同时要确定 Mihomo 对输入 fingerprint 的格式规范，并做相同 normalization。

### 5.4 `name-cert-verify`

Mihomo 注释说明它只修改证书 DNSName 校验目标，不修改 SNI。

所以必须把：

- TCP 连接目标
- TLS SNI
- certificate verification name

拆成三个变量。

建议运行时模型显式表示：

```rust
TlsEndpoint {
    connect_host,
    sni,
    verify_name,
}
```

不能继续用一个 `server_name` 同时承担多个语义。

### 5.5 ECH

`ech-opts` 至少包括：

- `enable`
- `config`
- `query-server-name`

这是独立能力，建议放在 TLS 通用层而不是 VLESS 私有实现。

实现优先级低于普通 TLS/mTLS/Reality，但 schema 必须先设计好，避免后面再次改 `OutboundVless`。

### 5.6 ShadowTLS / Restls / JLS

Mihomo 当前 VLESS TCP 文档还暴露：

- `shadow-tls-opts`
- `restls-opts`
- `jls-opts`

这些不是普通 TLS 小参数，而是独立外层传输/伪装能力。

建议：

- 第一阶段先加入 config struct。
- converter 在 runtime 未实现时明确返回 unsupported。
- 后续每个 transport 单独实现，不要塞进 `TlsClient` 一个巨大的 enum。
- 优先抽象成：
  `SecurityLayer: Tls | Reality | ShadowTls | Restls | Jls`

## 6. Reality 兼容缺口

当前 Reality 已经能完成基础 X25519 public-key + short-id 握手，并能支持 Vision splice，这是很好的基础。

仍需补：

### 6.1 `support-x25519mlkem768`

Mihomo Reality 配置中包含：

```yaml
support-x25519mlkem768: false
```

当前 `OutboundTrojanRealityOpts` 只有：

- public-key
- short-id

应先增加字段，并在 runtime 未实现混合 KEM 前显式拒绝 `true`，不能忽略。

之后再做 ML-KEM-768 hybrid key share。

### 6.2 Reality 的 client fingerprint

当前 Reality ClientHello 是固定 Chrome 风格实现。

短期兼容策略：

- `client-fingerprint: chrome` -> 接受。
- 空值：
  - 根据 Mihomo 当前默认行为决定默认值。
- 其他值：
  - 尚未实现前明确报 unsupported。
- 不允许“配置 firefox，但实际发 Chrome”。

### 6.3 Reality ALPN

当前 Reality 内部默认 ALPN 是：

```text
h2
http/1.1
```

需要让 top-level `alpn` 可以传入 Reality ClientHello，否则 XHTTP/gRPC 等 transport 的显式 ALPN 无法真正控制握手。

## 7. WebSocket 兼容补齐

当前已有：

- path
- headers
- max-early-data
- early-data-header-name

还需要补 Mihomo 文档出现的：

- `v2ray-http-upgrade`
- `v2ray-http-upgrade-fast-open`

建议不要把 HTTP Upgrade 作为普通 WS bool 到处判断，而是让 WS transport 自己根据配置选择：

```text
RFC6455 WebSocket
或
V2Ray HTTP Upgrade
```

需要测试：

- 默认 WS
- HTTP Upgrade
- HTTP Upgrade fast-open
- TLS + SNI + WS Host 优先级

## 8. gRPC 兼容路线

这是建议最先落地的“新 transport”。

Mihomo 文档字段：

- `grpc-service-name`
- `grpc-user-agent`
- `ping-interval`
- `max-connections`
- `min-streams`
- `max-streams`

当前本地 `GrpcOpt` 只有：

```rust
grpc_service_name
```

### 8.1 第一切片：恢复 ref gRPC

从 `ref/` 迁移：

- transport/grpc
- converter branch
- feature/build 所需依赖
- 现有 gRPC E2E 测试

验收：

```bash
cargo test -p clash-lib <vless_grpc_config_test>
cargo check -p clash-lib
```

然后跑真实 Xray VLESS gRPC。

### 8.2 第二切片：Mihomo gRPC options

逐个补：

- user-agent
- ping interval
- connection/stream pool policy

连接池字段有互斥关系，应在 config conversion 阶段拒绝冲突，而不是运行后才处理。

## 9. VLESS Encryption

这是一个独立大功能，不应混入普通 VLESS framing PR。

Mihomo 文档提供的 `encryption` 已经包含：

- ML-KEM-768 + X25519 组合
- native/xorpub/random 外观
- 1-RTT / 0-RTT
- padding 参数
- 多组 key material 串联

当前 Chimera 没有对应字段和线协议。

建议拆成：

### 阶段 A：schema

新增：

```rust
pub encryption: Option<String>
```

定义默认语义：

- 缺省
- 空字符串
- `none`

要和 Mihomo 当前行为对齐。

在协议未实现前，如果 `encryption` 是非空/非 none，converter 明确报错。

### 阶段 B：parser

不要直接在 handler 中按 `split('.')` 临时解析。

新增独立类型，例如：

```rust
VlessEncryptionConfig
VlessEncryptionMode
VlessKemMaterial
VlessPaddingProfile
```

先完成：

- 字符串 grammar
- round-trip
- invalid cases
- padding range
- key material decode

### 阶段 C：crypto / handshake

独立模块，不和 `stream.rs` 的普通 VLESS header 混在一起。

要求：

- known-answer tests
- malformed peer input tests
- 0-RTT replay/状态约束测试
- interop test

由于这是密码协议，不应仅根据文档注释猜实现。开始该阶段前必须固定对应 Mihomo/Xray 源码基线并逐行核对 wire behavior。

## 10. XHTTP 是兼容工作的最大主体

当前 Chimera 已经具备不错的 H2 原型，但离 Mihomo 当前配置仍有显著距离。

### 10.1 应重构的配置模型

建议目标：

```rust
struct XhttpOpt {
    path: Option<String>,
    host: Option<String>,
    mode: Option<XhttpModeConfig>,
    headers: Option<HashMap<String, String>>,

    no_grpc_header: Option<bool>,

    x_padding_bytes: Option<RangeSpec>,
    x_padding_obfs_mode: Option<bool>,
    x_padding_key: Option<String>,
    x_padding_header: Option<String>,
    x_padding_placement: Option<XPaddingPlacement>,
    x_padding_method: Option<XPaddingMethod>,

    uplink_http_method: Option<HttpMethodConfig>,

    session_placement: Option<MetadataPlacement>,
    session_key: Option<String>,
    seq_placement: Option<MetadataPlacement>,
    seq_key: Option<String>,

    uplink_data_placement: Option<UplinkDataPlacement>,
    uplink_data_key: Option<String>,
    uplink_chunk_size: Option<RangeSpec>,

    sc_max_each_post_bytes: Option<RangeSpec>,
    sc_min_posts_interval_ms: Option<RangeSpec>,

    reuse_settings: Option<XmuxReuseSettings>,
    download_settings: Option<XhttpDownloadSettings>,
}
```

不要继续把这些字段放入松散的 `extra` 兼容桶作为最终架构。

可以保留 Xray/Chimera 历史 alias 作为输入兼容，但内部模型应规范化。

### 10.2 mode

必须保留：

- Auto
- StreamOne
- StreamUp
- PacketUp

`split` 如果继续支持，只能作为 Chimera legacy alias，并在文档中明确不是 Mihomo 正式值。

### 10.3 Metadata placement

Mihomo 文档已暴露：

- session-placement
- session-key
- seq-placement
- seq-key
- uplink-data-placement
- uplink-data-key
- uplink-chunk-size

需要建立统一 placement 引擎：

```text
path
query
cookie
header
```

不能分别在 stream-up/packet-up 里手写 URI。

建议新增：

```text
transport/xhttp/meta.rs
```

职责：

- normalize
- validation
- apply session
- apply seq
- apply uplink data

### 10.4 X-Padding

需要补：

- x-padding-bytes
- x-padding-obfs-mode
- x-padding-key
- x-padding-header
- x-padding-placement
- x-padding-method

当前只实现默认 Referer query padding 的一部分语义。

建议单独：

```text
transport/xhttp/padding.rs
```

覆盖：

- 默认模式的 wire 兼容
- repeat-x
- tokenish
- placement
- range sampling

所有随机行为测试必须支持 deterministic RNG 注入。

### 10.5 uplink HTTP method

文档允许：

- POST
- PUT
- PATCH
- DELETE

不要在 string 层直接传递；parse 成 enum，并规范化大写。

### 10.6 packet-up tuning

当前已有部分：

- sc-max-each-post-bytes
- sc-min-posts-interval-ms

但当前类型是单个整数，而 Mihomo/Xray 生态越来越多使用范围字符串。

建议抽象公共：

```rust
RangeSpec<T>
```

接受：

- 单值
- min-max

选择值时由 injectable RNG 决定。

### 10.7 reuse-settings / XMUX

Mihomo 当前 XHTTP 已暴露 reuse-settings：

- max-concurrency
- max-connections
- c-max-reuse-times
- h-max-request-times
- h-max-reusable-secs
- h-keep-alive-period

这意味着当前“一次 transport 创建一次 H2 conn”的模型最终要升级成 connection/session pool。

建议独立成：

```text
XhttpConnectionPool
XhttpReusableConnection
XhttpReusePolicy
```

并建立清晰语义：

- max-connections 与并发策略互斥/组合关系
- reuse count
- HTTP request count
- age based retirement
- keepalive

不要把这些状态放进 `Client::proxy_stream()` 的局部变量。

### 10.8 download-settings

Mihomo 当前 outbound 示例中的 `download-settings` 是“完整的另一侧 proxy endpoint + xhttp options”。

当前 Chimera 已有自己的：

- `extra.download-settings`
- 顶层 legacy `download-settings`
- `upload-settings` 扩展

但形状与 Mihomo 并不完全一致。

目标应改为：

```text
top-level VLESS
  ├─ uplink endpoint = proxy 根配置
  └─ xhttp.download-settings
       ├─ server/port
       ├─ TLS/Reality/security options
       ├─ ALPN
       ├─ servername
       ├─ fingerprint / client-fingerprint
       ├─ mTLS
       └─ nested xhttp path/host/headers/reuse
```

兼容策略：

- Mihomo 正式字段优先。
- 旧 Chimera `extra.download-settings` 作为 alias 读取。
- `upload-settings` 保留为 Chimera extension，但不能让它影响 Mihomo 配置语义。
- 内部全部转换成统一的 `XhttpEndpointConfig`。

### 10.9 H1/H2/H3 backend 解耦

建议目录最终变成：

```text
proxy/transport/xhttp/
  mod.rs
  config.rs
  meta.rs
  padding.rs
  session.rs
  pool.rs
  mode.rs
  backend/
    h1.rs
    h2.rs
    h3.rs
```

XHTTP 的 session/mode/padding/placement 不应绑定 Hyper H2。

## 11. 推荐实施顺序

### Slice 0：建立 Mihomo VLESS fixture 基线

新增：

```text
clash-lib/tests/data/mihomo-vless/
```

至少保存以下最小配置：

- tcp
- vision
- reality-vision
- reality-grpc
- ws
- xhttp
- vless-encryption

每个 fixture 都直接从当前锁定的 Mihomo config 语义转写。

此步骤只加 fixture/解析测试，不改变 runtime。

### Slice 1：修 schema 语义错误

完成：

- fingerprint 与 client-fingerprint 分离
- alpn
- encryption 字段
- certificate/private-key
- name-cert-verify
- Reality `support-x25519mlkem768`
- XHTTP host scalar compatibility
- flow validation

目标：让配置模型本身正确。

### Slice 2：统一 TLS config builder

完成：

- SNI / verify-name 分离
- ALPN
- cert fingerprint
- mTLS
- 对 VLESS/AnyTLS/Trojan 可复用

这一步是后续所有 transport 的基础。

### Slice 3：迁移 ref gRPC

完成基础 VLESS gRPC + TLS + Reality。

不要在同一切片实现 gRPC pool 参数。

### Slice 4：补 WS Mihomo 差异

完成 HTTP Upgrade 两字段，并建立真实 WS interop。

### Slice 5：Reality 参数对齐

完成：

- 显式 ALPN
- client fingerprint 约束
- support-x25519mlkem768 的行为边界

如果 hybrid KEM 较大，可先做到 `true` 明确报 unsupported，再开独立任务。

### Slice 6：XHTTP schema 规范化

只改：

- Config 类型
- aliases
- validation
- `Auto` enum
- endpoint normalization

不改 wire。

### Slice 7：XHTTP H2 wire parity

完成：

- placement engine
- x-padding
- method
- tuning
- download-settings
- Mihomo Auto/H2 行为

先把 H2 做到高质量 parity。

### Slice 8：XMUX/reuse

在 H2 稳定后加入连接池。

### Slice 9：XHTTP HTTP/1.1

单独 backend + interop。

### Slice 10：XHTTP HTTP/3

引入 QUIC/H3 前先确认：

- feature 边界
- crypto backend
- Reality 不支持组合
- Android socket protection / TUN 逃逸

### Slice 11：ECH / ShadowTLS / Restls / JLS

按独立 security layer 实现。

### Slice 12：VLESS Encryption

最后单独完成密码协议，不和 transport 重构混做。

## 12. 每步测试要求

### 12.1 配置测试

每个字段至少有：

- valid
- invalid
- default
- alias（如保留）
- conflicting combination

特别必须测：

- `fingerprint` 不再进入 client-fingerprint
- scalar xhttp host
- unknown flow reject
- unsupported network reject
- cert/key 必须成对
- Reality hybrid true 在未实现时必须报错

### 12.2 converter 测试

验证生成的 runtime options，而不是只检查 `is_ok()`。

例如：

- SNI
- verify name
- ALPN
- selected transport
- selected security layer
- Auto mode 的输入状态

### 12.3 wire 单测

对 WS/gRPC/XHTTP 的请求：

- URI
- method
- headers
- body placement
- padding
- session id
- sequence number
- content-type
- ALPN

应该能直接断言。

### 12.4 E2E

最低矩阵：

| 组合 | TCP | UDP |
| --- | --- | --- |
| VLESS TCP | 必须 | 必须 |
| VLESS TLS | 必须 | 必须 |
| Vision | 必须 | 按上游能力 |
| Reality Vision | 必须 | 按上游能力 |
| WS TLS | 必须 | 必须 |
| gRPC TLS | 必须 | 必须 |
| gRPC Reality | 必须 | 必须 |
| XHTTP H2 TLS | 必须 | 必须 |
| XHTTP H2 Reality | 必须 | 必须 |
| XHTTP split download | 必须 | 必须 |

XHTTP H1/H3 在对应 backend 落地后加入。

## 13. CI 建议

不要一开始把所有真实网络 E2E 塞进普通 CI。

建议三层：

### PR fast gate

```bash
cargo fmt --all -- --check
cargo clippy -p clash-lib --all-targets --all-features -- -D warnings
cargo test -p clash-lib <vless_unit_and_config_tests>
```

### Linux integration

Docker/Xray：

```text
vless tcp
vless ws
vless grpc
vless reality
vless xhttp h2
```

### Extended / scheduled

- H3
- ECH
- Reality hybrid KEM
- VLESS Encryption
- throughput
- Android/TUN socket protection 组合

## 14. 不建议的实现方式

### 不要只扩 `OutboundVless` struct

如果字段加完却继续不使用，会得到“配置兼容假象”。

### 不要把所有 TLS-like 功能塞进 `TlsClient`

Reality、ShadowTLS、Restls、JLS 应有独立 security layer。

### 不要继续扩大 `XhttpExtra`

`extra` 可以保留输入 alias，但不应该成为最终内部配置架构。

### 不要把 Auto 提前转换成 PacketUp

保留 Auto 语义到真正掌握 transport/security/ALPN 的层。

### 不要默默忽略 unsupported 字段

完整兼容的中间阶段宁可显式报：

```text
vless restls-opts is parsed but runtime support is not compiled
```

也不要让用户以为配置已经生效。

### 不要一次迁移整个 VLESS

遵循仓库的一步最多约 500 行增删原则。

每个切片必须能：

- 独立编译
- 独立测试
- 独立 review
- 明确对应一个兼容能力

## 15. 推荐的代码目标架构

最终可以朝以下方向整理：

```text
config/internal/proxy.rs
  OutboundVless
  VlessTlsOptions
  RealityOptions
  GrpcOptions
  WsOptions
  XhttpOptions
  VlessEncryptionOptions

proxy/converters/vless.rs
  validate_vless()
  build_security_layer()
  build_transport_layer()
  build_vless_protocol_options()

proxy/security/
  tls/
  reality/
  shadow_tls/
  restls/
  jls/

proxy/transport/
  ws/
  grpc/
  xhttp/
    backend/{h1,h2,h3}
    meta
    padding
    reuse
    session

proxy/vless/
  framing
  datagram
  vision
  encryption
```

不要求一次重构到这个形态，但新增功能应避免继续把所有逻辑堆进一个 converter。

## 16. 完全兼容验收清单

只有以下条件同时满足，才建议把“VLESS 与 Mihomo 完全兼容”标为完成：

| 能力 | 验收 |
| --- | --- |
| TCP | Mihomo 示例等价配置 E2E |
| TLS | SNI、ALPN、verify-name、skip、fingerprint、mTLS |
| Vision | framing + splice + interop |
| Reality | X25519、short-id、fingerprint、ALPN、hybrid 配置语义 |
| WS | 标准 WS + HTTP Upgrade |
| gRPC | 基础 + 文档中的 gRPC options |
| XHTTP | Auto/3 modes + H1/H2/H3 + placement + padding + reuse + split download |
| VLESS Encryption | parser + crypto + 0/1-RTT + interop |
| ECH | 文档字段 + live TLS |
| ShadowTLS | live interop |
| Restls | live interop |
| JLS | live interop |
| UDP | 各支持 transport 的真实 UDP |
| 错误行为 | unsupported/冲突配置不能静默降级 |
| CI | 稳定子集进入 PR gate，其余进入 integration/scheduled |

## 17. 建议马上开始的前三个任务

如果下一步直接进入实现，最合适的前三个最小任务是：

### Task VLESS-001：修正配置模型

只改配置层和测试：

- 分离 `fingerprint` / `client-fingerprint`
- 新增 `alpn`
- 新增 `encryption`
- 新增 `name-cert-verify`
- 新增 `certificate` / `private-key`
- Reality 新增 `support-x25519mlkem768`
- XHTTP host 接受 Mihomo 标量
- unknown flow validation

不要在这一任务实现新 transport。

### Task VLESS-002：统一 TLS options

把当前分散的 TLS 参数收敛到可被 VLESS 使用的公共构造器，接通：

- ALPN
- fingerprint
- verify-name
- mTLS

验证 VLESS TCP TLS。

### Task VLESS-003：恢复 gRPC

从 `ref/` 最小迁移 gRPC transport 和 VLESS converter，先支持：

- grpc-service-name
- TLS
- Reality

完成后再另开任务补 Mihomo gRPC pool 参数。

---

## 18. 结论

当前 Chimera 的 VLESS 已经不是“从零实现”状态。TCP、UDP、WS、Reality、Vision、XHTTP H2 三种 mode 都已有可利用的基础。

真正阻碍“完全兼容”的不是 VLESS framing 本身，而是：

1. 配置语义还没有严格对齐 Mihomo；
2. TLS / Reality 参数模型不够完整；
3. gRPC 丢失；
4. XHTTP 的 schema、Auto、H1/H3、placement、padding、reuse 尚未对齐；
5. VLESS Encryption 尚未实现；
6. 一部分字段目前存在“能解析但不生效”或“错误 alias”的情况。

因此最稳妥的路线不是继续单点往 XHTTP 填字段，而是：

```text
先修 schema
-> 再统一 TLS/Reality
-> 恢复 gRPC
-> 补 WS
-> 规范化 XHTTP config
-> 做 H2 完整 parity
-> 做 reuse
-> H1/H3
-> ECH/其他 security
-> 最后单独做 VLESS Encryption
```

这条路径能保持每一步可编译、可测试、可审查，也最符合当前 Chimera 仓库的迭代规范。

## 19. 2026-09-20 XHTTP 优先迭代记录

- 本轮以本地 `ref` `470bc5a4` 为参考；该基线尚未包含 XHTTP，因此没有直接迁移对应实现。
- 已完成一个配置模型切片：XHTTP 顶层、上传 endpoint、下载 endpoint 和嵌套 `xhttp-settings` 的 `host` 统一为单值字符串。
- 为兼容已有 Chimera 配置，仍接受单元素数组；多元素数组在配置解析阶段明确拒绝，不再在运行时隐式取第一个值。
- 验证：`cargo check -p clash-lib --no-default-features --features tls`、`cargo test -p clash-lib xhttp --lib`（112 passed）、`cargo test -p clash-lib xhttp --lib --features xhttp-h3`（129 passed）。
- 下一步继续优先处理 XHTTP 的 schema/wire parity，暂不转去实现 gRPC 或其他 VLESS 扩展。

## 20. 2026-09-20 当前支持边界与后续决策（权威状态）

本节取代前文旧 TODO 作为当前项目计划。前文继续保留，用于解释兼容工作为何这样演进。

当前目标不再定义为“无条件复制 Mihomo 的所有 VLESS 组合”，而是：

> **实现实际需要、可维护、可验证的 VLESS/Mihomo 兼容子集；对不计划实现的组合明确报错，不做静默降级。**

### 20.1 状态定义

| 状态 | 含义 |
| --- | --- |
| ✅ 支持 | 当前项目目标内，已有 runtime，并有 focused test 或更高等级验证 |
| 🚫 有意不支持 | 明确作为项目边界，不应继续当作 TODO；配置必须清楚报错 |
| 🟡 可选后续 | 只有确认真实节点/用户需要时才实现 |
| 🧪 需要加强验证 | 功能已有，不优先继续加 feature，优先补真实互操作/CI |

### 20.2 VLESS 总体能力矩阵

| 能力 | 当前决策 | 说明 |
| --- | --- | --- |
| VLESS TCP / UDP | ✅ | 基础 runtime 已存在 |
| 普通 TLS | ✅ | 包含 ALPN、证书校验相关配置 |
| mTLS | ✅ | `certificate` + `private-key` |
| 证书 fingerprint pinning | ✅ | 与 `client-fingerprint` 分离 |
| `name-cert-verify` | ✅ | 与 SNI 语义分离 |
| Reality | ✅ | 包含 Vision、gRPC、XHTTP TCP-based 路径 |
| Reality X25519MLKEM768 | ✅ | 已有 hybrid interop harness |
| XTLS Vision | ✅ | 包含 Reality + Vision |
| VLESS Encryption | ✅ | native/xorpub/random，1-RTT/0-RTT，含 UDP framing |
| WebSocket | ✅ | 包含 path/header early data |
| gRPC | ✅ | runtime + 配置校验 |
| ShadowTLS v1 | ✅ | TLS 1.2 camouflage handshake 后转 raw stream |
| ShadowTLS v2 | ✅ | 默认版本；首个 app-data 带 challenge response |
| ShadowTLS v3 | ✅ | authenticated stream runtime |
| explicit ECH config | ✅ | 普通 TLS 与 XHTTP endpoint 支持 |
| ECH DNS discovery | 🚫 | **当前 scope 明确不支持**；ECH 仅支持显式 `ech-opts.config`，不做自动 HTTPS/SVCB discovery |
| Restls | 🚫 | **当前 scope 明确不支持**；schema 可识别但 runtime 必须继续显式报错 |
| JLS | 🚫 | **当前 scope 明确不支持**；schema 可识别但 runtime 必须继续显式报错 |
| 非 Reality `client-fingerprint` / uTLS | 🚫 | **项目明确不支持**；不引入新的 browser-TLS/uTLS stack |
| Reality 非 Chrome client fingerprint | 🚫 | 当前 wire 目标固定为 Chrome-compatible 行为；其他值明确拒绝 |

### 20.3 XHTTP 当前完成定义

XHTTP 从现在起视为**主功能完成**，不再为了覆盖每个理论组合无限扩展。

| XHTTP 能力 | HTTP/1.1 | HTTP/2 | HTTP/3 |
| --- | ---: | ---: | ---: |
| `packet-up` | ✅ | ✅ | ✅ |
| `stream-up` | 🚫 | ✅ | ✅ |
| `stream-one` | 🚫 | ✅ | ✅ |
| standard TLS | ✅ | ✅ | ✅ |
| Reality | ✅ | ✅ | 🚫 |
| explicit ECH | ✅ | ✅ | ✅ |
| upload/download split endpoint | 基础支持 | ✅ | ✅（split modes） |
| upload reuse / XMUX | 🚫 | ✅ | ✅ |
| download reuse | 🚫 | ✅ | ✅ |
| H3 keepalive | N/A | N/A | ✅ |
| H3 `stream-one` + separate `download-settings` | N/A | N/A | 🚫 |

#### 有意不支持的 XHTTP 组合

以下项目**不是后续 TODO**：

1. **HTTP/3 + Reality**：H3 backend 保持标准 QUIC/TLS；converter 必须继续明确拒绝 Reality，不做 fallback。
2. **XHTTP standard TLS + browser `client-fingerprint`**：属于全项目 uTLS/browser ClientHello 模拟能力，项目决定不实现。
3. **HTTP/1.1 advanced reuse / XMUX / upload-settings**：H1 保持简单可靠的 packet-up backend，高级 multiplex/reuse 由 H2/H3 承担。
4. **HTTP/3 `stream-one` + separate download endpoint**：`stream-one` 本身是一条 bidirectional request/response stream，不创造额外 split 语义。

这些限制必须保留显式错误信息和 regression tests。

### 20.4 XHTTP 下一阶段不是继续加 feature，而是验证

优先建立真实服务端 interoperability matrix，至少覆盖：H2+TLS、H2+Reality、H3+TLS、H3 stream-up、H3 packet-up、H3 split upload/download、H2/H3 connection reuse，以及可控 endpoint 下的 ECH 握手路径。

对有意不支持的组合保留 negative tests；CI 继续覆盖 standard、`xhttp-h3,tls,aws-lc-rs,port`、Reality 和 no-default-features capability matrix。

### 20.5 后续项目优先级

```text
P0  冻结 XHTTP feature scope
    -> 补真实互操作矩阵和 CI
    -> 清理/更新兼容文档

P1  冻结 VLESS feature scope
    -> Restls / JLS 保持显式 unsupported
    -> ECH 只支持 explicit config，不做 DNS discovery
    -> uTLS / browser client-fingerprint 保持 out of scope

P2  其余工程质量
    -> workspace / feature matrix
    -> lifecycle / cancellation
    -> 长期维护测试
```

### 20.6 当前不做的事项

- uTLS / browser ClientHello fingerprint 模拟；
- 为 H3 强行实现 Reality；
- 为 H1 复制 H2/H3 的完整 XMUX/reuse 模型；
- 为 H3 stream-one 发明 split download 行为；
- 仅为了“字段看起来全部支持”而接受没有 runtime 语义的配置；
- Restls runtime；
- JLS runtime；
- ECH HTTPS/SVCB DNS discovery。

### 20.7 当前 Definition of Done

一个支持能力必须满足：

```text
schema / alias 正确
+ converter 明确校验组合
+ runtime 真正实现
+ focused positive test
+ unsupported combination 有 negative test
+ 关键 wire feature 有真实服务端 interoperability
+ feature build / clippy 不引入 warning
```

对于明确标记为 🚫 的能力，Definition of Done 是：

```text
配置不会被静默忽略
+ 错误信息明确
+ regression test 固定该行为
```

这就是当前 Chimera VLESS 兼容工作的正式边界。

### 20.8 WireGuard feature freeze（权威状态）

WireGuard 采用与 VLESS/XHTTP 相同的原则：**冻结已验证的单 peer 标准 WireGuard 能力，不为追求 Mihomo 字段全集继续扩展协议面。**

当前正式支持：

- single-peer standard WireGuard；
- IPv4 / IPv6 tunnel addresses；
- TCP / UDP；
- private/public key 与 optional PSK；
- canonical `reserved`（3-byte array / base64），包含 WARP-style reserved bytes；
- `persistent-keepalive`；
- `allowed-ips` 入站/出站路由约束；
- MTU，默认与 Mihomo 对齐为 1408；
- tunnel remote DNS；
- `dialer-proxy` / outer UDP connector chaining；
- network-change reset：丢弃 cached tunnel，并在下一次连接时重新建立；
- `ring` / `aws-lc-rs` provider builds；
- real Docker WireGuard encrypted DNS-over-UDP interoperability test。

以下能力从现在起为 **🚫 有意不支持，不是 TODO**：

1. **multi-peer `peers`**
   - 当前 runtime 明确保持一个 peer / 一个 `Tunn` / 一个 endpoint 模型。
   - 不实现 longest-prefix peer selection、per-peer handshake state 或 per-peer endpoint lifecycle。

2. **`ip-stack`**
   - Chimera 使用自己的 userspace IP stack。
   - 不复制 Mihomo 的 gVisor/MIPS stack selector 与 congestion-controller 语义。

3. **`amnezia-wg-option` / AmneziaWG**
   - 不把 AmneziaWG wire obfuscation 扩展塞进标准 WireGuard backend。
   - 如果未来产品需求发生变化，应作为独立 protocol/backend proposal 重新评审，而不是普通配置字段补丁。

WireGuard unsupported 配置必须：

```text
配置阶段明确报错
+ 不静默忽略
+ regression test 固定错误行为
```

### 20.9 Feature freeze 变更规则

VLESS/XHTTP 与 WireGuard 的上述 scope 视为**冻结**。未来只有满足以下条件之一才重新打开 feature 讨论：

- 有真实用户/节点配置无法使用；
- 有明确 interoperability blocker；
- 上游协议变化使当前已支持路径失效；
- 项目 owner 明确决定扩展产品 scope。

以下理由单独不足以重新打开 feature：

- Mihomo 文档新增了字段；
- 为了达到“字段 100%”；
- 某个理论组合可以被实现；
- 仅为了减少 unsupported error 数量。

冻结后的默认工程优先级是：

```text
correctness
> lifecycle / network reset
> interoperability
> CI / false-positive elimination
> performance / maintainability
> new protocol surface
```
