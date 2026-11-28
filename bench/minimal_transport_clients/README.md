# Minimal Chimera transport clients

This directory has three benchmark client shapes. Runtime and direct-handler
clients call the production HY2 or VLESS/REALITY handler. The standalone HY2
and REALITY clients call the extracted protocol cores also used by the
production handlers.

- `chimera-hy2-perf-client` and `chimera-reality-perf-client` replace the
  general CLI frontend but start the normal `clash-lib` runtime.
- `chimera-hy2-core-perf-client` and `chimera-reality-core-perf-client` call a
  feature-gated direct-handler API and a small SOCKS5 bridge. They skip
  `start_scaffold`, DNS service setup, rules, routing, and Controller startup.
- `chimera-hy2-protocol-perf-client` and
  `chimera-reality-protocol-perf-client` depend directly on
  `chimera-hysteria2-core` and `chimera-reality-core`; neither binary depends
  on `clash-lib`. They use a small loopback-only SOCKS5 bridge and leave
  application DNS, routing, and system integration out of the measured path.
  HY2 shares one authenticated native QUIC connection across TCP streams by
  default; `--quic-connections N` creates N authenticated QUIC connections and
  assigns accepted SOCKS streams round-robin. `--endpoint-mode shared` (the
  default) keeps those connections on one Quinn Endpoint and UDP socket;
  `per-connection` creates an Endpoint/socket for each connection.

Build each protocol in a separate Cargo invocation because feature selection
is additive:

```sh
CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-hy2-perf-client --no-default-features --features hy2

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-reality-perf-client --no-default-features --features reality

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-hy2-core-perf-client --no-default-features --features hy2-core

# Production HY2 Handler with Ring as the rustls crypto provider
CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-hy2-core-perf-client --no-default-features --features hy2-core-ring

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-reality-core-perf-client --no-default-features --features reality-core

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked \
  -p chimera-reality-core-perf-client --no-default-features --features zero-copy

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked -p chimera-hy2-protocol-perf-client \
  --features aws-lc-rs

CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked --no-default-features \
  -p chimera-reality-protocol-perf-client --features vision

# REALITY + VLESS TCP without Vision
CARGO_TARGET_DIR="$PWD/target/minimal-transport-clients" \
  cargo build --release --locked --no-default-features \
  -p chimera-reality-protocol-perf-client
```

The protocol-core binary takes numeric `--server IP:PORT`, `--server-name`, and
`--ca PEM` arguments. It reads the password from `HY2_PASSWORD`, defaults to a
loopback SOCKS5 listener on `127.0.0.1:59901`, and allows explicit local UDP
bind, bandwidth, and initial congestion-window settings. The CA file must
contain the server trust certificate; the benchmark does not disable TLS
verification. Enable `aws-lc-rs` when comparing with the normal product
profile; without it the minimal build uses Ring through Quinn. The listener
supports TCP CONNECT only and keeps DNS, interface
selection, routing, port hopping, and UDP forwarding outside this first core
slice. Use the same fixed generator and destination as the handler matrices.
The standalone HY2 binary accepts `--udp-socket-mode native`,
`tokio-abstract`, or `socket2-abstract`. These modes compare Quinn's native
endpoint socket with caller-supplied sockets; `socket2-abstract` follows the
Linux socket2 creation and Tokio-to-Quinn wrapping sequence used by the
production direct connector when no source address, interface, or socket
protector is configured. It also accepts `--quic-connections N` from 1 to 64
(default 1). With N greater than 1, each accepted SOCKS TCP stream is assigned
round-robin to an independently authenticated QUIC connection. The
benchmark-only `--endpoint-mode shared|per-connection` option controls whether
those connections share one Quinn Endpoint and UDP socket (default `shared`)
or each get a separate Endpoint/socket (`per-connection`). Shared mode isolates
QUIC connection-count scaling while holding the Endpoint and UDP socket count
constant; per-connection mode measures the combined effect of connection,
Endpoint, and socket sharding. Neither option changes the production client's
connection policy. A fixed local port can be used in shared mode; multiple
per-connection endpoints require an ephemeral `--local-bind` port.

To start it without placing the password in command history or process
arguments, read it into the environment first:

```sh
read -rsp 'HY2 password: ' HY2_PASSWORD
export HY2_PASSWORD
target/release/chimera-hy2-protocol-perf-client \
  --server 127.0.0.1:443 --server-name hy2.example --ca server-ca.pem
```

The standalone REALITY client reads `REALITY_PUBLIC_KEY` and `REALITY_UUID`
from the environment; `REALITY_SHORT_ID` is optional. It accepts numeric
`--server IP:PORT`, `--server-name SNI`, and `--flow vision|none`. Repeat
`--alpn VALUE` to match an explicit node ALPN list; when omitted, the core uses
its default `h2,http/1.1` list. Add `--x25519mlkem768` when the server
requires a hybrid offer. It sends X25519MLKEM768 first and also sends the
associated X25519 share; the client accepts only a ServerHello group it
offered. This lets Xray 26.11.9 require the hybrid offer while selecting
classical X25519 when its cover target does not support ML-KEM. The option
does not guarantee that the negotiated TLS session used ML-KEM.
The default build includes Vision. A `--no-default-features` build keeps
REALITY and VLESS TCP framing but omits Vision deframing, padding, and stream
filters; it accepts `--flow none` and rejects `--flow vision`.

```sh
read -rsp 'REALITY public key: ' REALITY_PUBLIC_KEY
export REALITY_PUBLIC_KEY
read -rsp 'VLESS UUID: ' REALITY_UUID
export REALITY_UUID
read -rsp 'REALITY short ID (empty if unused): ' REALITY_SHORT_ID
export REALITY_SHORT_ID
target/release/chimera-reality-protocol-perf-client \
  --server 127.0.0.1:443 --server-name reality.example --flow vision \
  --alpn h2 --alpn http/1.1
```

The runtime-front-end packages accept `--config PATH`, plus optional
`--directory PATH` and `--log-file PATH`. They require an existing config and
will not create a default one. Use a pure `socks-port`; it is always available
and avoids compiling the extra HTTP/mixed listener. Keep the same config,
numeric target IP, routing mode, and proxy node as the full `clash-rs` control
build.

The direct-core packages accept `--config PATH --proxy-name NAME`, with an
optional `--listen IP:PORT`; the listener must be an IPv4 or IPv6 loopback
address because the bridge has no authentication. Their YAML reader selects
one entry from `proxies:` and applies YAML merge keys like the production
config parser. Parse and validation errors suppress raw config values. HY2
requires a numeric server address. The REALITY profile requires VLESS TCP,
REALITY options, and `xtls-rprx-vision`; both the server and target must use
numeric IP addresses. The small SOCKS5 bridge
supports numeric TCP CONNECT only, using 64 KiB bidirectional copy buffers by
default. The REALITY protocol client accepts `--copy-buffer-size` from 4 KiB
to 1 MiB to measure the copy-buffer effect; this is a benchmark control, while
the product's corresponding setting is `experimental.tcp-buffer-size`. The
bridge enables `TCP_NODELAY` on accepted SOCKS streams and the upstream TCP
stream, matching the product listener's TCP option for this measurement. This
keeps DNS out of the measured path and makes the bridge suitable for the
existing generator. It is benchmark harness code, not the product SOCKS
listener. The HY2 direct-core binary also accepts `--relay-mode tokio`,
`product-copy`, or `raw-core`: `raw-core` returns the production HY2 stream
before `ChainedStreamWrapper` is applied, isolating that wrapper while keeping
the handler, connector, authenticated QUIC connection, and Tokio copy loop.
Both paths still use a trait object; this removes the outer metadata/forwarding
wrapper rather than all dynamic dispatch. The mode is enabled only by the
bootstrap's `hysteria` feature and is diagnostic-only. `raw-concrete` returns
the concrete HY2 stream before boxing. `raw-concrete-no-udp-rx` uses that same
TCP stream path while skipping the idle HY2 UDP receive task; use it only for
TCP-only ablations, since it intentionally cannot receive HY2 UDP datagrams.
`raw-concrete-socket2-no-udp-rx` also skips the idle receive task and forces the
standalone client's socket2 creation plus Tokio-to-Quinn wrapping sequence in
the Handler. The override is limited to numeric loopback endpoints without an
interface binding, port hopping, obfuscation, or Linux socket mark. Use it only
for this local TCP ablation; it does not replace the connector path in product
builds. All relay modes, the socket override, and the UDP-task switch are
behind the benchmark API feature and leave the normal product path enabled.

The runtime-front-end packages do not implement the general CLI's
compatibility mode or `--controller-ipc` override. Benchmark configs must not
depend on those options.

For matrix-runner build profiles, use the matching package, binary, and feature:

| Profile | Package and binary | Features | Startup path |
| --- | --- | --- | --- |
| HY2 runtime | `chimera-hy2-perf-client` | `hy2` (HY2 and AWS-LC) | `clash_lib::start_scaffold` |
| REALITY runtime | `chimera-reality-perf-client` | `reality` (REALITY and AWS-LC) | `clash_lib::start_scaffold` |
| HY2 direct core | `chimera-hy2-core-perf-client` | `hy2-core` | `transport_bench::Client` |
| VLESS + TCP + REALITY + Vision direct core | `chimera-reality-core-perf-client` | `reality-core` | `transport_bench::Client` |
| VLESS + TCP + REALITY + Vision direct core with Linux splice | `chimera-reality-core-perf-client` | `zero-copy` | `transport_bench::Client` plus production splice path |
| HY2 protocol core | `chimera-hy2-protocol-perf-client` | `aws-lc-rs` to match product | `chimera_hysteria2_core::HysteriaClient` |
| VLESS + TCP + REALITY protocol core | `chimera-reality-protocol-perf-client` | `--no-default-features` (`reality`, `vless`) | `RealityClient` + `VlessStream` |
| VLESS + TCP + REALITY + Vision protocol core | `chimera-reality-protocol-perf-client` | `--no-default-features --features vision` | `RealityClient` + `VlessStream` + `VisionStream` |

The release profile copies the Client workspace's `opt-level`, codegen units,
LTO, debug, strip, and panic settings. This keeps compiler optimization from
becoming an extra variable when comparing either harness with `clash-rs`.

The runtime-front-end binaries still include and start shared runtime,
resolver, DNS, routing, and configuration code. The direct-handler binaries
skip those startup paths while still compiling the broad `clash-lib` dependency
graph. The two protocol-core binaries build against extracted transport crates
and omit the Clash runtime entirely. The HY2 core owns H3 authentication,
congestion setup, and TCP stream framing. The REALITY crate exposes separate
`reality`, `vless`, and `vision` features, so the no-Vision profile measures
REALITY authentication plus VLESS TCP framing while the default profile adds
Vision stream processing.
Product DNS, interface/socket selection, routing, HY2 port hopping and UDP
forwarding, and session integration remain in `clash-lib`.

The direct-core bridge reads `RUST_LOG` for optional runtime diagnostics. Its
default filter is `error`; for example, use
`RUST_LOG=clash_lib::common::io=trace` on a full-content smoke to verify that
the splice handoff event occurs. Keep trace logging disabled during throughput
cells.

The 2026-11-26 lockfile counted 92 HY2 and 79 REALITY nodes. Recounting the
current locked profiles on 2026-11-27 with unique `{p}` package/version nodes
and all dependency edge kinds reports 71 HY2 nodes (`aws-lc-rs`) and 66
REALITY/Vision nodes. Restricting the same host-target graphs to normal runtime
dependencies gives 62 HY2 and 57 REALITY/Vision nodes. The standalone clients
include no `clash-lib`, `chimera-dns`, `watfaq-netstack`, Hyper, or Hickory
nodes. This distinction separates linked/runtime dependencies from build and
development graph size; the binary sizes and throughput comparisons are in the
results file.

The first local loopback comparison is recorded in
[RESULTS_LOCAL_LOOPBACK_2026-11-26.md](RESULTS_LOCAL_LOOPBACK_2026-11-26.md).
The runtime-front-end comparison found no repeatable throughput change. The
direct-core binaries were 73.07% smaller for HY2 and 69.21% smaller for
REALITY/Vision than their protocol-matched full CLI builds. Direct-core HY2
uplink was 7.69% faster in this loopback workload; other direction differences
were -1.29% to +0.17% and need more samples before being treated as effects.

The latest fixed-Xray REALITY/Vision ABBA compares both the product client and
the extracted protocol client against Xray 26.11.9. It records an initial
12.5% minimal-client throughput deficit traced to a missing `TCP_NODELAY` on
the benchmark SOCKS stream. With that socket option aligned and the feature
profile made explicit, the standalone client measured 2.6% above Xray on local
loopback. Full results, binary identities, CPU/RSS, and verification limits
are in the final section of the results file.

## Extracted transport-core boundary

The direct-handler binaries remain useful controls; their dependency graphs
still contain 353 HY2 and 348 REALITY package-version nodes because they build
`clash-lib`. The earlier standalone profiles contained 92 HY2 nodes (with
`aws-lc-rs`) and 79 REALITY nodes; current locked-profile recounts are 71 and
66. Both profiles omit `clash-lib`, `chimera-dns`, `watfaq-netstack`, Hyper,
and Hickory. The HY2 core owns QUIC/H3 authentication, TCP stream
framing, congestion setup, and Brutal selection. The REALITY core owns REALITY
TLS/authentication, VLESS TCP framing, and Vision processing. `clash-lib` adapts
DNS, interface and socket selection, routing, port hopping, network-path
checks, UDP framing, and proxy sessions around those cores.

Both protocol cores build as separate crates and are shared by the production
handlers and standalone clients. HY2 has passed full-content smoke tests
against the Chimera app server, the feature-minimized Chimera HY2 server, and
official Hysteria 2.14.0; an official Hysteria client also passed against the
feature-minimized Chimera server. REALITY/Vision has passed full-content smoke
and repeated loopback throughput comparisons against the feature-minimized
Chimera Server. The standalone HY2 binary uses Quinn's native UDP endpoint
while the product handler injects its connector-selected socket; both use the
same authentication, congestion, and TCP stream code.

A repeated one-stream local comparison against the same Chimera HY2 server and
target found the standalone core and direct product handler within their
run-to-run variation. See the extracted-core results in
[`RESULTS_LOCAL_LOOPBACK_2026-11-26.md`](RESULTS_LOCAL_LOOPBACK_2026-11-26.md).
The standalone binary is TCP-only in this slice: product DNS, socket selection,
port hopping, and UDP forwarding remain outside its measurement. This is local
loopback evidence. Official Hysteria 2.14.0 cross-server throughput and shared-
Endpoint QUIC connection-count results are recorded in
[`RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md`](RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md).
The remote node-to-origin direct egress control is recorded in
[`RESULTS_REMOTE_DIRECT_EGRESS_2026-11-28.md`](RESULTS_REMOTE_DIRECT_EGRESS_2026-11-28.md);
it is not a proxy-path measurement, so proxy WAN and loss/RTT performance
remain unmeasured. The standalone REALITY binary
similarly uses direct TCP and a fixed SOCKS bridge; this does not measure
product DNS, TUN, routing, or socket-selection paths. See the results file for
Xray interop and throughput results. Xray 26.11.9 interop requires
`reality-opts.support-x25519mlkem768: true` in the product config; the default
remains off for compatibility with older REALITY servers. The standalone
binary enables the same path with `--x25519mlkem768`.

The latest HY2 socket-path ABBA compares the production connector socket with
the same Handler forced to use the standalone socket2-to-Quinn setup. The
override measured about 1% slower on upload, and download pairs disagreed; it
does not explain the earlier standalone protocol client's upload lead. See
the results file for exact rates and limitations.

The subsequent matched ABBA compared the standalone HY2 protocol crate with
the production Handler behind the direct-core benchmark bootstrap, using the
same forced socket2 path on both. Handler throughput was 0.78% lower on upload
and 0.16% lower on download. The earlier connector-path run had a pooled 3.05%
upload deficit for Handler (paired changes -2.37% and -3.78%); this did not
repeat with the socket path matched. The local data therefore does not show a
stable multi-percent protocol-core bottleneck.

The direct-handler relay-copy ablation and its 512 MiB/connection HY2 download
confirmation are recorded in
[`RESULTS_LOCAL_LOOPBACK_2026-11-26.md`](RESULTS_LOCAL_LOOPBACK_2026-11-26.md).
The follow-up `raw-core` ablation in that file bypasses only the HY2
`ChainedStreamWrapper`: it found +0.36% upload and +2.17% download aggregate
median differences, with paired download results disagreeing. It therefore
does not establish a stable wrapper throughput cost.
The initial HY2 download point estimate favored the production tracking/copy
path by 3.20%, but the larger ABBA repetition reversed direction. Across HY2
and REALITY, this experiment does not identify a stable relay-copy throughput
effect or explain the earlier HY2 upload difference.

The first 2026-11-27 HY2 connection-sharding matrix used a separate Endpoint and
UDP socket per QUIC connection. It found 3.63 Gbit/s with one connection, 6.05
with two, 10.12 with four, and 12.28 with eight. This changed the number of
Endpoints/sockets along with the number of QUIC connections, so it measures
their combined effect. A follow-up held one Endpoint and UDP socket constant:
1/2/4/8 connections reached 3.67/6.23/10.44/10.75 Gbit/s. Four connections
were the best local tradeoff in that controlled matrix: near the eight
connection rate, with much lower run-to-run variation and sampled Server RSS.
The shared-Endpoint server profile also showed Quinn connection-state lock
contention decreasing from 4.64% of user-cycle samples at one connection to
1.23% at eight. These are benchmark-only controls; production connection
policy is unchanged. The detailed ABBA, CPU/GiB, RSS, profile, and evidence
limits are in the final sections of
[`RESULTS_LOCAL_LOOPBACK_2026-11-26.md`](RESULTS_LOCAL_LOOPBACK_2026-11-26.md).
The current locked HY2 `aws-lc-rs` graph recount is 71 release nodes; the
92-node count above records the earlier lockfile/profile.

The latest HY2 cross-client/server and 1/4/8-connection BBR matrices are in
[`RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md`](RESULTS_HY2_CROSS_AND_SHARDING_2026-11-27.md).

The 2026-11-27 REALITY/Vision splice-handoff A/B verified that the product
direct-handler path actually enters Linux splice after the Vision raw switch.
Across ten samples per mode on loopback, pooled download and upload medians were
1.93% and 2.81% above the buffered path; measured client CPU per GiB fell by
34–48%. This profile includes the direct production handler and `clash-lib`,
because the Linux splice relay and traffic trackers are product integration
code. It does not turn the standalone protocol-core result into a full product
benchmark. Exact bytes, binary identities, CPU/RSS, and limits are in
[`RESULTS_LOCAL_LOOPBACK_2026-11-26.md`](RESULTS_LOCAL_LOOPBACK_2026-11-26.md).

### 2026-11-27 protocol-core rebuild and smoke

The 候选源码快照包含本地修改 at HEAD `[源码快照已省略]`
rebuilds the two standalone profiles independently. `cargo tree -e no-dev`
reports 71 normal/build graph package-version nodes for HY2 with
`aws-lc-rs`, and 66 for REALITY/Vision. Neither graph contains `clash-lib`,
`chimera-dns`, Hickory, Hyper, or Axum. These counts describe the locked
compile graph, not a promise that every node is linked into the stripped binary.

| Profile | Release bytes | SHA-256 |
| --- | ---: | --- |
| HY2 protocol-core client (`aws-lc-rs`) | 3,242,392 | `87e3fc1c5f203864d72bd07d3873270a29fb500459e3038e253691fe81137435` |
| REALITY/Vision protocol-core client | 2,024,192 | `38de551503b2dbe30e9d7304b1ebc90f3c46015f1376f651744f678cf6d62ef9` |

Both rebuilt clients passed a current-binary loopback full-content smoke through
their matching extracted Server core: four SOCKS TCP streams, 1 MiB upload and
download per stream, and byte-pattern verification. The REALITY smoke selected
`flow=none`, because the minimal Server fixture currently accepts VLESS TCP
without Vision. These are correctness checks only; the transfers were too
short to report as throughput. Matching external official-client/server
interoperability for these exact rebuilt hashes has not been rerun here.

### 2026-11-28 Handler versus protocol-core repeat

A new 30-second ABBA on the fixed local Chimera HY2 Server compared the normal
product connector path in the direct Handler harness with the standalone
protocol-core client. The protocol-core median was only 0.23% higher on download
and 0.31% higher on upload, below the 3.85%–6.97% per-cell CV. Both core cells
passed full-content smoke; all four API cells completed 1204/1204 requests.
This repeat does not show a stable data-plane gain from removing the Handler
layer. It also profiles the Client: Quinn packet-buffer copies and AWS-LC AES-GCM
are the leading sampled hotspots. The harness skips full product runtime startup;
see [`RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md`](RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md)
for the exact build hashes, per-cell values and limitations. A syscall trace on
both loopback endpoints then confirmed that `UDP_GRO` and GSO capability probes
succeed, while the 8-way workload emitted no `UDP_SEGMENT` send cmsgs and no
`UDP_GRO` receive cmsgs. `recvmmsg` did return multiple independent datagrams
per call; this is syscall batching, not GRO packet coalescing.

### 2026-11-28 Server receive-drop and crypto backend profiling

A symbolized Server profile found AWS-LC AES-GCM at 19.44% and `memmove` at
18.98% of sampled user cycles. A separate 15-second socket attribution run
assigned 11,893 receive drops to the Server and 5,051 to the Client; their sum
exactly matched the system UDP receive-buffer error delta. A local Ring versus
AWS-LC Client ABBA found similar throughput within 4.32%–7.73% per-cell CV,
while Ring used about 7.7% less Client CPU per delivered GiB in this sample.
That protocol-core-only result was not enough to select a default provider.
Server profile details, binaries, socket values and raw paths are in
[`RESULTS_HY2_RCVBUF_2026-11-28.md`](RESULTS_HY2_RCVBUF_2026-11-28.md).

The production HY2 Handler **Client-side** Ring/AWS-LC repeat added four matched
15-second mixed-load cells per backend. Ring's median was +3.16% download and
+1.99% upload, with 4.90% lower Client CPU. It did not improve API tails: p95 was
3.18% slower and p99 9.99% slower than AWS-LC. Ring also recorded more local
UDP receive-buffer errors. Keep AWS-LC as the Client default. The full table,
hashes, failed preflight attempt, and limitations are recorded in
[`RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md`](RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md).

A separate Server-side ablation fixes the Client and selects the Rustls provider
only in the Hysteria2 Server. The isolated forced-Ring binary improved down/up
throughput by 3.24%/4.89% with the Chimera Handler Client, and by 4.94%/9.89%
with official Hysteria 2.14.0. API p95 did not improve consistently across
clients. The final local Server candidate uses Ring only when no client
fingerprints are configured and Ring can load the server key; otherwise it
falls back to AWS-LC. Generic QUIC and TUIC remain on AWS-LC. The final
17,929,808-byte release binary passed full-content smoke with both clients, but
was not rerun through the performance matrix. These are loopback results and do
not establish a WAN gain. Full results, hashes and limitations are in
[`RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md`](RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md).

Four direct cells with the same payload, 8-way full-duplex streams, and TLS API
load delivered 24.000/24.402 Gbit/s down/up, with 0.451/0.560 ms API p95/p99
and no UDP receive-buffer errors. The local HY2 Handler cells delivered about
58.5%–60.4% of direct download and 54.2%–55.3% of direct upload throughput,
with much higher API tails under load. This is a same-host loopback comparison,
not a WAN result; the exact direct cells and caveats are in the same report.

A later local CPU-affinity sweep used the same Chimera Client and AWS-LC versus
Ring Server binaries across four CPU profiles, with four cells per provider in
each profile. Allowing every process to use CPUs 0–15 produced the best API
tails (median about 10–12 ms p95 and 15–17 ms p99) and nearly zero UDP receive drops.
Splitting Client and Server onto exclusive CPU groups reduced socket drops but
increased API tails; the same-thread-count split also constrained each side to
four physical cores. Direct control under this desktop load measured
20.611/20.988 Gbit/s down/up. These results are local scheduling evidence, not a
production affinity recommendation; raw data and per-profile CVs are in
[`RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md`](RESULTS_PROTOCOL_CORE_VS_HANDLER_2026-11-28.md).
