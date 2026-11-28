# Minimal client frontends: local loopback results

## Question

Does removing the general Chimera CLI frontend and compiling one transport
profile change local transfer throughput when both binaries use the same
production `clash-lib` implementation?

## Setup

- Client baseline: `[源码快照已省略]`; the benchmark
  packages and workspace entries were uncommitted during the run.
- Server source: `[源码快照已省略]`, with a dirty
  worktree. The server, target, and generator executables were pinned by
  BLAKE3 in the matrix manifests, so the same binaries were used throughout.
- Host: Linux x86_64 (kernel 6.18), 16 logical CPUs.
- Process CPU and memory monitoring were disabled for these matrices; this
  record compares throughput and completion only.
- Client, proxy server, matrix generator, and TLS target all ran on this host
  over `127.0.0.1`. This measures local code-path throughput, not the remote node node,
  WAN, or a real Internet route.
- The full CLI and mini frontend used the same protocol-specific `clash-lib`
  feature closure, identical configuration per protocol, pure SOCKS listeners,
  and the same fixed Chimera server binary. `mixed_port` was disabled in both
  builds. The REALITY profile is VLESS TCP + REALITY + Vision; HY2 uses the
  Chimera minimal Hysteria server profile.
- Correctness smoke: one 1 MiB upload and download per frontend, with full
  payload verification. All four smoke flows completed.
- Throughput: 8 concurrent connections, 256 MiB per connection in the main
  direction and 1 MiB in the reverse direction, 1 warmup round and 5 measured
  rounds per cell. Cells ran in ABBA order: full CLI, mini, mini, full CLI.
  Each cell delivered 10 GiB of measured main-direction data and completed 40
  connections. Bulk runs used `full_verify=false` to avoid making payload
  pattern generation and checking the throughput limiter.
- The reported median is calculated from the 10 measured per-round aggregate
  rates for each frontend. CV is population standard deviation divided by the
  mean across those same 10 samples. Rates are decimal Mbps.

## Results

| Protocol | Direction | Full CLI median (CV) | Mini median (CV) | Mini vs full | Samples per frontend |
| --- | --- | ---: | ---: | ---: | ---: |
| HY2 | Download | 4,114.800 Mbps (1.86%) | 4,109.392 Mbps (0.79%) | -0.13% | 10 |
| HY2 | Upload | 3,339.496 Mbps (1.01%) | 3,279.324 Mbps (1.55%) | -1.80% | 10 |
| VLESS + REALITY + Vision | Download | 20,967.172 Mbps (2.47%) | 21,097.238 Mbps (2.65%) | +0.62% | 10 |
| VLESS + REALITY + Vision | Upload | 21,831.369 Mbps (1.40%) | 21,619.921 Mbps (1.57%) | -0.97% | 10 |

For each protocol and direction, all four ABBA cells reported `complete`, exit
code 0, 40 completed connections, and 10 GiB delivered in the main direction.
The smoke flows used full payload verification; bulk throughput runs did not.

## Binary and dependency footprint

| Profile | Mini executable | Full CLI executable | Size reduction | Unique Cargo package-version nodes |
| --- | ---: | ---: | ---: | ---: |
| HY2 | 15,193,248 bytes | 15,464,480 bytes | 271,232 bytes (1.75%) | 353 vs 364 |
| REALITY/Vision | 15,048,944 bytes | 15,320,232 bytes | 271,288 bytes (1.77%) | 348 vs 359 |

The mini profiles do not include `clap` and each removes 11 package-version
nodes from the selected dependency graph. Their protocol feature closure matches
the corresponding full CLI profile, including TLS and AWS-LC where required;
the feature tree does not enable `mixed_port`. Shared resolver, DNS, runtime,
routing, and configuration dependencies remain present.

## Interpretation and limits

The measured frontend differences are between -1.80% and +0.62%, alongside
sample variation of 0.79% to 2.65%. This run does not establish a repeatable
throughput advantage for the mini frontend. It does show that the general CLI
frontend is not a major steady-state data-plane cost in this setup. The HY2
upload difference is close to the run-to-run variation and needs a larger,
paired sample before treating it as a real effect.

This comparison is intentionally a first isolation step: the mini executables
still launch the production `clash-lib` runtime. They avoid actual DNS lookups
by using numeric loopback addresses, but do not remove DNS code or other shared
subsystems from the binary. A true transport-core benchmark needs a direct,
minimal API that invokes the production HY2 and VLESS/REALITY transport paths
without starting the full runtime; that is the next architecture slice.

The Reality throughput logs also contain repeated inner-target TLS handshake
EOF messages and a small number of server-side early-EOF messages, although all
matrix cells completed and the verified smoke flows passed. The matrix runner's
TCP readiness probe is confirmed to open a raw TCP connection to the TLS target,
which explains the initial target handshake-EOF log. The additional Reality
EOF messages have not yet been fully attributed, so the throughput result is
useful for frontend comparison but the connection-log noise remains an open
diagnostic item.

Raw matrix manifests, logs, and JSONL results were kept outside the repository
under `本机临时目录`; the
generated YAML files and credentials are not part of this source change.

## Direct-handler harness comparison

The second comparison adds a feature-gated
`clash_lib::transport_bench::Client` API. It constructs the production HY2 or
VLESS/REALITY handler from one selected `proxies:` entry, then opens a TCP
stream directly through that handler. A small test-only SOCKS5 server provides
the generator interface and copies with 64 KiB buffers. This path does not call
`start_scaffold`, start DNS/rules/Controller services, or apply product routing
and connection-tracking setup. It still uses the production protocol handler
and a system resolver object; the fixed numeric server and target addresses
mean no DNS query is issued.

The full CLI and direct-handler binaries were built from the same Client
worktree and root lockfile, with the same protocol features, config, server,
generator, target, host, and ABBA workload as the preceding section. The direct
binary additionally enables `transport-bench-api`; neither profile enables
`mixed_port`. The matrix manifests pin all external executables by BLAKE3. The
Server source tree was still dirty at commit
`[源码快照已省略]`.

The direct-handler correctness smoke passed for both protocols: one 1 MiB
upload and download per client with full payload verification. Bulk results use
10 measured aggregate samples per client, each sample representing 8 parallel
connections. CV is calculated across those 10 per-round rates.

| Protocol | Direction | Full CLI median (CV) | Direct-handler median (CV) | Direct vs full | Samples per client |
| --- | --- | ---: | ---: | ---: | ---: |
| HY2 | Download | 4,182.322 Mbps (2.23%) | 4,188.515 Mbps (3.21%) | +0.15% | 10 |
| HY2 | Upload | 3,313.494 Mbps (0.85%) | 3,568.339 Mbps (1.03%) | +7.69% | 10 |
| VLESS + REALITY + Vision | Download | 20,819.865 Mbps (2.41%) | 20,855.622 Mbps (2.58%) | +0.17% | 10 |
| VLESS + REALITY + Vision | Upload | 21,737.607 Mbps (1.70%) | 21,457.977 Mbps (1.97%) | -1.29% | 10 |

All four cells in each direction reported `complete`, exit code 0, 40 completed
connections, and 10 GiB delivered in the main direction. Bulk runs used
`full_verify=false`; payload correctness is covered by the separate smoke.

### Direct-handler binary footprint

| Profile | Direct-handler binary | Full CLI binary | Size reduction | Unique Cargo package-version nodes |
| --- | ---: | ---: | ---: | ---: |
| HY2 | 4,165,144 bytes | 15,464,480 bytes | 11,299,336 bytes (73.07%) | 353 vs 364 |
| REALITY/Vision | 4,717,424 bytes | 15,320,232 bytes | 10,602,808 bytes (69.21%) | 348 vs 359 |

The direct binaries also omit `clap`; their Cargo dependency graphs remain
almost the same size as the runtime-front-end profiles because `clash-lib`
still declares shared DNS, API, resolver, and routing dependencies. Link-time
optimization removes most unreachable application code from these executables,
but this is not yet a dependency-minimal standalone transport crate.

The exact release client and server binaries were:

| Protocol/profile | BLAKE3 |
| --- | --- |
| HY2 full CLI | `6dfa99ea583655b6bf127a4fcd28449d3d3e4be8c4ac2e173ee1c4ff5042a91b` |
| HY2 runtime frontend | `9bbb831331e5c95db0deb6470f7204002d1350332a2244cc0f2b4a953cb42410` |
| HY2 direct handler | `ee1ce4637160e89afa684bb9d092d7cd9d07bf1e22421ff34fd51ae52cea4251` |
| HY2 server | `f4b32427c3f58a565436d8cb639f933b1a99425595587429067a294fa190539d` |
| REALITY full CLI | `2695694a73e64b974e12b9df27c210954cabdf8bd8b5f1909f81760ae94f991b` |
| REALITY runtime frontend | `6713ec19da9e08db15a81d2febf33b711d3f88934a984209357644a5b36ccc79` |
| REALITY direct handler | `c0cc0d1eb56959a083d74401be75e2acba55ea7dc59fd117498a946a7404148d` |
| REALITY server | `681c36811f4e61e6c7ffec467a1f4325461fab9f651d85d4d4495ec77f4696ab` |
| Generator | `39e4bcfea6a1369695e420791126c0b57ab952f4448380e4d4e3b6c0144ba719` |
| TLS target | `0bb3e523d2edd26ae87ecf5c84bb22bb926503c5318c1c09dfc051ee694ce5b1` |

After these matrices, the benchmark bridge was hardened to reject non-loopback
`--listen` addresses, and its config reader was updated to apply YAML merge
keys and sanitize config-derived error messages. These startup/config changes
were not present in the direct-handler binaries above; the listed hashes
intentionally identify the exact measured binaries. They do not touch the
transfer path. Targeted regression tests cover the new behavior. After these
changes, both direct-core release clients were rebuilt by the matrix runner and
passed a full-verification smoke against the same fixed Chimera server: one
1 MiB upload and download each for the full CLI and direct client, all four
cells complete with exit code 0. This was a correctness smoke only; no
post-change throughput matrix was run. Smoke artifacts are under
`本机临时目录,reality}/`.

### Reading the result

Skipping full runtime startup and product dispatch made no measurable
difference in HY2 or REALITY download in this run. Direct-handler HY2 upload
was 7.69% faster across the 10 samples, with a lower sample spread than the
full CLI. This is a strong lead that the full HY2 upload path or its copy
buffering/dispatch costs merit profiling. The direct bridge itself uses a
64 KiB copy buffer while the product inbound path has its own relay code, so
the result does not attribute the gain to one runtime module. REALITY upload
was 1.29% lower with the direct handler, close to the observed variation; it
does not establish a regression.

The source trace gives a focused next experiment. Production SOCKS TCP
connections enter `proxy/socks/inbound/stream.rs`, then
`app/dispatcher/dispatcher_impl.rs`, which calls
`common/io/mod.rs::copy_bidirectional_with_report` with the dispatcher's
default 64 KiB buffer, flow accounting, and half-close/idle handling. The
direct harness uses Tokio's `copy_bidirectional_with_sizes` with 64 KiB buffers.
The configured buffer sizes match, while the copy implementation and
dispatcher work differ. This makes per-chunk tracking/relay overhead a concrete
candidate for the HY2 upload gap; it is a source-backed hypothesis, not a
confirmed root cause. The next A/B should hold handler, server, destination,
and buffer size fixed while profiling or replacing only the relay copy path.

Each Reality bulk matrix logged 193 target inner-TLS handshake EOFs. The
runner's raw TCP readiness probe accounts for one target EOF. The remaining
192 match the 192 warmup and measured generator connection slots, but their
target-side source has not been identified. Each matrix also logged four
server-side `early eof` errors. The runner performs one raw TCP readiness probe
to the proxy server in each of its four cells, so those four errors likely
come from the probes; this has not been confirmed with socket-level tracing.
The direct SOCKS bridge logs two additional `early eof` messages when the
runner checks listener readiness; these are a separate pair of bridge-side
probe messages.

All matrix cells completed and full-verification smoke passed. The unresolved
target-side EOFs should be traced before treating the Reality absolute rate as
a clean end-to-end reference.

The direct-handler matrices and logs are under
`本机临时目录`. They are not
committed because their YAML configs contain local credentials.

## Standalone HY2 protocol-core verification and throughput

The new `chimera-hysteria2-core` package and its standalone client were tested
against both Chimera and official Hysteria implementations. The 1 MiB smoke
cells sent 1 MiB in each direction through the same TLS target with full
content verification enabled:

| Client | Server | Result |
| --- | --- | --- |
| Standalone HY2 protocol core | Chimera app server | Pass |
| Standalone HY2 protocol core | Feature-minimized Chimera HY2 server | Pass |
| Standalone HY2 protocol core | Official Hysteria 2.14.0 server | Pass |
| Official Hysteria 2.14.0 client | Feature-minimized Chimera HY2 server | Pass |

The standalone client release build used `aws-lc-rs`, matching the product
crypto provider. Its binary was 3,219,104 bytes, SHA-256
`be1fa5605f645dabbcf3435e80b7f3ecd2b83b9ac5a0f01dc9c5636d4562fd53`. The
direct-handler HY2 control binary was 4,161,800 bytes, SHA-256
`d149d640cbda383289154818c8a5a6a06fe99cc9d322bb205e62df2b62cedfb8`.
The standalone binary was 22.65% smaller than this direct-handler control.
This size comparison does not imply a speed improvement.

For throughput, the standalone protocol core (`A`) and the direct product HY2
handler (`B`) ran in A/B/A/B order against the feature-minimized Chimera
Server and the same local target. Each cell used one warmup followed by five
measured runs; each measured run transferred 32 MiB up and 32 MiB down over one
TCP stream, with inner TLS, TCP_NODELAY, and full payload verification. This
gave ten measured runs per profile and 320 MiB delivered in each direction per
profile.

| Client profile | Upload median | Upload CV | Download median | Download CV | Measured runs |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standalone HY2 protocol core | 3,821 Mbps | 4.08% | 4,423 Mbps | 3.93% | 10 |
| Product HY2 direct handler | 3,742 Mbps | 4.22% | 4,640 Mbps | 3.95% | 10 |

The standalone core was 2.12% faster in upload and 4.67% slower in download by
median. Both differences are within the observed run-to-run variation, so this
run does not establish a throughput gain or regression from extracting the
core. It does show that the minimal binary can carry the same verified payload
at approximately the same loopback rate while avoiding the `clash-lib`
dependency graph. This comparison does not include product DNS, TUN, route
selection, interface/socket policy, port hopping, or UDP forwarding, and it is
not evidence about WAN throughput.

The exact samples and smoke records are under
`本机临时目录`. The temporary configs in that directory
are intentionally not copied into the repository because they contain local
test credentials. Client source was at `[源码快照已省略]`
with the extraction uncommitted; the Chimera Server worktree was at
`[源码快照已省略]` and already had unrelated dirty
changes. No Server source was changed for these runs.

## Standalone REALITY/Vision protocol-core verification and throughput

The new `chimera-reality-core` package contains the REALITY TLS/authentication
implementation and the VLESS TCP/Vision stream path shared with `clash-lib`.
The standalone client depends on that package directly, opens TCP to the
configured server, and exposes a loopback-only SOCKS5 CONNECT listener. It
does not start Clash DNS, routing, TUN, Controller, or session management.

A full-content correctness smoke transferred 1 MiB in each direction through
the standalone REALITY + Vision client and the feature-minimized Chimera Server.
Both payloads passed the generator's verification. The recorded rates were
6,721 Mbps upload and 7,822 Mbps download; this single smoke is not a throughput
estimate.

The loopback A/B/A/B comparison used the same feature-minimized Chimera Server,
target, and eight parallel TCP connections for both profiles. Each measured
run moved 64 MiB per connection in each direction. Each of the four A/B/A/B
cells used one warmup and five measured runs, giving ten measured samples and
5 GiB transferred per direction per profile. Runs used inner TLS, TCP_NODELAY,
64 KiB buffers, and `full_verify=false`; the separate full-content smoke above
checks payload correctness. No explicit ALPN arguments were passed, so the core
used its default `h2,http/1.1` offer.

| Client profile | Upload median | Upload CV | Download median | Download CV | Measured samples |
| --- | ---: | ---: | ---: | ---: | ---: |
| Standalone REALITY/Vision protocol core | 21,943 Mbps | 5.51% | 21,922 Mbps | 5.93% | 10 |
| Product REALITY/Vision direct handler | 21,972 Mbps | 3.60% | 22,394 Mbps | 4.09% | 10 |

The standalone result is 0.13% lower for upload and 2.11% lower for download
by median. Those deltas are smaller than the observed sample spread; this run
does not establish a speed change from extracting the core. The measured
standalone binary was 2,018,584 bytes, compared with 4,712,312 bytes for the
direct-handler control, a 57.17% reduction. The tested binary predates the
later addition of the optional `--x25519mlkem768` and repeatable `--alpn`
command-line switches. Their defaults preserve the measured handshake behavior
and data path.
The measured standalone and direct-handler SHA-256 values were
`9da0acac235a9c03041299586ba6da976cdfbd7c277524d802ec6b71ba182d96` and
`2221a8a3eb9103fc824d16e2546700bf8b22c40b1b495bd777967705356f34ea`,
respectively. The final source build after adding those switches is
2,019,360 bytes with SHA-256
`b1e74c22e86f1957f20b583dbd4f28dc70fa77f84a7ec774980ee90569cdf051`; it was
rebuilt successfully but was not substituted into the recorded A/B matrix.

The standalone dependency graph has 79 unique package-version nodes with
`cargo tree --locked -e no-dev -p chimera-reality-protocol-perf-client
--no-default-features --prefix none --format '{p}' | sort -u | wc -l`. The HY2
standalone graph has 92 with its `aws-lc-rs` feature enabled. Neither graph
includes `clash-lib`, `chimera-dns`, `watfaq-netstack`, Hyper, or Hickory.

### Xray 26.11.9 interoperability and throughput

The cross-test used Xray 26.11.9, commit `676eaf6`, Go 1.27.4, with the
same Xray REALITY + Vision server, numeric target, and loopback benchmark
generator for both clients. Xray's official client and Chimera's extracted
REALITY core both completed full-content 1 MiB upload/download smoke tests.
The Chimera core used `--x25519mlkem768`; the server had no explicit
`minClientVer`. Server diagnostics showed the Chimera client version
`[1, 8, 2]`, a successful authenticated REALITY connection, and negotiated
X25519MLKEM768. A Chimera `clash-rs` release build also passed the repository
interop script with `support-x25519mlkem768: true`. A temporary product
configuration with Vision enabled on both VLESS users passed the same
full-content echo check. The product `clash-rs` run was interop-only; the
throughput table below compares the official Xray client against the
standalone Chimera protocol-core client.

The measured standalone client SHA-256 was
`b1e74c22e86f1957f20b583dbd4f28dc70fa77f84a7ec774980ee90569cdf051`;
the Xray binary was
`111522ad8f1a5603a5ed5457c9274bfb14c55aa85f0f7ea000053200e9b7100c`.
The benchmark generator and target SHA-256 values were
`de3145c7512a53cebe6879742e4ff350719e9c62589da55bda6e90eb8698c762` and
`be5e9fddd4ae093b3cd9d864dd7baae6bf5ba7e8b20637a2001585c1f5ed86a1`.
The temporary Xray credentials/configs are not included in these fingerprints.

The classic X25519-only standalone client failed against this Xray server and
received the fallback target's ECDSA certificate. Lowering `minClientVer` to
`1.8.2` did not make that classic handshake work; enabling the hybrid key
share did. This isolates the tested failure to the missing X25519MLKEM768
share. Xray's REALITY server implementation checks for this share before
accepting the optional X25519 share
([upstream handshake code](https://github.com/XTLS/REALITY/blob/main/tls.go)).
The current test did not reproduce a client-version rejection: Xray 26.11.9
accepted version `1.8.2` when the hybrid share was present.

The subsequent bulk comparison used the same Xray server for both clients.
The official Xray client and standalone Chimera core both ran VLESS + REALITY
+ Vision, inner TLS, and TCP_NODELAY. Each test cell had one warmup followed
by five measured rounds. The 8-stream case transferred 64 MiB per connection
in the primary direction; the single-stream case used 256 MiB. Each used
1 MiB in the reverse direction. Bulk runs disabled full payload verification
to keep the generator out of the throughput path; correctness was checked in
the separate full-content smoke. Medians and population CV below cover all
measured rounds from the two ABBA cells per client.

| Concurrent streams | Direction | Xray client median (CV) | Chimera core median (CV) | Chimera vs Xray | Samples per client |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Upload | 18,059.9 Mbps (9.8%) | 18,759.5 Mbps (8.5%) | +3.9% | 10 |
| 1 | Download | 16,372.7 Mbps (3.4%) | 14,428.9 Mbps (20.0%) | -11.9% | 10 |
| 8 | Upload | 13,539.2 Mbps (13.1%) | 17,658.3 Mbps (3.1%) | +30.4% | 20 |
| 8 | Download | 16,278.7 Mbps (2.5%) | 14,760.9 Mbps (3.6%) | -9.3% | 20 |

This is loopback throughput, not WAN performance. The 8-stream download
comparison is close to a 10% gap; the single-stream Chimera download is slower
and highly variable, so neither is a final performance verdict. The Xray
client's 8-stream upload also varied substantially. CPU and memory were not
sampled during these cross-client runs. Raw generator JSONL is under
`本机临时目录` and
`xray-single-flow/`; no credentials or raw client/server configs were copied
into the repository.

The earlier extracted-core A/B/A/B samples, smoke result, and process logs are
under `本机临时目录`. These results
represent local loopback only, not WAN throughput, packet-loss resilience, or
production TUN and routing behavior.

### Feature-separated REALITY profiles and current Xray smoke

The standalone REALITY crate can be built with and without Vision. Both profiles
depend on the same `chimera-reality-core`; `--no-default-features` removes only
the Vision stream processing from the benchmark binary. Unique production
dependency nodes remain 79 in both profiles. Release binary sizes from the
current source build were:

| Profile | Binary bytes | SHA-256 | Unique dependency nodes |
| --- | ---: | --- | ---: |
| REALITY + VLESS TCP, no Vision | 1,985,016 | `9270a1ffe0d1601accb32f8d6f020700a76c19dc842dbac114bf36cda8d7f42b` | 79 |
| REALITY + VLESS TCP + Vision | 2,020,584 | `1b0de2b1caf76fe5cedd5d0938723f509637be0f2e1605fd39b51e9a4d3ae0cf` | 79 |
| HY2 protocol core + AWS-LC | 3,219,104 | `be1fa5605f645dabbcf3435e80b7f3ecd2b83b9ac5a0f01dc9c5636d4562fd53` | 92 |

Removing Vision reduced this standalone binary by 35,568 bytes (1.76%). The
crate still needs the same REALITY, X25519MLKEM768, and VLESS dependencies, so
the package-node count did not change.

The HY2 check used `cargo test --locked -p chimera-hysteria2-core` (9 passed)
and `cargo build --release --locked -p chimera-hy2-protocol-perf-client
--features aws-lc-rs` (passed). The HY2 interoperability and throughput
measurements earlier in this file were not rerun during this feature-split
check.

Full-content, one-connection smokes used Xray 26.11.9 (`676eaf6`) on loopback.
Each moved 1 MiB in each direction with payload verification enabled:

| Client and Xray profile | Upload | Download | Payload verification |
| --- | ---: | ---: | --- |
| Official Xray client, Vision user | 6,916 Mbps | 7,277 Mbps | Passed |
| Standalone Chimera, no Vision, no-flow user | 4,770 Mbps | 196 Mbps | Passed |
| Standalone Chimera, Vision user | 7,115 Mbps | 8,259 Mbps | Passed |
| Current `clash-rs` product profile, Vision user | 6,770 Mbps | 8,375 Mbps | Passed |

These single-run rates only confirm that both directions completed and matched
the expected payload. They are too small and variable to compare throughput.
The Xray client, Vision, no-Vision, and product rows use different user-flow
profiles, so treat them as separate interoperability checks.

During this check the standalone and product clients initially failed against
Xray 26.11.9: the hybrid ClientHello omitted its associated X25519 share, and
the client rejected X25519 when the server selected that offered group. The
client now advertises hybrid plus X25519 when explicitly enabled and derives
the negotiated group. The default remains X25519-only. This interoperability
behavior is not evidence that the transfer used a post-quantum key exchange;
the selected group must be recorded separately before making that claim.

The source profile was client commit `[源码快照已省略]`
with a 候选源码快照包含本地修改. The standalone binaries and full-content output are
under `本机临时目录`; temporary credentials
and raw configs remain outside the repository. This is loopback smoke evidence,
not a performance result or a WAN test.

## Fixed Xray REALITY/Vision client comparison and splice-read fix

This iteration tested the REALITY/Vision data path against the official Xray
26.11.9 client and server, then compared the standalone protocol client with
the product `clash-rs` client. All processes ran on one Linux x86_64 host (kernel 6.18, 16 logical CPUs). The target, generator, and Xray
server came from the dirty Chimera Server tree at
`[源码快照已省略]`; Xray was commit `676eaf6`. The
Client tree was dirty at `[源码快照已省略]`.

The measured path was VLESS + TCP + REALITY + Vision through loopback SOCKS5
to an inner-TLS target. Each ABBA cell lasted 20 seconds with 8 concurrent
streams, 1 MiB upload and 64 MiB download per generator run, and 64 KiB copy
buffers. The performance run used `full_verify=false`; a separate full-content
smoke below checked both directions. Xray's two ABBA endpoints used separate
SOCKS listener ports to avoid rebind conflicts after process shutdown.

| Client matrix | Xray first | Chimera first | Chimera second | Xray last | ABBA Xray mean | ABBA Chimera mean | Chimera vs Xray |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Product `clash-rs` | 19.583 Gbit/s (CV 3.0%) | 20.034 (3.7%) | 20.323 (3.5%) | 19.269 (2.6%) | 19.426 Gbit/s | 20.179 Gbit/s | +3.87% |
| Standalone, before SOCKS option alignment | 20.058 (3.3%) | 17.431 (6.7%) | 17.460 (5.9%) | 19.797 (3.1%) | 19.928 Gbit/s | 17.445 Gbit/s | -12.46% |
| Standalone, after SOCKS option alignment | 20.171 (2.4%) | 20.460 (3.3%) | 20.491 (3.0%) | 19.757 (3.3%) | 19.964 Gbit/s | 20.475 Gbit/s | +2.56% |

Rates are the generator's median aggregate download rates for each cell; the
ABBA mean is the arithmetic mean of the two cell medians. CV is the generator
variation within that cell. The standalone profile used
`--no-default-features --features vision`; its dependency enables the required
REALITY and VLESS TCP features. The product profile used `clash-rs` release,
`--no-default-features --features reality,mixed_port`.

The first standalone matrix exposed a harness mismatch, not a demonstrated
REALITY/Vision core bottleneck. Its accepted local SOCKS stream did not set
`TCP_NODELAY`, while the production mixed listener calls
`apply_tcp_options()`, which sets that option. The minimal client's upstream
TCP stream already had `TCP_NODELAY`. Adding `stream.set_nodelay(true)` to the
accepted SOCKS stream raised the standalone ABBA mean from 17.445 to 20.475
Gbit/s (+17.37%); the final standalone result is 2.56% above Xray. This
identifies the missing local TCP option as the cause of the measured gap in
this loopback setup. It does not establish the same effect on WAN links.

The fixed 20-second matrices also captured process resources:

| Profile | Client CPU per 20-second cell | Approx. CPU cores | Peak RSS | Release binary |
| --- | ---: | ---: | ---: | ---: |
| Xray client, two-cell average | 13.45 s | 0.673 | 49,394 KiB | 32,260,220 bytes |
| Product Chimera, two-cell average | 17.54 s | 0.877 | 24,618 KiB | 15,623,264 bytes |
| Standalone Chimera after alignment, two-cell average | 15.37 s | 0.768 | 12,986 KiB | 2,020,640 bytes |

The standalone profile used about 14.2% more client CPU than Xray at the
measured rate, while its peak RSS was 73.7% lower. Its binary was 87.1% smaller
than the product build. The product result used about 32.2% more CPU than Xray
and about half the Xray peak RSS. These figures are local process observations,
not normalized CPU-per-byte benchmarks.

A full-content smoke was then run with `full_verify=true`, inner TLS, 4
concurrent connections, 3 measured runs, 4 MiB upload and 16 MiB download per
connection. Both clients completed all 12 connections and passed the payload
checks:

| Client | Result | Verified upload | Verified download |
| --- | --- | ---: | ---: |
| Official Xray 26.11.9 | Pass | 48 MiB | 192 MiB |
| Standalone Chimera REALITY/Vision | Pass | 48 MiB | 192 MiB |

An earlier concurrency-8 Vision download run had reproduced `BadRecordMac` in
the inner TLS target. Source tracing found that the REALITY reader could decrypt
all complete records from one socket read before Vision consumed the VLESS
`CMD_DIRECT` frame. Coalesced raw inner-TLS bytes after that splice boundary
could then be treated as REALITY ciphertext; AEAD authentication failure may
overwrite its in-place input buffer. The fix stops after one application
record, lets Vision consume the frame and switch to raw mode, and processes any
remaining complete REALITY record from the in-memory buffer before polling the
socket again. The latter is necessary to avoid waiting indefinitely when a
socket read already coalesced multiple valid records.

Regression coverage includes preservation of raw bytes after one app record
and an async stream test that supplies two valid encrypted app records in one
read, then returns `Pending` forever. The second record must still be
delivered. `chimera-reality-core` passed 166 tests with
`reality,vless,vision` and 142 with `reality,vless`; the async regression and
the existing raw-boundary regression passed. An independent L2 code review
found no blocker in the final read progression or splice ordering. The final
product and standalone Xray ABBA logs contained no `BadRecordMac` or generator
decrypt failures.

The matrices are loopback-only and were run on a dirty source tree. Bulk
payload-pattern verification was disabled to protect the throughput path; the
separate verified smoke covers content integrity at lower concurrency. They do
not measure remote node, WAN latency or loss, TUN, DNS, routing, REALITY server
throughput, or long-duration stability. Raw manifests, logs, and results stay
under `本机临时目录`; temporary credentials
and configs were not copied into the repository.

## REALITY/Vision TCP copy-buffer ablation

To test whether the remaining client CPU cost is sensitive to the relay loop,
the standalone REALITY/Vision benchmark client gained a diagnostic
`--copy-buffer-size` option (4 KiB through 1 MiB; default 64 KiB). This changes
only the two buffers passed to Tokio's
`copy_bidirectional_with_sizes`; it does not change the production default.
The corresponding product setting already exists as
`experimental.tcp-buffer-size`, whose default is 64 KiB.

Both matrices ran on the same Linux 6.18 / x86_64 host against the
same Xray 26.11.9 REALITY server and inner-TLS target. The standalone matrix
used 8 concurrent connections, 1 MiB upload and 2 GiB download per connection,
and 3 measured runs per cell (48 GiB downloaded per cell). The product matrix
used 8 concurrent streams, a 20-second duration and 5 generator runs per cell;
it delivered 41.5–44.5 GiB per cell. Cells were mirrored around the Xray
control to expose order drift. Payload-pattern checks were disabled in these
throughput matrices; see the integrity check below. Reported client CPU is
process CPU time divided by successfully delivered download GiB. RSS is the
mean peak resident set across the paired cells. CV is the mean within-cell
variation reported by the generator.

### Standalone protocol-core client

| Client profile | Copy buffer | Mean download | Delta vs Xray | Client CPU / GiB | Mean peak RSS | Mean cell CV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Xray 26.11.9 | — | 20.422 Gbit/s | baseline | 0.247 s | 39.6 MiB | 1.30% |
| Chimera REALITY/Vision | 4 KiB | 14.714 Gbit/s | -27.95% | 1.930 s | 5.9 MiB | 1.25% |
| Chimera REALITY/Vision | 64 KiB | 20.694 Gbit/s | +1.33% | 0.335 s | 7.4 MiB | 0.75% |
| Chimera REALITY/Vision | 256 KiB | 20.250 Gbit/s | -0.84% | 0.295 s | 8.6 MiB | 1.05% |
| Chimera REALITY/Vision | 1 MiB | 20.414 Gbit/s | -0.04% | 0.299 s | 13.1 MiB | 0.65% |

The 4 KiB result repeated in both mirrored cells: throughput fell about 28%
and CPU per GiB rose by about 5.8 times compared with 64 KiB. The relay
buffer size is therefore a real throughput control in this workload. At
256 KiB the standalone client stayed within 1% of Xray while using about 12%
less CPU per GiB than its 64 KiB profile. A 1 MiB buffer gave no material
additional CPU reduction and raised peak RSS.

### Product `clash-rs` client

| Client profile | Configured copy buffer | Mean download | Delta vs Xray | Client CPU / GiB | Mean peak RSS | Mean cell CV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Xray 26.11.9 | — | 20.020 Gbit/s | baseline | 0.304 s | 45.4 MiB | 2.95% |
| Chimera product | default 64 KiB | 20.179 Gbit/s | +0.80% | 0.394 s | 23.1 MiB | 3.60% |
| Chimera product | 256 KiB | 19.927 Gbit/s | -0.47% | 0.370 s | 29.0 MiB | 2.80% |
| Chimera product | 1 MiB | 19.847 Gbit/s | -0.86% | 0.385 s | 56.2 MiB | 2.70% |

The product's 256 KiB cells both used less CPU than the paired 64 KiB cells
(about 6% lower CPU per GiB), with about 5.8 MiB higher peak RSS at this test
load. Its mean throughput point estimate was 1.25% below 64 KiB, smaller than
the 2.8–3.6% within-cell variation, so this run does not establish a real
throughput regression. At 1 MiB, RSS more than doubled relative to the default
without a further CPU benefit. Keep 64 KiB as the product default for now;
256 KiB is a promising explicit setting to recheck under WAN conditions and
higher connection counts, where its memory cost can be measured.

A separate full-content matrix used Xray, product 64 KiB, and product 256 KiB
with verification enabled. Each completed 12 connections and verified 48 MiB
uploaded plus 192 MiB downloaded. All three matrix cells exited successfully.

These results do not locate the remaining CPU gap: at 256 KiB the standalone
and product clients still used about 19% and 22% more client CPU per GiB than
their respective Xray controls. `perf stat` attachment counters from this host
were inconsistent with the process CPU measurements, and the sampled profile
did not resolve most kernel frames; neither is used here to claim a code
hotspot. Source inspection does identify a candidate path to measure: the
Linux `zero_copy` branch only accepts an inbound `TcpStream` and an outbound
`ChainedStreamWrapper<TcpStream>`. VLESS Vision instead returns a chained
`AnyStream` containing `VisionStream -> VlessStream -> SplicableTlsStream`,
so the current downcast cannot select that branch even after Vision switches
to raw TCP mode. This is a confirmed type-path limitation, not proof that it
accounts for the remaining CPU gap. The next step is to test whether a safe
post-splice socket view can reach both TCP sockets after all Vision, VLESS,
and REALITY buffers are empty, then measure the fallback and splice paths
separately. The server CPU was not separately profiled. This is local-loopback
evidence; it does not establish WAN behavior or the best default for
high-concurrency deployments.

## Product REALITY/Vision zero-copy feature ablation

The CLI previously had no feature alias for `clash-lib/zero_copy`, making it
impossible to compare that Linux-only dispatcher path in a minimal product
build. The CLI now exposes `zero_copy` as an opt-in feature. It is deliberately
not added to `standard` or the default profile. The tested release profiles
were `reality,mixed_port` and `reality,mixed_port,zero_copy`; both came from
候选源码快照包含本地修改 commit `[源码快照已省略]` and used
the same Xray 26.11.9 REALITY server and inner-TLS loopback target on the
Linux 6.18 / x86_64 host.

The ABBA schedule was Xray control, Chimera without the feature, Chimera with
the feature twice, Chimera without it, then Xray control. Each product cell ran
8 concurrent connections for 20 seconds, with one warmup, 1 MiB uploaded and
64 MiB downloaded per connection per generator run. The generator completed
87–89 measured runs (43.5–44.5 GiB of downloads) per cell. Full payload-pattern
verification was off for this throughput matrix; the separate one-connection
integrity smoke verified 1 MiB uploaded and 16 MiB downloaded for each Chimera
profile. All six throughput cells and both integrity smokes exited successfully.

| Client profile | Mean per-cell median download | Delta vs Xray | Client CPU / downloaded GiB | Mean peak RSS | Mean within-cell CV |
| --- | ---: | ---: | ---: | ---: | ---: |
| Xray 26.11.9 control | 19.701 Gbit/s | baseline | 0.318 s | 45.6 MiB | 3.15% |
| Chimera, `zero_copy` off | 20.214 Gbit/s | +2.60% | 0.400 s | 24.1 MiB | 3.05% |
| Chimera, `zero_copy` on | 19.902 Gbit/s | +1.02% | 0.404 s | 22.7 MiB | 3.45% |

The feature-on point estimate is 1.54% below the feature-off mean. That is not
evidence of a regression: the two Xray control cells themselves differed by
1.86%, and per-cell run CV was 2.9–3.5%. The result shows no measurable
throughput or CPU benefit for this REALITY/Vision path. The feature-on binary
was 8,648 bytes larger (15,631,912 vs. 15,623,264 bytes). Client CPU remained
about 0.40 seconds per downloaded GiB, roughly 27% above the Xray client in
this test; this A/B does not explain that remaining cost.

To check branch selection, a separate `RUST_LOG=trace` smoke made one
full-content-verified REALITY/Vision request. The trace filter was confirmed
active, but the exact event `using zero copy for bidirectional copy` appeared
zero times. The dispatcher tries the Linux splice branch only when the inbound
stream downcasts to `tokio::net::TcpStream` and the outbound stream downcasts to
`ChainedStreamWrapper<TcpStream>`; otherwise it uses the buffered copy path
([`common/io/mod.rs`](../../clash-lib/src/common/io/mod.rs#L412)). VLESS Vision
wraps its VLESS stream in `VisionStream` before the dispatcher receives it
([`vless/mod.rs`](../../clash-lib/src/proxy/vless/mod.rs#L137)). The trace and
the source types agree: enabling the feature compiles the splice code, but this
protocol path does not reach it. Do not treat this result as a test of splice
performance. A future splice experiment needs a safe way to expose the raw TCP
sockets only after protocol buffers are empty, then a separate test proving
that selection before measuring it.

The private matrix manifests, logs and raw results remain under
`本机临时目录` and
`本机临时目录`; configs and credentials
were not copied into this repository. This is local-loopback evidence only; it
does not measure remote node/WAN behavior or Chimera Server performance.

## TrackedStream zero-byte accounting A/B

The REALITY/Vision product profile spends part of its data-path time in
`TrackedStream::poll_read` and `poll_write`. Those methods previously called
traffic-statistics and per-flow atomic counters even when an I/O poll delivered
zero bytes. The candidate guards those updates with `bytes > 0`. Positive-byte
accounting and the stream result are unchanged; `TrafficProof::received(0)` was
already a no-op.

This check used the release `clash-rs` profile with no default features and
`reality,mixed_port`, against the same Xray 26.11.9 REALITY/Vision server and
inner-TLS target on loopback. The Linux 6.18 / x86_64 host ran one Xray
control at each end and four baseline/four candidate cells in an interleaved
order. Each product cell used 8 concurrent connections, 1 MiB upload and
64 MiB download per connection per generator round, and a 20-second measured
duration. Payload verification was disabled in this throughput matrix. All ten
cells completed with exit code 0 and delivered 664–712 connections (about
41.5–44.5 GiB downloaded per cell).

| Profile | Median download | Median upload | Client CPU / downloaded GiB | Median peak RSS | Median within-cell download CV |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline, 4 cells | 20.003 Gbit/s | 14.890 Gbit/s | 0.405 s | 24.26 MiB | 3.45% |
| Zero-byte accounting guard, 4 cells | 20.079 Gbit/s | 15.136 Gbit/s | 0.400 s | 23.96 MiB | 3.20% |

The candidate point estimates are +0.38% for download, +1.66% for upload,
-1.10% CPU per downloaded GiB, and -1.23% peak RSS. These are not a confirmed
throughput improvement: the baseline cells varied by up to 5.4% in paired
download comparisons, and the first/last Xray controls differed by -3.84% in
download. No direction has a repeatable gain large enough to separate from
this run's variation. The change removes redundant zero-value atomic updates
in the pending/empty-I/O path, but it does not explain the product's broader
CPU-per-GiB gap against the standalone protocol-core client.

Separate one-connection smokes for baseline and candidate each uploaded and
downloaded 1 MiB with full content verification enabled; both matrix cells
completed with exit code 0. The direct regression test
`cargo test --locked -p clash-lib --lib tracked_stream_counts_only_transferred_bytes`
passed. It checks `Pending`, zero-byte write, positive read/write, EOF, and
write-error results against both per-flow and global byte totals. The test
guards accounting behavior; the zero-RMW fast path itself is visible in the
source branch and was not established as a measurable throughput gain. Also
passed: `cargo fmt --all -- --check`, `git diff --check`, and
`python3 ci/check-feature-forwarding.py`.

The baseline binary BLAKE3 was
`deaaaa223db346995f4fbfca27139befeb83ef57b765a9d08d2811bbe47b24b4`; the
candidate was
`8620599167d52d62388eb16d0bf9d25c6c49846494851b705ab13c8053668606`. Both
used the same REALITY feature selection and benchmark configuration. Raw
manifests and results remain under
`本机临时目录`; credentials
and generated client configurations remain outside the repository. This is a
local-loopback client measurement, not WAN or server-throughput evidence.

To keep the transport-core route reproducible while this product-path change is
measured, both extracted protocol binaries were also rebuilt from this
worktree: `cargo build --release --locked --no-default-features -p
chimera-reality-protocol-perf-client --features vision` and
`cargo build --release --locked -p chimera-hy2-protocol-perf-client --features
aws-lc-rs`. Both start successfully and their locked `cargo tree -e no-dev`
graphs contain no `clash-lib`, DNS, netstack, Hyper, or Hickory package. They
contain 79 REALITY/Vision and 92 HY2 package-version nodes; the resulting
release executables are 2,023,072 and 3,219,104 bytes. These binaries share the
production protocol cores but bypass `TrackedStream`, so they isolate transport
performance and cannot by themselves measure the effect of this statistics
change. The product A/B above is the measurement for that change.

## Relay-copy and outbound-accounting ablation

The earlier 7.69% HY2 upload difference between the full runtime and the
direct-handler harness did not identify which part of the shorter path helped.
This follow-up keeps the same direct production handler, client executable,
server, target, generator, and SOCKS bridge, then changes only the relay after
the outbound connection is established:

- `tokio`: Tokio `copy_bidirectional_with_sizes` with 64 KiB buffers.
- `product-copy`: production `TrackedStream` around the outbound stream plus
  `copy_bidirectional_with_report`, also with 64 KiB buffers, 10-second
  half-close timeouts, and `ShutdownMode::HalfClose`.

The measured code is the direct-handler harness, not the standalone
`chimera-hy2-protocol-perf-client` or `chimera-reality-protocol-perf-client`.
It uses production HY2 or VLESS/REALITY outbound handlers, but it does not
start the full runtime or include dispatcher routing decisions, traffic proof,
inbound connection tracking, DNS, or Controller services. The ablation
therefore tests whether the production outbound tracker and relay-copy loop
explain the earlier difference; it does not measure every cost of the full
product dispatcher.

### First ABBA matrices

The client, Chimera HY2/REALITY server, TLS target, generator, and benchmark
runner all ran on the local x86_64 host host over loopback. Each protocol and
direction used four cells in ABBA order (`tokio-a`, `product-copy-a`,
`product-copy-b`, `tokio-b`). Each cell had one warmup and five measured rounds;
each measured round used 8 concurrent TCP streams, 256 MiB per stream in the
main direction and 1 MiB in reverse. Thus every cell delivered 10 GiB of
measured main-direction bytes and completed 40 connections. The 64 KiB relay
buffers, inner TLS, and TCP_NODELAY were fixed. Bulk verification was disabled;
separate 1 MiB full-content verification smokes passed for both relay modes
with each protocol. All sixteen throughput cells completed with exit code 0.

The table uses the ten measured per-round aggregate rates from the two cells
for each mode. CV is population standard deviation divided by the mean across
those ten rates. Mbps is decimal. Only the main, 256 MiB direction is
interpreted; the 1 MiB reverse transfer is too short for a useful rate
comparison.

| Protocol | Direction | Tokio median (CV) | Product-copy median (CV) | Difference |
| --- | --- | ---: | ---: | ---: |
| HY2 | Upload | 3,472.800 Mbps (1.32%) | 3,483.003 Mbps (0.86%) | +0.29% |
| HY2 | Download | 4,190.003 Mbps (3.46%) | 4,323.956 Mbps (2.26%) | +3.20% |
| VLESS + REALITY + Vision | Upload | 21,423.253 Mbps (1.70%) | 21,692.751 Mbps (2.10%) | +1.26% |
| VLESS + REALITY + Vision | Download | 21,247.603 Mbps (2.35%) | 20,753.518 Mbps (2.03%) | -2.33% |

The HY2 download result initially looked like a repeatable gain: both product
cells exceeded the corresponding Tokio cells. We repeated that direction with
512 MiB per connection, keeping 8-way concurrency and five measured rounds
per cell (20 GiB per cell). All four confirmation cells completed. Across ten
measured rates per mode, Tokio reached 4,217.980 Mbps median (1.44% CV) and
product-copy reached 4,188.054 Mbps (-0.71% by median; 2.99% CV). The paired
cell differences reversed direction: product-copy-a was 3.00% below tokio-a,
while product-copy-b was 1.68% above tokio-b. The original +3.20% result did
not reproduce under the longer workload.

Taken together, these matrices do not establish a stable throughput gain or
regression from `TrackedStream` plus the production relay-copy loop. They
weaken the hypothesis that this relay layer explains the earlier 7.69% HY2
upload difference. They also do not prove the entire dispatcher is free of
overhead: the harness still omits routing, traffic proof, inbound tracking,
network-path selection, and full runtime integration. CPU and memory monitoring
were disabled, so this result is throughput-only.

The full-verification smoke and all raw matrix artifacts remain outside the
repository under `本机临时目录`. The manifests
pin the client, server, generator, and target by BLAKE3. The measured HY2
direct-handler client was
`c83fcb4f6a41ebe903bf90e9f150eb1ca6181296f552f412fb04156c23c683cd` and the
REALITY client was
`9c7ececcbcc82d4bac671e9d23cdd5a94de52ea08141394ffb0a2d02223edaef`. They
used the same HY2 server (`f4b32427c3f58a565436d8cb639f933b1a99425595587429067a294fa190539d`)
or REALITY server (`681c36811f4e61e6c7ffec467a1f4325461fab9f651d85d4d4495ec77f4696ab`),
generator (`2e2ef448f49ef28ea389ddf7704b79c5f9c6faebd0e71839fcc4299fc7a9832e`),
and TLS target (`017d18122e399eb22e8b0713f6b8db5e0eb125da62682d5085269e9b7c410dd8`).
Generated configs and credentials were not copied into the repository.

## HY2 chained-stream wrapper ablation

The relay-copy comparison above still returned a production
`ChainedStreamWrapper` in both modes. This follow-up keeps the same direct
production HY2 `Handler`, connector-selected QUIC socket, authenticated
connection, `HysteriaClient::open_tcp_stream`, SOCKS bridge, Tokio copy loop,
server, target, and generator. The `tokio` mode returns the normal wrapped
stream; the `raw-core` mode uses a `transport-bench-api` entry point to return
the same HY2 stream before `ChainedStreamWrapper` adds network-path metadata.
Both modes use 64 KiB Tokio copy buffers. The raw mode is diagnostic-only and
does not alter the production outbound path. Both paths still use trait
objects: the normal path returns `Box<dyn ChainedStream>` around a boxed HY2
`ClientStream`, while raw-core returns `Box<dyn ClientStream>`. The ablation
removes the outer forwarding/metadata wrapper, not dynamic dispatch entirely.

Both paths passed 4 MiB upload and download smoke requests with full TLS target
content verification. The ABBA throughput cells used 8 concurrent streams,
one warmup and five measured rounds per cell, 512 MiB per connection in the
main direction and 1 MiB in reverse. Each cell delivered 20 GiB in its main
direction and completed 40 connections. Full payload verification was off in
these throughput cells; the separate smoke established content correctness.
All eight throughput cells exited successfully. Rates below are medians across
the ten measured per-round aggregate rates from both cells for each mode; CV
is population standard deviation divided by the mean.

| Main direction | Normal wrapper | Raw core stream | Raw-core change | Per-cell paired changes |
| --- | ---: | ---: | ---: | --- |
| Upload | 3,558.677 Mbps (0.89% CV) | 3,571.463 Mbps (0.60% CV) | +0.36% | -0.72%, +1.68% |
| Download | 3,880.453 Mbps (1.70% CV) | 3,964.523 Mbps (1.10% CV) | +2.17% | +2.79%, -0.17% |

This does not show a stable wrapper penalty: upload is effectively unchanged,
and the download pair changes disagree. The second download pair is within
0.2%, while the first pair favors raw-core by 2.8%; the two Tokio control cells
also differ by 3.7%. The earlier standalone protocol-core versus
direct-handler upload gap remains unresolved by this same-handler ablation.
This test does not isolate native versus connector-selected UDP socket setup,
the harness boundary, full-runtime routing, traffic proof, inbound tracking,
CPU, or memory.

The direct-handler client was rebuilt from dirty worktree commit
`[源码快照已省略]`, with `hy2-core` and release
settings; it was 4,247,800 bytes and had BLAKE3
`65d25b5ea31534fc21d5463aa293aefd700c01013b478ee114e12f8f43129522`.
The feature-minimized server remained at BLAKE3
`f4b32427c3f58a565436d8cb639f933b1a99425595587429067a294fa190539d`; the
generator and target remained `2e2ef448f49ef28ea389ddf7704b79c5f9c6faebd0e71839fcc4299fc7a9832e`
and `017d18122e399eb22e8b0713f6b8db5e0eb125da62682d5085269e9b7c410dd8`.
Raw JSONL, logs, and the private test configuration remain under
`本机临时目录`.
This is a controlled loopback ablation, not a WAN result.

The HY2 and REALITY direct-core profiles both passed `cargo check` with
`--no-default-features` and their explicit features. The `hysteria` bootstrap
test `tests::relay_mode_defaults_to_tokio_and_selects_enabled_paths` passed,
including the `raw-core` parser branch. `cargo fmt --all -- --check` and
`git diff --check` also passed.

## HY2 concrete stream and socket-path ablations

The next ablation changed the direct-handler benchmark return type from
`Box<dyn ClientStream>` to the concrete `Hy2TcpStream`. Both `raw-core` and
`raw-concrete` still use the same production `Handler`, connector-selected UDP
socket, authenticated QUIC connection, HY2 TCP stream, Tokio copy loop, and
fixed server/target/generator. Both paths bypass `ChainedStreamWrapper`; this
isolates trait-object dispatch at the copy boundary, not the complete product
outbound path. Each direction used 8 concurrent streams, one warmup, five
measured rounds, 512 MiB per connection in the main direction, and 1 MiB in
reverse. Each cell delivered 20 GiB in its main direction. Paired changes are
concrete relative to boxed:

| Main direction | Boxed raw stream | Concrete stream | Change | Paired changes |
| --- | ---: | ---: | ---: | --- |
| Upload | 3,574.756 Mbps (0.69% CV) | 3,553.668 Mbps (0.78% CV) | -0.59% | -0.37%, -1.04% |
| Download | 3,962.877 Mbps (0.59% CV) | 3,965.945 Mbps (0.95% CV) | +0.08% | -1.83%, +0.42% |

The stream type and dynamic dispatch do not show a repeatable throughput cost
at this workload. Both paths passed 4 MiB full-verification upload and
download smoke requests. Raw results are under
`本机临时目录`.

A separate comparison used the standalone HY2 protocol client's
`socket2-abstract` mode against the production direct Handler's
`raw-concrete` mode. The standalone mode creates an IPv4 socket2 datagram
socket, enables broadcast and nonblocking mode, converts it through Tokio to
the Quinn Tokio runtime, and then calls the HY2 protocol core. This matches the
Linux `DirectConnector` socket setup for the no-source-address, no-interface,
no-protector case; it does not reproduce the Handler's session pool and
network-path checks. Both clients used the same feature-minimized server, TLS
target, and generator. The workload again used 8 streams, one warmup, five
measured rounds, and 20 GiB in the main direction per cell.

| Main direction | Standalone socket2 | Handler concrete | Handler change | Paired Handler changes |
| --- | ---: | ---: | ---: | --- |
| Upload | 3,638.142 Mbps (0.64% CV) | 3,575.469 Mbps (0.93% CV) | -1.72% | -2.01%, -1.65% |
| Download | 3,949.439 Mbps (1.03% CV) | 3,928.461 Mbps (1.53% CV) | -0.53% | +0.21%, +0.99% |

The upload deficit followed the Handler in both pairs, with about 4% more
combined client/server CPU per GiB in that direction; download differences
were small and the paired direction disagreed with the pooled median. This
leaves a small Handler-side or measurement-path difference to investigate,
but does not identify its cause. The test does not establish the same
difference under WAN conditions. Raw results are under
`本机临时目录`.

## HY2 idle UDP receive-task ablation

The `raw-concrete-no-udp-rx` mode was added to test whether
`HysteriaConnection::spawn_tasks`' UDP datagram receive loop affects a
TCP-only workload. It uses the same concrete Handler stream path as
`raw-concrete`, with only the receive task disabled before the first
connection. The switch exists under `transport-bench-api`, defaults to
enabled, and is diagnostic-only; do not use it when testing UDP traffic.

Both modes passed 4 MiB upload and download with full TLS-target content
verification. Throughput used two ABBA pairs per direction (enabled, disabled,
disabled, enabled), 8 concurrent streams, one warmup and five measured rounds
per cell, 512 MiB per connection in the main direction, and 1 MiB in reverse.
That is 20 GiB of measured main-direction traffic and 40 completed connections
per cell. Both directions used a 64 KiB buffer, TCP_NODELAY, and a TLS inner
stream. Rates are medians across ten non-warmup round rates per mode; CV is
population CV across those ten samples. Paired changes are disabled relative
to enabled.

| Main direction | UDP receive task enabled | UDP receive task disabled | Change | Paired changes | Client CPU per GiB, enabled → disabled |
| --- | ---: | ---: | ---: | ---: | ---: |
| Upload | 3,556.936 Mbps (1.23% CV) | 3,559.307 Mbps (0.58% CV) | +0.07% | -1.22%, +0.96% | 3.308 → 3.310 s/GiB |
| Download | 3,989.559 Mbps (0.59% CV) | 3,971.887 Mbps (0.72% CV) | -0.44% | -0.37%, -0.69% | 3.358 → 3.360 s/GiB |

These measurements do not show a material throughput or client-CPU benefit
from skipping the idle UDP receive task. The small download decrease is below
the observed per-cell variation. The earlier roughly 1.7% standalone-versus-
Handler upload gap therefore is not explained by this task. The remaining
candidate is in the Handler/session or benchmark boundary, but further
isolation is needed before calling it a code bottleneck. This result applies
only to loopback TCP streams and says nothing about UDP reception or a real
network.

The client was built from dirty worktree commit
`[源码快照已省略]`; the benchmark binary was 4,255,848
bytes with BLAKE3 `7131c2ad59057d4d751666fb6361e8c61beea00fe70327156879baf2c5398178`.
Server, generator, and TLS target BLAKE3 hashes were
`f4b32427c3f58a565436d8cb639f933b1a99425595587429067a294fa190539d`,
`2e2ef448f49ef28ea389ddf7704b79c5f9c6faebd0e71839fcc4299fc7a9832e`, and
`017d18122e399eb22e8b0713f6b8db5e0eb125da62682d5085269e9b7c410dd8`.
Private configs and raw artifacts remain outside Git under
`本机临时目录`.

The benchmark build and parser checks passed:

```sh
cargo build --locked --release -p chimera-hy2-core-perf-client \
  --no-default-features --features hy2-core
cargo test --locked -p chimera-transport-bench-bootstrap \
  --no-default-features --features 'hysteria,clash-lib/aws-lc-rs' \
  tests::relay_mode_defaults_to_tokio_and_selects_enabled_paths -- --exact
cargo test --locked -p chimera-transport-bench-bootstrap \
  --no-default-features --features 'clash-lib/reality,clash-lib/aws-lc-rs' \
  tests::raw_core_error_lists_only_modes_enabled_in_this_profile -- --exact
git diff --check
```

## HY2 Handler socket2 versus connector socket path

To test whether the earlier standalone-protocol client's upload lead came from
Quinn's UDP socket setup, a benchmark-only `raw-concrete-socket2-no-udp-rx`
mode was added. Both variants use the production `Handler`, concrete
`Hy2TcpStream`, the same authenticated HY2 session and 64 KiB Tokio relay loop,
and both skip the idle UDP receive task. The only intended difference is the
socket creation path: A uses the production connector-selected UDP socket; B
forces the standalone client's socket2 → std → Tokio → std → Quinn wrapping
sequence. B is refused for non-loopback endpoints, interface binding, port
hopping, obfuscation, and Linux socket marks. The branch exists only behind
`transport-bench-api`.

Both variants first passed 4 MiB upload and download with full TLS-target
content verification. Throughput then used ABBA order (A, B, B, A) separately
for each direction, 8 concurrent streams, one warmup and five measured runs
per cell, 512 MiB per connection in the main direction and 1 MiB in reverse.
Each cell delivered 20 GiB measured main-direction data across 40 completed
connections. The buffer was 64 KiB, with inner TLS and TCP_NODELAY enabled.
Rates and CV below use the ten non-warmup per-run samples per variant. Pair
deltas compare the median rate for the adjacent A/B cells in each ABBA pair.

| Main direction | Connector socket median (CV) | Forced socket2 median (CV) | Socket2 change | Paired socket2 changes | Client CPU, connector → socket2* |
| --- | ---: | ---: | ---: | ---: | ---: |
| Upload | 3,579.926 Mbps (0.74%) | 3,545.275 Mbps (0.70%) | -0.97% | -1.20%, -0.90% | 3.295 → 3.328 s/GiB (+1.02%) |
| Download | 4,002.390 Mbps (0.79%) | 3,967.713 Mbps (0.60%) | -0.87% | +0.15%, -1.61% | 3.365 → 3.368 s/GiB (+0.09%) |

*CPU combines both cells for each variant and divides their combined CPU delta
by 40 GiB of measured main-direction payload (20 GiB per cell). The generator's
CPU delta starts at client startup and includes each cell's warmup run, so this
is not a pure measured-run CPU counter.

The forced socket2 path did not recover the standalone client's earlier upload
lead. It was about 1% slower than the connector path in both pooled directions;
the two upload pairs agreed, while the download pairs disagreed. This points
away from connector socket creation as the cause of the earlier roughly 2%
standalone-versus-Handler upload gap, but does not explain that residual. The
remaining useful isolation is around the Handler's connection pool checkout,
network-path context validation, and the two benchmark SOCKS/runtime boundaries.
Do not treat the sub-1% pooled download change as a stable effect.

The socket2-mode guard runs before the port-hopping branch, so a configured
port range cannot silently select `UdpHop` while retaining the socket2 mode
label. A targeted runtime negative check added `ports: "35476-35477"` to a
temporary client profile; the client returned the expected unsupported-context
error before trying the UDP-hop connection. The loopback throughput workload
used the original non-hopping HY2 profile.
The preflight-order fix was made after that socket-path matrix; since its
profile had no port range, it does not change the recorded throughput path.
The matched protocol-core comparison below uses the rebuilt Handler with the
preflight fix.

The Handler binary was 4,257,560 bytes, SHA-256
`7e680d452246b62b5a83b006677a597832f25e951a4779a191a4306bb3ca2c63`.
It was built from Client worktree HEAD
`[源码快照已省略]` with a 候选源码快照包含本地修改. The
fixed Chimera Server executable was 17,443,360 bytes, SHA-256
`c24fd37b1365412df9f902bfd761c428dd100bd0a23d38598d226a49a6fcc997`;
it came from dirty Server worktree HEAD
`[源码快照已省略]`. The target and generator SHA-256
hashes were `ab4f97296b28af2afa4f8500529796bd51f9710d33f11f6ac4ca7b4e6790228e`
and `8195e43c63e967cb25181b865acf9d23c7837746aefb3648ff056555e83782be`.
The private server and client config SHA-256 hashes were
`61b28ea89548eba4866544ea851e3e2eb6e6b929d8531b4cbd1dbf4903dec654` and
`adfdbe424442b04a2f5dcd563974e0c9352907bd850c98e0d9b4bfb8239e8ade`.
Raw generator JSONL and process logs are under
`本机临时目录`;
private config files remain outside Git.

The release benchmark build and both relay-mode parser tests passed, as did
`cargo check -p clash-lib --no-default-features --features 'hysteria,aws-lc-rs'`
without the benchmark API. The targeted `clash-lib` unit test for the new
context guard was attempted but could not compile the test target: the existing
`TunCandidateExclusion::Named` variant in `clash-lib/src/app/network.rs` is
reported as dead code under this no-TUN test profile and workspace
`-D warnings`. No unrelated feature or lint allowance was added to bypass it. The
runtime negative check above covers the port-hopping fall-through case. The
throughput comparison does not measure WAN loss/RTT, real-interface binding,
UDP datagram service, port-hopping throughput, or socket protection. The first
runner attempt stopped before a transfer because `b3sum` was unavailable; the
completed retry used SHA-256 for binary identity and ran all smoke and
throughput cells.

## Matched standalone HY2 core versus production Handler

The previous protocol-core versus Handler ABBA showed a larger upload
difference than the socket-path ablation could explain. This follow-up compared
the standalone `chimera-hysteria2-core` client directly with the production
HY2 Handler behind the direct-core benchmark bootstrap, forced to the same
socket2 → Tokio → Quinn socket setup. The Handler used
`raw-concrete-socket2-no-udp-rx`; both used a concrete HY2 stream, the same SOCKS
relay loop with 64 KiB buffers, the same feature-minimized Chimera Server, TLS
target, and generator. Both passed 4 MiB upload and download smoke tests with
full-content verification.

The ABBA sequence was standalone, Handler, Handler, standalone for each
direction. Each cell used 8 concurrent streams, one warmup, five measured runs,
512 MiB per connection in the main direction, 1 MiB in reverse, inner TLS, and
TCP_NODELAY. Each cell delivered 20 GiB measured main-direction data across 40
completed connections. Rates and CV use the ten non-warmup run samples per
client. Paired changes compare the Handler cell median with the adjacent
standalone cell median.

| Main direction | Standalone protocol core median (CV) | Production Handler, same socket (CV) | Handler change | Paired Handler changes |
| --- | ---: | ---: | ---: | ---: |
| Upload | 3,585.529 Mbps (0.88%) | 3,557.593 Mbps (0.86%) | -0.78% | -1.57%, -0.74% |
| Download | 4,024.206 Mbps (0.69%) | 4,017.974 Mbps (0.99%) | -0.16% | +0.01%, +0.03% |

The earlier comparison was `earlier protocol-vs-handler comparison`, with
raw JSONL under
`本机临时目录`.
Its Handler used `raw-concrete-no-udp-rx` and the normal connector socket path;
the first upload pair favored standalone by 2.37%, the second by 3.78%, and
the pooled ten-sample medians were 3,713.931 Mbps for standalone versus
3,600.562 Mbps for Handler (-3.05%). With the Handler forced to the same
socket2 setup as standalone, this matched run reduced the pooled upload gap to
0.78%; its download result moved from +1.15% to -0.16%, further indicating that
the direction of the download difference is not stable. The Handler was still
slightly slower in both upload pairs. This points to a small residual
Handler-side or harness-boundary cost, but the size depends on the exact
comparison path and does not establish a multi-percent HY2 protocol-core
defect. CPU is not compared here because the
standalone client authenticates before its SOCKS listener becomes ready while
the Handler establishes its shared QUIC session lazily; the monitored CPU
windows therefore include different setup work.

The standalone protocol binary was 3,224,328 bytes, SHA-256
`6b7169bee7bc939fc7bdb246e6de7a262b35be959658a3dbcc72ef7475401502`. The
Handler binary was 4,258,080 bytes, SHA-256
`dbb6bd89b606e2cfe930176a978c7e426c1263c6d0befb5213385d634a00a5f1`; both
were built from Client worktree HEAD
`[源码快照已省略]` while the worktree was dirty. The
Server, target, and generator hashes were unchanged from the preceding
socket-path section. The client and server config hashes were also unchanged.
Raw JSONL and logs remain under
`本机临时目录`.

This is a local loopback test against the feature-minimized Chimera Server. It
does not establish the same margin over a WAN, under packet loss, or with
official Hysteria endpoints.

## HY2 QUIC connection sharding with one Endpoint per connection (2026-11-27)

The standalone `chimera-hy2-protocol-perf-client` accepts the benchmark-only
`--quic-connections N` option. It authenticates N independent QUIC connections
and assigns incoming SOCKS TCP streams round-robin. In this first matrix each
connection used its own Quinn Endpoint and UDP socket. A four-connection and an
eight-connection 4 MiB full-content smoke both passed.

The client protocol-core binary has 71 release dependency nodes with the
current locked `aws-lc-rs` profile and does not link `clash-lib`. The server
binary was the independent `chimera-hy2-perf-server` frontend with only its
`hysteria` feature enabled (220 release dependency nodes, 16,313,896 bytes).
It retains the production Server configuration and data path; numeric
addresses kept DNS resolution out of the measured transfer, but this profile
does not remove the shared resolver and routing code from the binary. Both
client and server source worktrees were dirty at HEADs
`[源码快照已省略]` and
`[源码快照已省略]`, respectively.

Each cell used eight concurrent SOCKS TCP streams, inner TLS, TCP_NODELAY,
socket2-created client UDP sockets, and the same local target and config hashes.
Each stream uploaded 512 MiB and downloaded 1 MiB per measured run. The 1 vs 8
ABBA used five measured runs per cell (40 completed streams and 20 GiB of main
direction data per cell); the 2 vs 4 ABBA used three measured runs per cell (24
completed streams and 12 GiB per cell). CV is calculated over all non-warmup
upload samples pooled for that connection count. CPU/GiB uses process CPU
sampled between warmup and the measured runs. RSS is a process peak sampled
every 250 ms, not a kernel high-water mark.

| QUIC connections | Upload median | Gain vs 1 | Pooled CV | Server CPU/GiB | Client CPU/GiB | Peak client RSS | Peak server RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 3,626 Mbps | baseline | 0.84% | 3.92 s | 3.22 s | 28.7 MiB | 27.4 MiB |
| 2 | 6,054 Mbps | +67.0% | 2.89% | 4.37 s | 3.72 s | 45.3 MiB | 42.7 MiB |
| 4 | 10,118 Mbps | +179.0% | 1.70% | 3.35 s | 3.88 s | 77.0 MiB | 24.5 MiB |
| 8 | 12,280 Mbps | +238.7% | 7.58% | 2.57 s | 3.44 s | 142.2 MiB | 60.3 MiB |

The two paired 1 vs 8 comparisons were +237.0% and +239.8%; the two paired
2 vs 4 comparisons were +65.7% and +65.9%. Four connections delivered about
82% of the eight-connection rate, with about 54% of its client RSS in these
cells. The sampled Server RSS was not monotonic across 1/2/4/8, so it should
not be used to claim that four connections reduce Server memory. Eight
connections had materially higher run-to-run variation than four.

Separate 49 Hz server `cycles:u` call-graph samples used the symbol-preserving
release build of the same minimal Server frontend. Both profiles lost zero
samples. `std::sys::sync::mutex::futex::Mutex::lock_contended` accounted for
3.95% of the one-connection profile and 0.73% of the eight-connection profile.
The sampled stack enters from H3 `RecvStream::poll_data`; the Server's locked
Quinn 0.11.9 source takes `connection.state` in
`quinn::RecvStream::poll_read_generic` (`recv_stream.rs:362`). This makes
per-connection Quinn state contention a plausible contributor to the
single-connection ceiling, but this first matrix also increased the number of
Endpoints and UDP sockets with the connection count. Connection sharding
changes congestion control, connection-level flow control, scheduling, and
receive-driver/socket structure, so this test does not attribute the gain to
the mutex alone. At eight connections the leading
Server samples shifted toward AES-GCM (22.50%) and `memmove` (14.00%), leaving
those as follow-up hot paths.

The matching Client call-graph sample used the symbol-preserving standalone
protocol-core release binary. Client `Mutex::lock_contended` was 2.77% with one
QUIC connection and below the report's 0.5% cutoff with eight; its stack names
the mutex as protecting `quinn::connection::State`. Client self samples also
shifted from AES-GCM 12.38%, `memmove` 8.71%, and Quinn
`Connection::poll_transmit` 6.15% at one connection to 14.48%, 12.26%, and
8.04%, respectively, at eight. Each profile had about 4K `cycles:u` samples
and zero lost samples. This independently supports the same per-connection
contention effect on the client, while showing that crypto, copying, and
packet generation become larger costs after sharding. The Client profile
binary SHA-256 is
`f3f2f48e04193177c82783d698be2be5a9d0854ea76d3176bfababb0623b1ce0`; raw
Client reports are under
`本机临时目录`.

Four connections are the best local tradeoff observed so far: about 10.1
Gbit/s, low 1.7% pooled CV, and substantially less client memory than eight.
This remains a same-host loopback result. It does not establish WAN behavior,
fairness against competing flows, recovery under loss, or interoperability
performance with official Hysteria/Xray endpoints. The 1 MiB reverse transfer
is only a harness check, not a download-throughput result. Raw matrices and
reports are under
`本机临时目录`,
`.benchmark-artifact`, and
`.benchmark-artifact`.

## HY2 connection scaling with one shared Endpoint (2026-11-27)

The earlier matrix changed the number of Quinn Endpoints and UDP sockets along
with the QUIC connection count. This follow-up added `--endpoint-mode shared`
and repeated the comparison with one Endpoint, one UDP socket, and one receive
driver per client process. It holds those resources constant while varying the
number of independently authenticated QUIC connections. The same standalone
client, minimal Server, server/target configs, inner-TLS eight-stream workload,
and socket2 UDP setup were used. Each stream uploaded 512 MiB; the 1 MiB reverse
transfer remains a harness check, not download-throughput data.

The q1/q8 ABBA used five measured runs per cell after one warmup; q2/q4 used
three. That yielded 10 samples for q1/q8 and 6 for q2/q4. Each measured run
completed eight streams and 4 GiB of upload; each q1/q8 cell transferred 20 GiB
and each q2/q4 cell transferred 12 GiB. Pooled CV and medians below use all
non-warmup run samples.

| QUIC connections | Upload median | Gain vs 1 | Pooled CV | Server CPU/GiB | Client CPU/GiB | Sampled Server RSS per cell |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 3,674.837 Mbps | baseline | 0.827% | 3.925 s | 3.205 s | 23.9 / 25.3 MiB |
| 2 | 6,226.538 Mbps | +69.4% | 1.924% | 4.239 s | 3.526 s | 48.2 / 28.9 MiB |
| 4 | 10,438.650 Mbps | +184.1% | 1.800% | 3.298 s | 3.656 s | 25.0 / 34.0 MiB |
| 8 | 10,752.273 Mbps | +192.6% | 12.977% | 2.599 s | 3.726 s | 71.9 / 72.1 MiB |

Four connections were about 3.0% below eight, with 1.8% pooled CV versus 13.0%
at eight and much lower sampled Server RSS in both ABBA cells. These are
sampled peaks during each cell, not kernel high-water marks. Four connections
are the stronger local throughput/resource tradeoff in this shared-Endpoint
matrix. This does not establish the best policy over WAN, under loss, or against
competing flows.

Matching 49 Hz `cycles:u` profiles of the symbol-preserving minimal Server
showed `Mutex::lock_contended` at 4.64% of self samples for q1 and 1.23% for q8.
The H3 `RecvStream::poll_data` closure accounted for 2.47% and 2.11%, while
`poll_data` itself was 0.98% and 0.86%. AES-GCM rose from 13.89% to 22.35% and
`memmove` from 7.46% to 14.77%, making crypto and packet copying larger costs
after sharding. Client profiles showed lock contention falling from 2.53% to
below the report's 0.5% cutoff; AES-GCM was 12.58%/12.43%, `memmove`
9.01%/14.36%, and Quinn `Connection::poll_transmit` 6.77%/9.28% for q1/q8.
Both Client and Server profiles had zero lost samples and each profile run
completed 40 measured streams.

Because this experiment kept the Endpoint/socket fixed, its q1-to-q8 result
supports per-connection QUIC state contention as a real contributor. It still
changes congestion-control instances, per-connection flow control and
scheduling; the profile does not prove the mutex is the only cause. The Server
H3 path uses `read_chunk` and returns `Bytes`, so this evidence does not support
moving a full payload copy outside the Quinn connection lock as an optimization
for this path.

The standalone Client release binary was SHA-256
`a8b3fb483bb3da938e19a01dfaa670e7da5fea5e4eb0e0f53efb4f9ebb4203a2` (3,231,552
bytes); the symbol-preserving Client profile binary was
`354aa4a6d179c8dd072a8423c0f2d1580e2b8364269d75a9ead6e017bb46f524`. The
Server profile binary SHA-256 was
`2030ae626d855f08c460d1dc7183e286f79c8b7bb609de67f5844c9b85816afd`. Both
source worktrees were dirty at Client `[源码快照已省略]`
and Server `[源码快照已省略]`; the tested Client source
included the shared-Endpoint benchmark option. Raw throughput data is under
`本机临时目录`
and `.benchmark-artifact`. Client and Server
profiles are under `.benchmark-artifact` and
`.benchmark-artifact`.

## REALITY/Vision zero-copy midstream handoff (2026-11-27)

The previous candidate did not emit a splice event in its smoke log, but that
run filtered `clash_lib::common::io` at `debug` while the handoff event is
`trace`. The absence of that event was not evidence that splice had failed.
With the temporary smoke filter raised to `trace`, the 64 MiB upload and
64 MiB download both passed full-content verification and the log recorded
`using zero copy for bidirectional copy after Vision raw switch`.

This exposed and fixed a REALITY type-erasure mismatch: the product adapter
passed Clash's child stream trait object into the generic REALITY handshake,
while VLESS later downcast the inner stream using `chimera_reality_core`'s
`AnyStream` type. The spliced transport now upcasts to that core stream type
before the handshake. The smoke confirms the resulting runtime path can reach
the raw TCP socket and complete the full transfer.

Feature-boundary checks also exercised the slim crate profiles. The HY2
protocol-core client with `aws-lc-rs`, the REALITY protocol-core client with
Vision and without Vision, the HY2 direct-handler client, and the REALITY
direct-handler client with `zero-copy,splice-diagnostics` all passed locked
feature-specific checks. The first HY2 direct-handler minimal-feature check
found that the REALITY-only readiness helper remained compiled without the
`reality` feature; gating the helper and diagnostic state removed that
`deny(warnings)` failure. HY2 core tests passed 12/12, REALITY/Vision core
tests passed 168/168, and the splice-buffer handoff regression test passed
1/1. These feature checks complement the standalone protocol binaries; they
do not claim that one feature set covers all supported platform combinations.

The independent L2 review found that the new handoff also needed to preserve
`FlushOnly` semantics used by HTTP CONNECT, maintain authenticated per-user
totals, and account for bytes if either splice-side shutdown fails. The relay
now skips all splice entry points for `FlushOnly`; Linux splice trackers add
user upload/download counters, and both shutdown-error paths record bytes
already transferred before returning. Regression tests cover buffered
`FlushOnly`, user totals through splice trackers, and both left- and
right-side shutdown errors. The review found no remaining blocker in this
splice path; it noted that the review did not cover the worktree's separate
HY2 changes.

The throughput comparison used the feature-gated direct production handler,
not the full CLI and not the standalone protocol-core binary. This layer skips
runtime startup, DNS, rules, routing, and Controller setup, but keeps the
production `clash-lib` REALITY/Vision adapters, Linux splice relay, and traffic
tracking. Both profiles used one Xray 26.11.9 server on loopback, an inner TLS
payload target, SOCKS5, eight concurrent streams, 64 KiB relay buffers,
`TCP_NODELAY`, one warmup and five measured runs per cell, and alternating
copy-off / splice / splice / copy-off cells. The download-dominant workload
sent 256 MiB down and 128 MiB up per connection; the upload-dominant workload
reversed those sizes. Each mode therefore has ten measured samples and 30 GiB
of payload in each A/B matrix. All cells passed the runner's 5% CV gate. The
bulk runs count payload bytes but do not hash every byte; the separate full-
content smoke above verifies correctness.

Rates below are pooled medians from ten runs per mode. CPU/GiB divides the
client process CPU measured over both cells by their total transferred
application bytes. RSS is the maximum sampled client process RSS across the
two cells, not the kernel high-water mark.

| Workload and primary direction | Buffered median | Splice median | Change | Primary CV, buffered / splice | Client CPU/GiB, buffered / splice | Sampled peak RSS, buffered / splice |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Download-dominant, download | 16,944 Mbps | 17,271 Mbps | +1.93% | 1.84% / 1.09% | 0.320 / 0.212 s | 11.41 / 11.17 MiB |
| Upload-dominant, upload | 17,122 Mbps | 17,603 Mbps | +2.81% | 1.93% / 1.06% | 0.286 / 0.149 s | 11.82 / 12.05 MiB |

The reverse-direction medians also changed by +5.11% upload in the
download-dominant matrix and +0.54% download in the upload-dominant matrix.
They are concurrent secondary traffic, not the primary result for those rows.
The pooled primary medians were within 3% of the buffered path, while sampled
client CPU per GiB fell by about 34% and 48%. Paired cell medians showed a
smaller and less consistent throughput difference than the pooled medians:
the download pairs were -0.05% and +1.79%; the upload pairs were +0.13% and
+4.14%. The result supports retaining the splice candidate for further
validation, but it does not establish a repeatable large throughput gain. Peak
sampled RSS stayed within about 0.25 MiB of the buffered path in these final
cells.

The exact release binaries were baseline `reality-core` (5,819,520 bytes,
BLAKE3 `d03bc43c906641605057ef63026507d1137b771469f04dfb5ef9c779b5207ea4`)
and candidate `zero-copy` (5,834,848 bytes, BLAKE3
`6834604cebb6102da115416d883d2d7289f937fc2287a3f0e5d1ff7c5234e7f3`). The
diagnostic full-content smoke used a separate binary with BLAKE3
`9a9029d65a07f4cdea97704aec7f45c5dcdac4d9f237e00d43f62d7b953c750b`.
Both were built from dirty Client worktree `[源码快照已省略]`
with Rust/Cargo 1.99.1 on Linux 6.18 / x86_64 host, pinned to CPUs
0–7. The test target was Xray 26.11.9; the separate Chimera HY2 results above
do not apply to this REALITY matrix.

This is host-local loopback evidence, not a physical-NIC or remote-remote node result.
The 64 MiB diagnostic smoke used trace logging and is correctness evidence,
not a throughput sample. The ABBA throughput runs had full-content hashing
disabled and trace logging off. WAN RTT/loss, remote server CPU, GSO/GRO,
concurrent application latency, and long-duration stability remain untested.
The manifests, configs, and credentials remain outside the repository under
`本机临时目录`.
