# HY2 minimal-core cross and connection-scaling results (2026-11-27)

## Findings

The extracted HY2 crate is useful for isolating the protocol data path and makes a much smaller test binary. Removing the general client runtime does not, by itself, raise single-connection throughput: the runtime client, direct production handler, and protocol-core client were within about 2.5% of one another in the matched local workload.

The largest repeatable local throughput change came from using multiple independently authenticated QUIC connections while keeping one client Endpoint and UDP socket. With eight concurrent TCP streams, four QUIC connections were best against the Chimera production server: 12.65 Gbit/s upload and 9.87 Gbit/s download, versus 4.68/5.27 Gbit/s with one connection. Against official Hysteria 2.14.0, eight connections gave the highest rate, but its 14% upload and 4% download improvement over four connections used more client memory. The best connection count therefore depends on the server implementation.

These are host-local loopback results. They do not establish WAN, physical-NIC, GSO/GRO, RTT/loss, or Brutal performance.

## Benchmark setup

- Host: x86_64 host, Linux 6.18; the matrix runner and all children were pinned to CPUs 0–7.
- All transfers used loopback and the same TLS payload target, numeric endpoints, 64 KiB copy buffers, inner TLS, and TCP_NODELAY.
- Main workload: eight concurrent SOCKS TCP streams; each stream transferred 128 MiB up and 128 MiB down per measured run. Rates count successfully transferred application payload bytes, not protocol overhead.
- Connection-scaling profiles used the same Quinn Endpoint and UDP socket, with one, four, or eight separately authenticated QUIC connections. SOCKS streams were assigned round-robin. BBR was used; no Brutal bandwidth cap was configured.
- Each connection-count/server pair ran two counterbalanced cells, each with three warmups and ten measured runs: 20 measured samples per pair. Client-resource and server-resource matrices were run separately with the same schedule. All 12 cells in each matrix completed. The worst individual cell CV was 6.1% in the client-monitor matrix and 9.1% in the server-monitor matrix, below the 12% gate.
- Throughput runs did not perform byte-by-byte verification. Separate full-content smoke matrices did: all six runtime/handler/protocol-core combinations against the two Chimera server shapes passed; all six Chimera/official client and server cross combinations passed; and all six one/four/eight-connection profiles against the Chimera and official servers passed.

The tested Client checkout was **[源码快照已省略]** and dirty; the Server checkout was **[源码快照已省略]** and dirty. Client release builds used Rust/Cargo 1.99.1; Server release builds used Rust/Cargo 1.98.0. The official reference was Hysteria 2.14.0, commit **c2b181e0b0e72b077e4b0b7297735af14d1f9929**, with quic-go **v0.65.1-0.20261109005002-2895f039137a**.

## Chimera client layers × Chimera server layers

This matched matrix uses one QUIC connection, c8 traffic, ten measured samples per pair, and the BBR profiles. Rates are median application payload Gbit/s. Server CPU is average process cores during measured runs; RSS is the highest sampled process RSS in the cell pair.

| Client path | Server path | Upload / download | Server CPU cores | Server sampled peak RSS |
| --- | --- | ---: | ---: | ---: |
| Full runtime | Extracted HY2 BBR core | 4.615 / 5.314 | 1.341 | 25.3 MiB |
| Full runtime | Feature-minimal production | 4.564 / 5.223 | 1.336 | 34.5 MiB |
| Direct production handler | Extracted HY2 BBR core | 4.518 / 5.415 | 1.364 | 27.5 MiB |
| Direct production handler | Feature-minimal production | 4.576 / 5.290 | 1.349 | 31.9 MiB |
| Extracted protocol-core client | Extracted HY2 BBR core | 4.602 / 5.344 | 1.363 | 27.4 MiB |
| Extracted protocol-core client | Feature-minimal production | 4.628 / 5.332 | 1.362 | 32.3 MiB |

The per-pair throughput CVs were 0.6–5.4%. Client-layer changes stayed within 2.5% in each direction, and the two Chimera server shapes stayed within 2.4% for a fixed client. This does not show a repeatable forwarding penalty from the full runtime or production server adapter in this workload.

The protocol-core client uses Quinn's native UDP Endpoint; the production handler uses its connector-selected socket. A separate socket-matched ABBA in the [local loopback report](RESULTS_LOCAL_LOOPBACK_2026-11-26.md) found the direct handler within 0.8% upload and 0.2% download of the protocol core. Treat this table as a comparison of executable paths, not a perfectly identical socket-initialization path.

The release binaries were:

| Binary | Size | BLAKE3 |
| --- | ---: | --- |
| chimera-hy2-perf-client (runtime) | 15,206,104 bytes | 5cf7ef7ee25cc89a43761bc37ed191d010e5e14d4100941b9c88eb2f026a2403 |
| chimera-hy2-core-perf-client (direct handler) | 4,259,032 bytes | 05b39f11d21567929f28950fd32866eaaee73aaddf1a9b231eacdb6ca7e56daa |
| chimera-hy2-protocol-perf-client | 3,231,552 bytes | e46cdb5473bc94c4a4ab43b98aa6386b9fac8771e355480e9b92f20cda3f39b4 |
| chimera-hy2-core-perf-server (BBR) | 4,875,776 bytes | 0273ef18521ff62c47195812d7bf7204961313928b4ca97701b4c2cb698ded50 |
| chimera-hy2-perf-server (production) | 16,316,408 bytes | 80eb242bee533b533524f5b6c46a7617ad0c1137df19784154e234a006c5ed4a |
| Hysteria 2.14.0 client/server | 25,149,602 bytes | 70db925e1fa43f52ba502687940a936a4d8948c5607cf2a93a719049a8650978 |
| TLS payload target | 5,899,992 bytes | 0e9a5972f77c7597b832b4eb560c99785a18c69e8d1bf981a993147d26e13b01 |
| Traffic generator | 4,052,496 bytes | 2e2ef448f49ef28ea389ddf7704b79c5f9c6faebd0e71839fcc4299fc7a9832e |

The protocol-core client is 78.8% smaller than the runtime-front-end binary; its separately monitored RSS was 18.4–20.0 MiB versus 29.1–30.0 MiB for the runtime client. Average client CPU was about 1.32–1.36 cores for all three client shapes. These size and memory savings are useful for focused benchmarks, but they did not translate into higher one-connection throughput.

## Client and server cross matrix

This matrix uses the protocol-core Chimera client, official Hysteria client, both Chimera server shapes, and the official Hysteria server. Each row has ten measured samples. CPU columns come from the corresponding process-monitor run.

| Client | Server | Upload / download | Client CPU cores | Server CPU cores |
| --- | --- | ---: | ---: | ---: |
| Chimera protocol core | Chimera production | 4.651 / 5.361 Gbit/s | 1.319 | 1.345 |
| Chimera protocol core | Chimera extracted BBR core | 4.637 / 5.346 Gbit/s | 1.361 | 1.361 |
| Official Hysteria 2.14.0 | Chimera production | 6.303 / 3.711 Gbit/s | 2.008 | 1.113 |
| Official Hysteria 2.14.0 | Chimera extracted BBR core | 6.493 / 3.790 Gbit/s | 2.048 | 1.101 |
| Chimera protocol core | Official Hysteria 2.14.0 | 3.471 / 6.338 Gbit/s | 1.076 | 1.938 |
| Official Hysteria 2.14.0 | Official Hysteria 2.14.0 | 5.484 / 5.330 Gbit/s | 1.921 | 1.834 |

The rates follow the client/server pairing and direction: the official client had higher upload against Chimera's servers, while the Chimera client had higher download against the official server. The official client also used more client CPU in this c8 run. These data do not support a single overall winner or attributing the directional differences to the Chimera server alone. The Chimera production and extracted server remained close for a fixed client.

## QUIC connection-count matrix

The table below uses the uniform 20-sample c8 matrix. CV is pooled across the 20 measured runs. Client and server process resources were sampled in separate, otherwise matched matrices. CPU/GiB is process CPU time divided by total successfully transferred upload plus download payload.

| Server | QUIC connections | Upload / download Gbit/s | Pooled CV up / down | Client / server CPU cores | Client / server CPU s/GiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chimera production | 1 | 4.682 / 5.273 | 2.5% / 2.3% | 1.320 / 1.364 | 2.312 / 2.417 |
| Chimera production | 4 | **12.651 / 9.872** | 4.5% / 2.5% | 2.383 / 2.535 | 1.873 / 1.949 |
| Chimera production | 8 | 11.813 / 9.556 | 5.1% / 2.0% | 2.317 / 2.557 | 1.909 / 2.076 |
| Official Hysteria 2.14.0 | 1 | 3.471 / 6.370 | 2.9% / 5.8% | 1.088 / 1.951 | 2.085 / 3.708 |
| Official Hysteria 2.14.0 | 4 | 8.253 / 8.320 | 3.6% / 2.8% | 1.751 / 2.547 | 1.825 / 2.654 |
| Official Hysteria 2.14.0 | 8 | **9.377 / 8.624** | 2.4% / 3.3% | 1.794 / 2.584 | 1.743 / 2.529 |

| Server | QUIC connections | Client sampled peak RSS / HWM | Server sampled peak RSS / HWM |
| --- | ---: | ---: | ---: |
| Chimera production | 1 | 24.4 / 32.6 MiB | 37.4 / 39.2 MiB |
| Chimera production | 4 | 75.2 / 85.1 MiB | 84.8 / 110.2 MiB |
| Chimera production | 8 | 89.2 / 115.3 MiB | 78.5 / 88.5 MiB |
| Official Hysteria 2.14.0 | 1 | 32.4 / 39.4 MiB | 29.7 / 42.6 MiB |
| Official Hysteria 2.14.0 | 4 | 74.3 / 89.5 MiB | 31.7 / 54.2 MiB |
| Official Hysteria 2.14.0 | 8 | 81.9 / 123.8 MiB | 36.7 / 54.1 MiB |

Against the Chimera production server, four connections improved upload by 170% and download by 87% over one; eight connections were 6.6% slower upload and 3.2% slower download than four. Four also had lower client memory than eight. Against official Hysteria, eight connections improved upload by 13.6% and download by 3.7% over four, with nearly the same process CPU but higher client peak RSS/HWM. The server-dependent result argues for a configurable pool size and a conservative default until WAN and competing-flow tests are available.

The connection-count test changes the number of QUIC congestion-control and flow-control contexts and the number of TCP streams assigned to each context. It therefore identifies connection sharding as an effective local lever, but does not isolate a single Quinn lock or claim that mutex contention is the sole cause. Earlier symbol-preserving profiles in [the local loopback report](RESULTS_LOCAL_LOOPBACK_2026-11-26.md) found Quinn connection-state mutex contention falling as connection count increased while the Endpoint and socket remained shared; this is supporting evidence, not proof of exclusive causality.

## Anomalies and limits

An initial five-run official-server q8 cell exceeded the configured CV gate at 36.9% upload CV. It was rejected, then repeated with three warmups and ten measured runs per cell; the subsequent uniform matrix completed all 20 samples for that pair with 2.4% pooled upload CV. The rejected cell is not included in the table.

All connection-count results in the matrix above are local loopback with BBR. They do not measure real-network throughput, physical NIC offloads, GSO/GRO toggles, network RTT or loss, Brutal congestion control, UDP relay traffic, fairness against an independent competing flow, or browser/API latency under download load. At the time of that earlier matrix, multi-connection was a standalone benchmark control and the production Handler had not yet been changed. The production Handler pool implementation and its separate measurement are recorded below; its default remains one connection.

Raw manifests, JSONL matrices, and logs are private under 本机临时目录; manifests and test credentials are not included in the repository. The source worktrees were dirty, so the binary hashes above are the exact artifact identities. A prior partial server-monitor run without the 0–7 CPU affinity was aborted and excluded; all reported resource matrices use the pinned schedule.

## Production Handler connection-pool matrix

The production `clash-lib` HY2 Handler now accepts `quic-connections` from 1 to 8 (default 1). It creates the authenticated QUIC sessions on one Endpoint and one connector-selected UDP socket, publishes the pool only after all sessions are ready, and assigns new TCP streams round-robin. This matrix tests the actual Handler through the direct-handler benchmark bridge. The earlier protocol-core connection-count matrix above is retained as the isolated transport-core comparison.

The Client source checkout was `[源码快照已省略]` with uncommitted changes; the Server checkout was `[源码快照已省略]`, also dirty. The exact Handler client binary was 4,264,688 bytes, BLAKE3 `8c437794c2f5e7791cd89df4d331ba6756dd93d64dca82fef0e906fd0c531b9a`. The Chimera production server binary was 16,316,408 bytes, BLAKE3 `80eb242bee533b533524f5b6c46a7617ad0c1137df19784154e234a006c5ed4a`. The reference server was official Hysteria 2.14.0.

Both CPU-monitor matrices ran on the same Linux 6.18 / x86_64 host, pinned to CPUs 0–7. They used eight concurrent SOCKS TCP streams, 128 MiB per stream in each direction, 64 KiB buffers, inner TLS, TCP_NODELAY, three warmups and ten measured runs in each of two reversed-order cells per server/connection-count pair. Throughput counts application payload. The client-CPU and server-CPU matrices were run separately; throughput below is from the server-CPU matrix, while process-resource columns combine the corresponding matched monitor matrices. All 12 cells completed in each matrix, and every per-cell CV gate passed (worst CV 7.7%).

| Server | QUIC connections | Upload / download Gbit/s | Pooled CV upload / download |
| --- | ---: | ---: | ---: |
| Chimera production | 1 | 4.484 / 5.308 | 2.33% / 1.97% |
| Chimera production | 4 | **11.956 / 9.995** | 6.76% / 1.49% |
| Chimera production | 8 | 11.974 / 9.381 | 5.32% / 2.88% |
| Official Hysteria 2.14.0 | 1 | 3.509 / 6.148 | 1.93% / 6.09% |
| Official Hysteria 2.14.0 | 4 | 8.369 / 8.223 | 3.96% / 2.20% |
| Official Hysteria 2.14.0 | 8 | **9.252 / 8.509** | 2.17% / 5.58% |

| Server | QUIC connections | Client / server average cores | Client / server CPU s/GiB | Client peak RSS / HWM | Server peak RSS / HWM |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chimera production | 1 | 1.317 / 1.372 | 2.320 / 2.435 | 23.8 / 33.6 MiB | 33.8 / 38.4 MiB |
| Chimera production | 4 | 2.414 / 2.476 | 1.910 / 1.983 | 74.1 / 89.8 MiB | 89.7 / 114.2 MiB |
| Chimera production | 8 | 2.321 / 2.530 | 1.964 / 2.089 | 98.8 / 120.2 MiB | 80.7 / 89.0 MiB |
| Official Hysteria 2.14.0 | 1 | 1.090 / 1.925 | 2.107 / 3.694 | 27.9 / 35.5 MiB | 29.9 / 46.0 MiB |
| Official Hysteria 2.14.0 | 4 | 1.774 / 2.537 | 1.878 / 2.660 | 68.9 / 84.1 MiB | 31.5 / 51.0 MiB |
| Official Hysteria 2.14.0 | 8 | 1.821 / 2.556 | 1.801 / 2.533 | 82.5 / 118.3 MiB | 35.1 / 55.8 MiB |

Against the Chimera production server, q4 increased upload by 166.6% and download by 88.3% over q1. q8's upload was effectively tied with q4 (+0.15%), while its download was 6.1% lower. On the official server, q8 was 10.5% faster upload and 3.5% faster download than q4. Pool size therefore changes the local result by server implementation; q4 is the strongest balanced setting for the Chimera server in this test, but its client peak RSS rose from 23.8 MiB at q1 to 74.1 MiB. The conservative product default remains q1 pending WAN and fairness measurements.

Compared with the earlier matched protocol-core matrix above, Handler throughput medians stayed within about 5.5% for every server, connection count, and direction. This does not show a repeatable large forwarding penalty in the production adapter on this loopback workload. The result supports using extracted protocol crates to isolate transport behavior, then using a direct Handler executable to check that the production socket selection, session assignment, and adapter preserve the transport result.

All six Handler smoke cells (q1/q4/q8 against both servers) completed 1 MiB uploads and downloads with full content verification. `e2e_network_reset_reauthenticates_hysteria2` passed with q4 after sending 40 UDP echoes into the production 32-packet receive queue; it confirmed reset returns within two seconds, closes all four sessions, clears the UDP maps, drains and closes the old datagram stream, and authenticates a replacement pool. A local QUIC/H3 core test also authenticated the first pool member, then either held the second auth request open and cancelled setup or returned HTTP 403; both variants confirmed that the first and second sessions closed. The pending-connection guard unit test confirms its H3 driver task is aborted on drop. These are lifecycle correctness checks, separate from the throughput matrix.

An earlier Handler attempt without fixed CPU affinity was excluded. Its client-CPU official q1 upload CV failed the stability gate (33.6%); all reported Handler rates and resource values above are from the pinned 0–7 runs. The measurements remain host-local BBR tests. WAN, packet loss/RTT, Brutal, UDP relay throughput, physical NIC GSO/GRO, competing-flow fairness, and application latency under background load remain untested. Raw manifests and credentials remain outside the repository under `本机临时目录`.

## Post-review-fix correctness rerun

After adding cancellation-safe QUIC/H3 cleanup and moving UDP delivery outside the session-map lock, the direct-handler release client was rebuilt from the 候选源码快照包含本地修改. The new binary is 4,268,016 bytes, BLAKE3 `22fc65f0e606d26a9909c1a3e66bf06ee71c995348b6ae75949a4cd52f1c0d7c`. The 1 MiB full-content q1/q4/q8 smoke against both Chimera production and official Hysteria 2.14.0 servers passed all 6/6 cells.

This correctness rerun does not replace the pinned bulk-throughput matrix above: that matrix's Handler binary is hash `8c437794c2f5e7791cd89df4d331ba6756dd93d64dca82fef0e906fd0c531b9a`. The intervening fixes change connection cleanup and the UDP receive path, not TCP bulk forwarding. No new bulk-throughput measurement was run for the post-fix binary, so the table above remains evidence for the earlier measured binary and should not be labeled as an exact throughput result for hash `22fc65f0...`.

## Post-review production Handler pinned bulk rerun

This rerun closes the post-review bulk-throughput gap for the current direct production Handler binary. It uses the feature-minimal `chimera-hy2-core-perf-client` executable, which loads a numeric-address HY2 config and constructs the production `clash-lib` Hysteria2 `Handler`; it does not start the full client runtime, DNS resolution, policy routing, or dashboard. The `hy2-core` benchmark feature enables only the benchmark entry, Hysteria2, AWS-LC, and its small SOCKS bridge. The Server is the feature-minimal production HY2 server binary. The official comparison server is Hysteria 2.14.0.

The Client source was `[源码快照已省略]` with uncommitted changes. Its release binary was 5,298,872 bytes, BLAKE3 `fd2b60d28555103a36814aee4f2b78ac07a9ec891db0c97dfa1c4636142a6678`, built from `bench/minimal_transport_clients/hy2_core_client/Cargo.toml` with `--locked --no-default-features --features hy2-core`. The Server source was `[源码快照已省略]`, also dirty; its feature-minimal production binary was 16,316,408 bytes, BLAKE3 `80eb242bee533b533524f5b6c46a7617ad0c1137df19784154e234a006c5ed4a`. Hysteria 2.14.0 was BLAKE3 `70db925e1fa43f52ba502687940a936a4d8948c5607cf2a93a719049a8650978`.

The host was an x86_64 host running Linux 6.18. Both matrices ran with `taskset -c 0-7`; the runner, generator, payload target, client, and server inherited CPUs 0–7, confirmed from live process affinity and each run's host record. All transfers used loopback, BBR, numeric endpoints, eight concurrent SOCKS TCP streams, 128 MiB in each direction per stream, 64 KiB buffers, inner TLS, and TCP_NODELAY. Each server/connection-count pair used two counterbalanced cells with 16 warmups and 10 measured runs per cell. Client and Server process-monitor matrices ran separately; all 12 cells in each completed, every per-cell throughput CV stayed below the 12% gate, and every pair has 20 measured samples. The rates and CV column below come from the Server-monitor matrix (maximum cell CV 7.2%); the Client-monitor matrix's maximum was 7.7%, and its per-pair rates differed from the corresponding Server-monitor medians by -4.2% to +5.4%. A separate current-binary smoke completed full-content q1/q4/q8 transfers against both servers in all 6/6 cells.

| Server | QUIC connections | Upload / download Gbit/s | Pooled CV up / down | Worst Server-monitor cell CV |
| --- | ---: | ---: | ---: | ---: |
| Chimera production | 1 | 4.688 / 5.285 | 2.60% / 0.90% | 2.80% |
| Chimera production | 4 | **12.280 / 9.467** | 5.50% / 5.61% | 5.80% |
| Chimera production | 8 | 12.352 / 9.337 | 5.27% / 5.33% | 7.20% |
| Official Hysteria 2.14.0 | 1 | 3.539 / 6.338 | 1.85% / 5.50% | 6.00% |
| Official Hysteria 2.14.0 | 4 | 8.375 / 8.292 | 4.42% / 2.54% | 5.60% |
| Official Hysteria 2.14.0 | 8 | **9.199 / 8.392** | 3.53% / 4.00% | 4.80% |

| Server | QUIC connections | Client / Server average cores | Client / Server CPU s/GiB | Client peak RSS / HWM | Server peak RSS / HWM |
| --- | ---: | ---: | ---: | ---: | ---: |
| Chimera production | 1 | 1.329 / 1.353 | 2.327 / 2.361 | 28.0 / 38.6 MiB | 39.6 / 40.1 MiB |
| Chimera production | 4 | 2.412 / 2.451 | 1.903 / 1.997 | 81.3 / 98.6 MiB | 120.5 / 130.7 MiB |
| Chimera production | 8 | 2.319 / 2.497 | 1.901 / 2.079 | 97.2 / 126.1 MiB | 106.2 / 120.6 MiB |
| Official Hysteria 2.14.0 | 1 | 1.110 / 1.950 | 2.184 / 3.719 | 26.7 / 35.8 MiB | 30.3 / 48.4 MiB |
| Official Hysteria 2.14.0 | 4 | 1.770 / 2.537 | 1.848 / 2.668 | 72.9 / 91.0 MiB | 32.8 / 51.1 MiB |
| Official Hysteria 2.14.0 | 8 | 1.819 / 2.565 | 1.805 / 2.545 | 69.2 / 116.9 MiB | 35.7 / 54.1 MiB |

CPU/GiB divides the monitored process CPU time across both cells by their total successfully transferred upload plus download payload. Average cores use the same two-cell process CPU and elapsed-time totals. RSS is the highest sampled resident set size; HWM is the process high-water mark.

Against the Chimera production server, q4 raised throughput over q1 by 162% upload and 79% download. q8 was effectively tied with q4 for upload (+0.6%) and 1.4% lower for download, so q4 remains the better balanced local setting; it also used less client peak RSS/HWM than q8. Against the official server, q8 exceeded q4 by 9.8% upload and 1.2% download, with a small increase in client average cores and higher client HWM. The pool-size result is server-dependent.

At q4, the Chimera production server delivered 46.6% more upload and 14.2% more download than the official server with the same Chimera Handler client. This is a same-client, same-host server comparison; it does not isolate server implementation cost from congestion-control interaction. The q1 directional result differs: Chimera was faster upload, while the official server was faster download.

## 2026-11-27 user-space profiles and Quinn state samples

Symbolized release builds were profiled on the same x86_64 host/Linux 6.18
host, pinned to CPUs 0–7. The Client profile compared the standalone Chimera
protocol-core client with official Hysteria 2.14.0 against the feature-minimal
Chimera production Server. Each run used one QUIC connection, eight SOCKS TCP
streams, 256 MiB up/down per stream, one warmup and two measured runs. The
`cycles:u` profiler used 99 Hz sampling with DWARF call chains. Client profile
recordings contained 3,361 Chimera samples and 5,569 official samples, with no
lost samples.

| Client | Profiled upload / download | Approx. user-cycle event count | Top self-cycle functions |
| --- | ---: | ---: | --- |
| Chimera protocol core | 4.544 / 5.540 Gbit/s | 61.18 billion | AES-GCM 15.47%; `memmove` 10.28%; Quinn `poll_transmit` 3.74%; AWS-LC AES encrypt 3.29%; contended mutex 2.00% |
| Official Hysteria 2.14.0 | 6.238 / 3.794 Gbit/s | 92.89 billion | AES-GCM decrypt 6.99%; AES-GCM encrypt 6.36%; Go `runtime.memmove` 3.34%; BBR/runtime and QUIC frame functions below 2% each |

These two-run profile rates are diagnostic only. The separate ten-sample
unprofiled cross matrix above confirms the same directional result: against the
same Chimera production Server, the Chimera client measured 4.651/5.361 and the
official client 6.303/3.711 Gbit/s. Their upload-plus-download rates were
almost equal, while the official client used 2.008 average CPU cores versus
1.319 for the Chimera protocol-core client. This does not show a blanket
throughput loss from the minimal Chimera client; it shows different directional
behavior with substantially lower Client CPU use.

The profile's event counts are sampling estimates, not exact `perf stat`
counters. One 256 MiB × 8 warmup plus two measured runs transferred 12 GiB of
application payload in total; the approximate user-cycle event counts per GiB
were 5.10 billion for Chimera and 7.74 billion for the official client. The
profile symbols show crypto and memory movement as the largest Client CPU
costs. They do not explain the direction change by themselves.

The upstream Hysteria checkout used for comparison was commit
`c2b181e0b0e72b077e4b0b7297735af14d1f9929`. Its standard BBR sender is a custom
implementation in `core/internal/congestion/bbr/bbr_sender.go`; it starts at
32 packets and includes BBR profile, startup, and bandwidth-sampler behavior.
Chimera uses Quinn's `quinn_proto::congestion::Bbr`, also seeded with 32
packets, through `DynController`. Thus the starting window is aligned, but the
controller implementations are not identical. This is the strongest current
candidate for the directional difference, not yet a proven root cause.

The benchmark-only Chimera client now accepts `--stats-interval-ms N` to sample
Quinn cwnd, pacing, RTT, and loss every N milliseconds. `DynController` now
forwards the underlying controller metrics so pacing is observable through
this wrapper. A 250 ms upload-dominant trace reached a reported 3.38 GB cwnd,
with no packet loss and reported pacing around 2.35–2.95 Gbit/s; the downlink
trace records the Client's sender state only and cannot report the Server's
pacing. Quinn's min-RTT sample frequently rounded to 0 microseconds, so the
absolute cwnd and pacing trace still needs validation before it is used to tune
the congestion controller. These traces are in
`本机临时目录` and are not throughput results.

The next bounded step is to add the same opt-in state trace at the feature-minimal
production Server connection boundary, then compare cwnd, pacing, RTT, and loss
for the same client/server pair during isolated upload and download phases.
That will distinguish Client-side Quinn BBR behavior from Server pacing before
porting or tuning another controller. No production controller defaults have
been changed.

An initial 16-warmup rerun was accidentally launched without CPU affinity; its JSONL host records showed `0-15`, and the matrix runner does not set affinity itself. Those samples and their single-cell retries are retained only as diagnostics and excluded from the tables above. The reported rerun explicitly launched the runner under `taskset -c 0-7`; both monitor matrices then completed with all cells under the unchanged CV gate. The new measurements remain local loopback BBR results: WAN, loss/RTT, Brutal, UDP relay throughput, physical-NIC GSO/GRO, fairness, and latency under background load remain untested. Raw matrices and private configs remain under `本机临时目录` and `本机临时目录`.
