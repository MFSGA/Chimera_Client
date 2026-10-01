# Iteration Plan

## Execution Mode

- Iterate task by task.
- Do not mix multiple tasks in one implementation cycle.
- Do not ask for confirmation during normal iteration.
- If a task cannot be solved, skip it and record the reason.
- Each completed task must be committed as one separate git commit.
- Do not push, amend commits, rewrite history, or modify unrelated files.

## Per-Task Workflow

1. Read the current implementation.
2. Locate and study the corresponding implementation in `ref`.
3. Treat `ref` as the preferred behavior and implementation reference.
4. Only diverge from `ref` if it is confirmed to contain a bug or conflicts with this Rust architecture.
5. Implement the smallest correct change.
6. Add tests for the task.
7. Run relevant verification commands.
8. Fix failures until the task passes or is explicitly skipped.
9. Commit only the files related to the current task.
10. Move to the next task.

## Testing Requirements

Every task must include a test case.

Preferred test order:

1. Unit tests for parsing, conversion, pure logic, and boundary behavior.
2. Integration tests for cross-module behavior.
3. End-to-end tests for CLI, runtime, config loading, and network flow behavior.

If automated testing is not feasible, record the reason and provide a manual or semi-automated verification path.

## Verification Commands

Use the narrowest useful command first.

Common commands:

- `cargo fmt`
- `cargo test -p <crate> <test>`
- `cargo check --all`
- `cargo clippy --all-targets --all-features`
- `cargo test --all`

## Commit Rules

Before each commit:

1. Run `git status`.
2. Run `git diff`.
3. Run `git log --oneline -10`.
4. Stage only files related to the current task.
5. Commit with a concise English message.

Rules:

- One task equals one commit.
- Do not commit unrelated changes.
- Do not revert user changes.
- Do not push unless explicitly requested.
- Do not amend unless explicitly requested.

## Skip Record Format

If a task cannot be completed, record it as:

```text
Skipped task: <task name>
Reason: <why it cannot be completed now>
Attempts: <what was tried>
Follow-up: <recommended next step>
```

## Ref Alignment Phase

After the current task list is completed:

1. Compare the current project with the latest `ref` code.
2. Identify features or behavior not yet implemented.
3. Add missing items to a new iteration task list.
4. Continue iterating task by task.
5. Repeat until the current project matches `ref` functionality.

## Mihomo Alignment Phase

After matching `ref`:

1. Use `https://github.com/MetaCubeX/mihomo/tree/Meta` as the upstream feature reference.
2. Compare current project functionality with mihomo.
3. Convert missing features into new iteration tasks.
4. Implement, test, and commit one task at a time.
5. Continue until the current project fully aligns with mihomo features.
## Model Constraint

- Use only free models when model selection is required, **except** for Plan Builder/Prometheus planning roles which may use GPT.
- All exploration, librarian, implementation, QA, review, and automation roles must use free models when model choice is available.
- If a non-plan-builder role cannot be executed with a free model, it must stop and record a blocker/skip rather than using GPT or paid models.
## Non-Free-Model Blocker Rule

If a non-plan-builder role (explore, librarian, implementation, QA, review, automation) cannot be executed with a free model, it must stop and record a blocker/skip instead of silently using GPT or paid models.

This rule connects to the existing Skip Record Format: record the task as skipped with reason "non-free-model unavailability" and follow-up "resolve model availability or escalate".

## Status and Evidence Rule

Future executors should track task status (completed/in-progress/skipped) in the plan file and capture verification evidence (command output, diffs, test results) in .omo/evidence/ without requiring human confirmation.

This rule preserves the existing one-task-one-commit discipline and does not change backlog task meanings.

## Completion Definition

There are no new tasks only when:

1. All planned tasks are completed or explicitly recorded as skipped.
2. The project is functionally aligned with `ref`.
3. The project is functionally aligned with mihomo Meta.
4. All completed tasks have tests.
5. All completed tasks have individual commits.

## Initial Ref Alignment Backlog

This backlog is the first task batch found by comparing the current workspace against `ref`.
Each item must be implemented, tested, and committed separately.

### Task 1: Align TUN + Fake-IP Runtime Behavior With Mihomo

- Reference: `ref` TUN/DNS implementation first, then mihomo Meta behavior from `https://github.com/MetaCubeX/mihomo/tree/Meta`.
- Current gap: when `tun + fake-ip` is enabled, the default DNS server behavior must be tied to the TUN gateway, and domain traffic must follow mihomo-style fake-ip routing semantics.
- Expected behavior: enabling `tun + fake-ip` makes domain website access receive a fake IP first, then dispatch by the original domain rule context.
- Expected behavior: when the selected outbound is a proxy, the core must not resolve the real destination IP locally; real domain resolution is delegated to the proxy node.
- Expected behavior: direct or otherwise IP-required paths may resolve real IPs only when routing requires it.
- Privilege note: TUN feature verification may require root privileges. Full root permission can be granted for this task when needed.
- Test environment note: root permission is required for real TUN verification.
- Test environment note: when enumerating local network interfaces, the configured virtual TUN interface is expected to appear.
- Expected behavior: the virtual TUN interface must use a DNS server endpoint in the same address family/network as the TUN gateway, not the gateway IP itself and not a public IP address.
- Expected behavior: the designed DNS server endpoint should generally be the next host address after the gateway, for example gateway `192.168.10.1` maps to DNS server `192.168.10.2`; confirm the exact behavior against mihomo core before implementation.
- Expected test: unit or integration test proving DNS listener/gateway defaults are derived from TUN settings when fake-ip is active.
- Expected test: root-enabled E2E test proving the virtual TUN interface has the expected LAN-style gateway/DNS address after startup.
- Expected test: integration or end-to-end test proving a domain query returns a fake IP and dispatch keeps the original domain for proxy routing.
- Suggested verification: focused `cargo test -p clash-lib <tun_fake_ip_test>`, `cargo test -p clash-lib <dns_config_test>`, and root-enabled E2E verification for real TUN behavior.

### Task 2: Restore Proxy Group API Response Parity

- Reference: `ref/clash-lib/src/proxy/group/mod.rs`.
- Current gap: group API responses do not include `hidden` and `testUrl`, and `icon` is omitted instead of defaulting to an empty string.
- Expected test: unit or API serialization test proving selector/url-test/fallback group responses match the `ref` response shape.
- Suggested verification: `cargo test -p clash-lib <group_api_response_test>` and `cargo fmt`.

### Task 3: Add Relay Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/relay/`.
- Current gap: `relay` groups are absent from `OutboundGroupProtocol`, runtime group modules, and group conversion wiring.
- Expected test: config parsing test for a `proxy-groups` entry with `type: relay`, including proxy list validation.
- Suggested verification: `cargo test -p clash-lib <relay_group_test>` and `cargo check -p clash-lib`.

### Task 4: Add Load-Balance Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/loadbalance/`.
- Current gap: `load-balance` groups and `LoadBalanceStrategy` are absent.
- Expected test: config parsing test covering `consistent-hashing` and `round-robin` strategy values.
- Suggested verification: `cargo test -p clash-lib <load_balance_group_test>` and `cargo check -p clash-lib`.

### Task 5: Add Smart Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/smart/`.
- Current gap: `smart` groups are absent from config and runtime group modules.
- Expected test: config parsing test for `type: smart` with health-check fields and proxy references.
- Suggested verification: `cargo test -p clash-lib <smart_group_test>` and `cargo check -p clash-lib`.

### Task 6: Add VMess Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/vmess/`, and `ref/clash-lib/src/proxy/converters/vmess.rs`.
- Current gap: `vmess` is missing from outbound config, converter wiring, `OutboundType`, and runtime proxy modules.
- Expected test: config/converter test that builds a VMess outbound from YAML, including TLS and network options supported by `ref`.
- Suggested verification: `cargo test -p clash-lib <vmess_test>` and `cargo check -p clash-lib`.

### Task 7: Add Shadowsocks Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/shadowsocks/`, and `ref/clash-lib/src/proxy/converters/shadowsocks.rs`.
- Current gap: `ss`/Shadowsocks support and the `shadowsocks` feature are absent from the current implementation.
- Expected test: config/converter test for an AEAD Shadowsocks proxy and a supported 2022 cipher case if dependencies permit.
- Suggested verification: `cargo test -p clash-lib <shadowsocks_test>` and `cargo check -p clash-lib --features shadowsocks`.

### Task 8: Add AnyTLS Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/anytls/`, and `ref/clash-lib/src/proxy/converters/anytls.rs`.
- Current gap: `anytls` is missing even though `ref` treats it as a normal outbound protocol.
- Expected test: config/converter test for AnyTLS password, SNI, ALPN, and certificate verification options.
- Suggested verification: `cargo test -p clash-lib <anytls_test>` and `cargo check -p clash-lib`.

### Task 9: Add TProxy And Redir Module Gates

- Reference: `ref/clash-lib/src/proxy/tproxy/` and `ref/clash-lib/src/proxy/redir/`.
- Current gap: feature flags exist in `Cargo.toml`, but corresponding proxy modules are not wired in `proxy/mod.rs`.
- Expected test: compile-gated smoke test or focused `cargo check` proving `tproxy` and `redir` feature builds include the modules on supported platforms.
- Suggested verification: `cargo check -p clash-lib --features tproxy,redir` on Linux.

### Task 10: Add Socks5 Converter Module Parity

- Reference: `ref/clash-lib/src/proxy/converters/socks5.rs`.
- Current gap: outbound Socks5 config exists, but converter module parity with `ref` is missing.
- Expected test: converter test for username/password, UDP flag, and TLS-related fields when enabled.
- Suggested verification: `cargo test -p clash-lib <socks5_converter_test>` and `cargo check -p clash-lib`.

### Task 11: Add First Advanced Optional Protocol Feature Skeletons

- Reference: `ref/clash-lib/src/proxy/tuic/`, `shadowquic/`, `ssh/`, `wg/`, `tailscale/`, and `tor/`.
- Current gap: optional protocol feature flags and modules are missing or incomplete compared with `ref`.
- Expected test: one feature-gated config parsing test per protocol before runtime implementation is expanded.
- Suggested verification: run focused `cargo check` with each added feature.

## 2026-09-10 Feature Boundary Alignment

- Baseline: Chimera `afd9bfca`, local `ref/` `6f50ec9e`.
- Completed: reject `tun.enable: true` when the binary lacks the `tun` feature;
  retain the existing enabled-TUN conversion path when the feature is present.
- Completed: stop `tokio-rustls` and `hickory-net` from implicitly selecting AWS-LC;
  propagate AWS-LC and Ring through their respective features, and make `trojan`
  depend explicitly on `tls`.
- Completed: zero-feature builds retain UDP/TCP DNS and reject DoT/DoH with a
  clear error when neither crypto backend is compiled.
- Local deviation: `ref/` does not reject an enabled TUN configuration in a
  no-TUN build. Chimera does so to keep configuration and compiled capability
  consistent.
- Verified: zero-feature, Ring + Trojan + WS, AWS-LC + Trojan + WS, default,
  all-feature, CLI Ring + Trojan + WS builds; focused TUN and encrypted-DNS
  tests; formatting and diff checks.
- Next slice: add these stable combinations to CI, then review whether the
  general `tls` capability and encrypted-DNS capability need separate features.

## 2026-09-24 Trojan gRPC Transport

- Baseline: `origin/master` `a5d4c970` (v0.26.0). Trojan's converter rejected
  `network: grpc` and its `grpc-opts` field was commented out, while the shared
  gRPC transport and VLESS gRPC option type already existed. The current `ref/`
  is not a browsable source checkout; this slice was adapted from local branch
  commit `949cbced` and reconciled with the current API.
- Completed: enabled Trojan `grpc-opts`, constructed the shared gRPC client
  with service path, user-agent, ping interval, and pool limits; rejected
  missing options and conflicting pool settings. Kept unrelated TLS-option
  additions from the source commit out of this slice.
- Verification: baseline and modified `cargo check -p clash-lib --features
  trojan` passed; `cargo fmt --all -- --check` passed; focused
  `cargo test -p clash-lib --lib --features trojan trojan_grpc` passed (3
  tests). A no-default-feature check without `tun` fails on pre-existing
  unused-variable warnings in `clash-lib/src/lib.rs`; the supported default
  feature combination with `trojan` was used for verification.
- Next slice: re-check current master for equivalent behavior before selecting
  another protocol compatibility fix.

## 2026-09-26 VLESS UDP Datagram Integrity

- Baseline: local `master` `70ebf8c4`. The VLESS UDP sink capped frames at 8 KiB
  and encoded only the prefix of a larger datagram, silently losing its tail.
- Completed: retain UDP datagram boundaries by encoding the full payload in one
  frame; reject payloads larger than the 16-bit frame length instead of
  truncating them. Added focused coverage for both behaviors.
- Verification: baseline `cargo check -p clash-lib --features trojan` passed;
  `cargo fmt --all -- --check` passed; focused
  `cargo test -p clash-lib --lib --features trojan udp_datagram` passed (2
  tests).
- Next slice: review the pending Vision fragmented-record/UUID fixes against
  this updated master before migrating them.

## 2026-09-26 VLESS Vision Fragmentation

- Baseline: local `master` `ddef6af3`. `VisionFilter` parsed a ServerHello only
  when the full handshake was in one TLS record; `VisionUnpadder` did not retain
  a UUID split across calls. The outer `VisionStream` already buffers partial
  UUID bytes and fragmented TLS records at its own framing layer.
- Source and deviation: migrated the two focused fixes from the existing local
  pending VLESS worktree patch. The current `ref/` is a gitlink, not a browsable
  source checkout, so this slice was checked against local implementation and
  tests rather than asserted as upstream parity.
- Completed: accumulate ServerHello handshake payload across TLS records and
  buffer a partial initial UUID; on UUID mismatch, pass through all buffered
  bytes without loss.
- Verification: baseline `vision_filter` tests (2) and `vision_unpad` test (1)
  passed; `cargo fmt --all -- --check` passed; focused
  `cargo test -p clash-lib --lib --features trojan proxy::vless::vision` passed
  (19 tests).
- Held candidate: the pending `stream.rs` read-first handshake change is not
  migrated. In the relay's bidirectional copy path, a partially pending first
  write can coexist with a read poll; if the read path completes that pending
  write, the write retry may resend the same application bytes. The candidate
  test covers read-first startup but not this interleaving.
- Next slice: separate request-header transmission from pending application
  write ownership, then validate the interleaved read/write lifecycle before
  considering this candidate again.

## 2026-09-26 VLESS Native Encryption 1-RTT

- Baseline: current local `master` `7697d162`; `cargo check -p clash-lib`
  passed before changes. The user-selected scope is outbound VLESS native
  `mlkem768x25519plus.native.1rtt`; 0-RTT, `xorpub`/`random`, encrypted UDP,
  and hybrid Reality are excluded from this first implementation.
- Reference: current local `ref/` has no VLESS native-encryption implementation.
  The wire behavior will be checked against the official Mihomo VLESS config
  documentation and Xray-core implementation; this is a Chimera extension, not
  a claim of parity with `ref/`.
- Completed: added the `encryption` config field and outbound runtime for
  `mlkem768x25519plus.native.1rtt`: X25519 + ML-KEM-768 key agreement, the
  1-RTT hello/PFS exchange, padded TLS-shaped encrypted records, and explicit
  rejection of unsupported modes, Vision/REALITY combinations, and encrypted
  UDP.
  Added the optional `vless-encryption` feature to `clash-lib` and forwarded it
  through the CLI's `standard` feature. Implementation was split into
  reviewable commits of at most 500 changed lines; a too-large first port was
  reverted before the smaller commits were made.
- Verification: baseline and final `cargo check -p clash-lib` passed;
  `cargo check -p clash-lib --no-default-features --features
  tun,tls,aws-lc-rs,port,reality,extended-health-check,vless-encryption` passed;
  `cargo check -p clash-rs --no-default-features --features standard,aws-lc-rs`
  and the corresponding `cargo build` passed. Focused `cargo test -p clash-lib
  --lib encryption` passed (36 tests), all VLESS converter tests passed (85
  tests), and the complete final
  `clash-lib` unit suite passed (572 passed, 11 ignored). The feature-off
  rejection test passed with the supported feature
  set `tun,tls,aws-lc-rs,port,reality,extended-health-check`. The initial
  no-default attempt with only `tun` was blocked by existing unrelated
  unused-code warnings in DNS/TLS/XHTTP modules. The localhost interop script
  `clash-lib/tests/vless_native_encryption_xray_interop.sh` passed against
  Xray `26.3.27` for direct TCP; other transport combinations were not covered
  by that interop run. The current slice explicitly rejects REALITY and
  Vision. `cargo fmt --all -- --check`, `git diff --check`, and the script's
  `bash -n` check passed.
- CI follow-up for commit `73ebedce`: fixed Clippy's
  `items_after_test_module` and `useless_vec` findings by moving the test module
  after runtime impls and passing a fixed-size slice. CI-equivalent
  `cargo clippy -p clash-lib --all-targets --all-features -- -D warnings`
  passed locally; the focused encryption filter passed (37 tests), and
  `cargo test -p clash-lib --test lan_proxy_tests --all-features --locked`
  passed (2 tests).
- Next slice: validate supported outer TLS/XHTTP combinations against Xray,
  then consider encrypted UDP and 0-RTT separately with explicit compatibility
  and replay-safety design; none is implied by the direct-TCP 1-RTT result.

## 2026-10-01 VLESS Native Encryption Outer TLS/XHTTP Interop

- Baseline: local `master` `cd4457f9`. The direct-TCP native 1-RTT interop
  already passed against Xray 26.2.6; the remaining supported outer-layer slice
  was standard TLS over RAW/TCP and XHTTP over TLS.
- Completed: added
  `clash-lib/tests/vless_native_encryption_transport_xray_interop.sh`, which
  generates temporary TLS credentials with Xray, derives matching VLESS
  Encryption credentials, and exercises both RAW+TLS and XHTTP+TLS through a
  local SOCKS-to-echo round trip.
- Verification: `bash -n` passed; the interop script passed both cases against
  Xray 26.2.6. No runtime code changes were required by this validation slice.
- Next slice: consider encrypted UDP and 0-RTT separately, with explicit
  compatibility and replay-safety design; neither is implied by the TLS/XHTTP
  interop result.

## 2026-10-01 VLESS Native Encryption 0-RTT

- Baseline: local `master` `c8240881` after the outer TLS/XHTTP interop slice.
  Xray documents client `0rtt` as ticket-based session resumption, with `1rtt`
  remaining available as the forced-handshake mode.
- Completed: enabled native `mlkem768x25519plus.native.0rtt` runtime support.
  A per-handler ticket cache is populated by a successful 1-RTT handshake,
  valid only until the server-provided ticket lifetime. Cache misses and expired
  tickets fall back to 1-RTT; malformed early response headers invalidate only
  the matching cached PFS state.
- Replay compatibility: the implementation keeps a fresh NFS key for each
  0-RTT attempt rather than replaying a captured first flight. Xray's server
  tracks the ticket session and rejects a repeated NFS key as a replay, while
  expired tickets trigger a new handshake.
- Verification: 47 focused encryption/converter tests passed; the full
  `clash-lib` unit suite with `vless-encryption` passed (618 passed, 11 ignored);
  `cargo clippy -p clash-lib --all-targets --all-features -- -D warnings`
  passed; and
  `clash-lib/tests/vless_native_encryption_0rtt_xray_interop.sh` passed against
  Xray 26.2.6, exercising a 1-RTT cache bootstrap followed by a cached 0-RTT
  connection.
- Next slice: evaluate the remaining VLESS compatibility gaps separately;
  encrypted UDP is now covered by the following slice.

## 2026-10-01 VLESS Native Encryption Encrypted UDP

- Baseline: local `master` `98fb6177` after native 0-RTT and outer transport
  validation. The existing datagram path already frames VLESS UDP as length +
  payload over a VLESS UDP request; the missing piece was allowing the native
  EncryptionStream to wrap that same stream for encrypted UDP.
- Completed: removed the encrypted-UDP runtime rejection and report UDP support
  from the VLESS handler whenever the configured outbound has `udp: true`. The
  existing VLESS datagram framing is therefore carried inside the same native
  1-RTT encryption records used for TCP streams. Added a handler-level UDP
  capability regression test and an Xray interop test using a local UDP echo
  server.
- Compatibility boundary: this slice covers native `mlkem768x25519plus`
  1-RTT encryption over the existing TCP-carried VLESS UDP path. It does not
  claim XUDP/`packet-encoding: xudp` support, 0-RTT UDP, or a UDP transport
  (`network: udp`). Those remain separate compatibility questions.
- Verification: the focused encrypted-UDP handler test passed;
  `cargo clippy -p clash-lib --all-targets --all-features -- -D warnings`
  passed; `bash -n` passed; and
  `clash-lib/tests/vless_native_encryption_udp_xray_interop.sh` passed against
  Xray 26.2.6 with a SOCKS5 UDP-associate → Chimera → encrypted VLESS UDP →
  Xray → local UDP echo round trip.
## 2026-10-01 VLESS Native Encryption XUDP / packet-encoding

- Baseline: local `master` `4fef70b8` after native encrypted UDP support.
  Mihomo exposes `packet-encoding: xudp` for VLESS UDP; XUDP uses the VLESS
  Mux command and per-datagram destination metadata.
- Completed: added `packet-encoding: xudp` and the compatible legacy `xudp: true`
  switch to VLESS configuration. The converter rejects unknown encodings and
  explicitly rejects `packetaddr` until that separate framing is implemented.
- Runtime: encrypted VLESS UDP can now switch from the raw two-byte-length
  framing to XUDP Mux frames. The implementation preserves packet boundaries,
  carries IPv4/IPv6/domain destinations in Xray's port-then-address order, and
  decodes response destinations from Keep/Data frames. TCP/stream VLESS continues
  to use the normal VLESS request command.
- Verification: XUDP framing unit tests passed; packet-encoding resolver tests
  passed; the full `clash-lib` unit suite with `vless-encryption` passed
  (625 passed, 11 ignored); `cargo clippy -p clash-lib --all-targets
  --all-features -- -D warnings` passed; and
  `clash-lib/tests/vless_native_encryption_xudp_xray_interop.sh` passed against
  Xray 26.2.6, exercising native 1-RTT VLESS Encryption + `packet-encoding: xudp`
  + outer TLS + SOCKS5 UDP. A manual XHTTP+TLS variant also completed the same
  round trip.
## 2026-10-01 VLESS packetaddr framing

- Baseline: local `master` `3b1e2f41` after XUDP / `packet-encoding: xudp`.
  V2Ray/sing-vmess packetaddr uses the magic destination
  `sp.packet-addr.v2fly.arpa` and prefixes each packet with a port-then-address
  header; packetaddr supports IPv4/IPv6 but not FQDN destinations.
- Completed: added `packet-encoding: packetaddr`. VLESS uses the UDP command
  with the packetaddr magic FQDN, while each datagram carries its actual IP
  destination in the packet payload before the user bytes. Response framing is
  decoded symmetrically, and FQDN packetaddr destinations are rejected rather
  than silently encoded with the wrong address family.
- Native encryption integration: packetaddr framing is applied below the same
  VLESS native EncryptionStream, so `mlkem768x25519plus.native.1rtt` can carry
  packetaddr bytes without changing the encryption record format. The external
  V2Ray interop used `encryption: none` because V2Ray 5.41.0 does not implement
  the Xray-native VLESS Encryption mode; native-encryption packetaddr coverage
  is therefore codec/unit coverage rather than a cross-implementation crypto
  claim.
- Verification: focused packetaddr stream, resolver, encoder, decoder, and
  domain-rejection tests passed; the full `clash-lib` unit suite with
  `vless-encryption` passed (629 passed, 11 ignored);
  `cargo clippy -p clash-lib --all-targets --all-features -- -D warnings`
  passed; and `clash-lib/tests/vless_packetaddr_v2ray_interop.sh` passed against
  V2Ray 5.41.0. The earlier Xray 26.2.6 native-encryption XUDP/TLS interop
  also remains passing.
## 2026-10-01 VLESS Compatibility Matrix Audit

- Confirmed boundaries: native VLESS Encryption is intentionally rejected with
  `xtls-rprx-vision` and REALITY in the current runtime, while XUDP and
  packetaddr are independent UDP payload framings below the VLESS security
  stream.
- Verified combinations in this iteration: native Encryption + XUDP + TLS
  against Xray 26.2.6; native Encryption + XUDP + XHTTP+TLS via the manual
  transport variant; packetaddr + plain VLESS against V2Ray 5.41.0; and the
  complete unit suite with all VLESS encryption tests enabled.
- Compatibility expansion completed for the currently available stream
  transports: packetaddr was interop-tested against V2Ray 5.41.0 over TCP,
  WebSocket, and gRPC. The framing is independent of the outer stream wrapper,
  and the same packetaddr codec passes IPv4/IPv6 unit coverage plus malformed
  frame rejection.
- Native VLESS Encryption remains intentionally rejected with
  `xtls-rprx-vision` and REALITY; those are a separate security-stack slice.
  Exploratory Xray 26.2.6 Vision interop exposed a real async-write bug in the
  Vision framing layer: when its inner writer returned `Pending` after a TLS
  record had already been queued, the next poll could queue that same record a
  second time. That bug is now fixed and regression-tested, but native
  Encryption + Vision still needs a clean end-to-end interop result before the
  configuration rejection is removed.
- XHTTP packetaddr cross-implementation coverage is not claimed because the
  available V2Ray 5.41.0 interop target does not provide the corresponding
  XHTTP server transport, while Xray's current VLESS implementation does not
  expose the legacy packetaddr framing as a server-side packet encoding.
