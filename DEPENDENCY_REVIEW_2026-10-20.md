# Chimera Client dependency change review and follow-up validation

Date: 2026-10-20 (America/Los_Angeles).
Branch: `fix/git-dependency-hardening-20261019`.
Initial commits reviewed: `35ba8f5e01f5b1030d2c0b90157efc968b555ee3`,
`d666e2a95365f6fda704bbdf65bb007897ba8b37`.

**Scope:** a developer-side review and regression hardening pass. It is
**not** the independent review required by project governance. No Git push,
PR, remote CI execution, history rewriting or host TUN/route manipulation.

## Findings from this review

### 1. WireGuard framing: MTU-bound padding (fixed locally)

Original change correctly zero-padded encrypted inner packets to the nearest
16-byte boundary (WireGuard whitepaper §5.4.6,
https://www.wireguard.com/papers/wireguard.pdf). However, it did not cap
padding by the configured inner MTU, so a packet already near the tunnel's
MTU could grow beyond it. The original `Tunn::encapsulate` also relied on
an internal panic for short destination buffers. Both issues matter to
Chimera's `panic = "abort"` release configuration.

Review fix: a dedicated `transport_plaintext_len` helper supports
`set_padding_mtu` on the local Noise tunnel; Chimera passes the same configured
MTU (default 1420) to the encryption layer and smoltcp virtual IP device.
Valid padding is added whenever the aligned length fits; when it does not,
the original inner length is retained rather than increasing the datagram.
Established-session encryption fails with
`WireGuardError::DestinationBufferTooSmall` before calling the lower-level
formatting helper if a destination buffer cannot hold the message. Receive,
replay and AEAD logic were not changed.

Unit regressions: exact padding round-trip, no-growth-at-MTU round-trip,
buffer-too-small error without panic; both AWS-LC and ring configurations.

Residual risk: configured tunnel inner MTU does not prove the real path MTU
of arbitrary chained UDP proxy paths. A real peer/interoperability and
fragmentation test is still required. Also, the library's other
pre-existing internal short-buffer panics were not comprehensively audited.

### 2. Linux process attribution: dump response misidentification (fixed locally)

The original `sock2proc` asked SOCK_DIAG for an `NLM_F_DUMP` and assumed the
**first** `InetResponse` was the target socket. Per Linux sock_diag(7)
(https://man7.org/linux/man-pages/man7/sock_diag.7.html), socket-list
queries primarily filter by state; they cannot be assumed to return only
the provided socket ID.

Review fix: explicitly match source/destination IP addresses and ports in
the returned SocketId (with a constrained wildcard-bind allowance on the
local side) before resolving uid/inode. Iterate Netlink multi-message
datagrams using 4-byte-aligned offsets. Unit tests cover mismatches,
wildcard local bind, truncated input and alignment overflow.

Residual risk: compile-only Linux validation does not prove correct live
kernel behavior, latency, cancellation under pathological socket lists,
or process attribution through NAT/TUN configurations. Failing closed may
cause some prior fuzzy matches to return no process rather than an
incorrect process. This needs Linux namespace / live TCP and UDP tests.

### 3. Windows native-table parsing (reviewed, execution still blocked)

The vendored IP Helper table parser uses `offset_of!` and validated sizes
before `read_unaligned` rows, consistent with Microsoft's warning that
padding can occur in `MIB_TCPTABLE_OWNER_PID`:
https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid

Windows cross-target compilation is not Windows execution. Requires an
independent FFI/unsafe audit and Windows live process attribution tests.
The older `MAX_PATH = 260` limitation is still present.

### 4. Shadowsocks and LWIP

`shadowsocks = =1.25.0` from crates.io resolves a newer crypto dependency
graph than the prior Git source at the same package version; passing a
local pair test is not independent implementation interoperability.

Original Shadowsocks UDP integration failures were reproduced on the
pre-migration Git-source baseline with local port-collision errors;
the migration's UDP behavior is not proven by those failures.
The isolated lwIP comparison compiles but still needs its own privileged,
non-production benchmark host.

## Evidence and acceptance checklist

- [x] macOS arm64: `cargo test -p sock2proc --lib --locked`:
  4/4 passed in prior hardening pass (live loopback TCP/UDP lookup).
- [x] macOS arm64: WireGuard local AWS-LC and ring test configurations:
  13 passed, 0 failed each, including new MTU and buffer tests.
- [x] macOS arm64: `cargo check -p clash-rs --locked` — PASS.
- [x] macOS arm64: `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings` — PASS.
- [x] macOS arm64: `cargo test -p clash-lib --lib --all-features --locked` — 934 passed, 0 failed, 12 ignored.
- [x] macOS arm64: `cargo test -p clash-lib --no-default-features --features shadowsocks,aws-lc-rs --test shadowsocks_integration_tests integration_test_shadowsocks_tcp --locked -- --exact --test-threads=1` — 1 passed, 0 failed; local same-implementation loopback only.
- [x] Linux x86_64: `cargo check -p sock2proc --tests --target x86_64-unknown-linux-gnu --locked`
  (compile only).
- [x] Windows x86_64: prior `sock2proc` compile/test-target checks
  (compile only; Linux/Windows binaries have not been executed).
- [ ] Linux x86_64 live socket-diag and process match/denied Netlink test.
- [ ] Windows live TCP/UDP process lookup and FFI review.
- [ ] WireGuard external peer interoperability, rekey/keepalive, fragmentation
  and configured MTU tests under real transport.
- [ ] Shadowsocks independent server TCP/UDP multi-user interoperability,
  legacy cipher policy review and crypto compatibility confirmation.
- [ ] Independent reviewer + maintainer approval for L2 changes.
- [ ] Remote GitHub CI and Verified status.
