# Supported Cargo feature profiles

This document distinguishes user-facing build profiles from compile-only
coverage profiles. Cargo features are additive, so turning on two crypto
providers or every experimental feature does not define a recommended release
configuration.

## User-facing profiles

| Profile | Command | Behavior and boundary |
| --- | --- | --- |
| CLI default | `cargo build -p clash-rs --locked` | Enables `standard`, `aws-lc-rs`, and `dashboard`; embeds the separately built `clash-dashboard/dist/` assets. |
| CLI standard, headless | `cargo build -p clash-rs --no-default-features --features standard,aws-lc-rs --locked` | Enables the standard protocol and listener bundle with AWS-LC, without embedding the Dashboard or requiring Node.js. |
| CLI plus | `cargo build -p clash-rs --features plus --locked` | Adds the `onion` compatibility feature to `standard`; the `onion` feature is empty and does not implement Tor. |
| CLI Hysteria performance | `cargo build -p clash-rs --no-default-features --features hysteria-perf --locked` | Hysteria client profile with AWS-LC crypto and mixed port; excludes DNS DoH3, unrelated proxy protocols, and Dashboard. The Hysteria QUIC transport remains enabled. |
| CLI REALITY performance | `cargo build -p clash-rs --no-default-features --features reality-perf --locked` | REALITY client profile with mixed port; excludes Hysteria, XHTTP/H3, and DNS DoH3. |
| CLI Linux zero-copy experiment | `cargo build -p clash-rs --release --no-default-features --features reality,mixed_port,zero_copy --locked` | Explicitly enables the Linux TCP splice path for an isolated benchmark. This feature is opt-in and does not change the default or standard profile. |

DNS server DoH3 is a separate `clash-dns` capability (`doh3-aws-lc-rs` or
`doh3-ring`). The CLI's `aws-lc-rs` and `ring` aliases keep enabling the matching
DoH3 capability for compatibility; `aws-lc-rs-crypto` selects the AWS-LC crypto
provider without DNS DoH3. The library default keeps AWS-LC DoH3 enabled. A
reduced profile without a matching DoH3 feature rejects `dns.listen.doh3`
during configuration conversion.

## Protocol coverage compared with the local reference

This comparison uses the checked-out `ref/` snapshot at
`2f62452678211746348b97e72fee0e78b8dc1b40` (2026-11-14). It describes source
and feature coverage, not interoperability or runtime support on every target.

| Area | Chimera Client | Local `ref/` snapshot |
| --- | --- | --- |
| Always-present outbound variants | Direct, Reject, SOCKS5, and VLESS | Direct, Reject, SOCKS5, AnyTLS, Trojan, VMess, VLESS, and Hysteria2 |
| CLI `standard` feature bundle | Adds Shadowsocks, WireGuard, Trojan, AnyTLS, Hysteria2, TUN, and listener features | Adds Shadowsocks, TUIC, SSH, ShadowQUIC, WireGuard, Tailscale, TUN, TProxy, and Redir |
| Chimera transport features | WebSocket, Reality, VLESS encryption, and XHTTP/H3 | XHTTP over H2 is present; this snapshot has no matching XHTTP/H3, Reality, or VLESS encryption feature |
| Additional reference protocols | — | Tor is enabled by `plus`; Tailscale, TUIC, SSH, and ShadowQUIC are feature-gated |
| `onion` feature | Empty compatibility feature; no Tor implementation | Enables the Tor client dependencies |

The local capability endpoint reports protocols compiled into the running
binary. Keep that runtime result as the authority for a particular build. A
reference-only protocol is a compatibility gap to prioritize from actual
configuration demand; do not add an empty Cargo feature to represent it.

Build Dashboard assets before using a Dashboard-enabled profile:

```bash
pnpm --dir clash-dashboard install --frozen-lockfile
pnpm --dir clash-dashboard build
```

The Nix package prepares dependencies from `fetchPnpmDeps` and runs the Dashboard
build in its pre-build phase before invoking Cargo.

`clash-lib` has its own default feature set. It is a library build profile, not
the CLI's standard protocol bundle; its defaults include TUN, Reality, and
VLESS encryption, which imply AWS-LC. A minimal `clash-lib --no-default-features`
build is supported as a compile boundary, but does not promise a useful
standalone client configuration.

## Benchmark-only protocol client packages

The workspace includes runtime-front-end and direct-handler clients under
`bench/minimal_transport_clients/`. Build one protocol profile per invocation
so Cargo does not unify protocol features:

```bash
cargo build --release --locked -p chimera-hy2-perf-client \
  --no-default-features --features hy2
cargo build --release --locked -p chimera-reality-perf-client \
  --no-default-features --features reality
cargo build --release --locked -p chimera-hy2-core-perf-client \
  --no-default-features --features hy2-core
cargo build --release --locked -p chimera-reality-core-perf-client \
  --no-default-features --features reality-core
cargo build --release --locked -p chimera-hy2-protocol-perf-client \
  --features aws-lc-rs
cargo build --release --locked -p chimera-reality-protocol-perf-client
cargo build --release --locked --no-default-features \
  -p chimera-reality-protocol-perf-client
```

The four runtime-front-end and direct-handler packages disable `clash-lib`
defaults and enable one protocol profile. The runtime-front-end clients call
`clash_lib::start_scaffold` with a SOCKS
listener and therefore start the shared resolver, DNS, routing, and
configuration runtime. The direct-handler clients enable the
`transport-bench-api` feature and call the production protocol handler through
a numeric-only SOCKS5 test bridge; they skip the full runtime startup. Both are
benchmark-only and are not product-supported build profiles. The direct API
still builds `clash-lib` and measures the production handler without the full
runtime. `chimera-hy2-protocol-perf-client` and
`chimera-reality-protocol-perf-client` instead depend directly on the
`chimera-hysteria2-core` and `chimera-reality-core` workspace crates; they skip
Clash DNS, routing, configuration, and Controller dependencies. Both
standalone clients use a TCP-only benchmark bridge in this slice; they do not
cover product DNS, socket selection, TUN, routing, or UDP forwarding. Build and
use details are in the
[`minimal transport client notes`](../bench/minimal_transport_clients/README.md).
Historical loopback results are in
[`bench/minimal_transport_clients/RESULTS_LOCAL_LOOPBACK_2026-11-26.md`](../bench/minimal_transport_clients/RESULTS_LOCAL_LOOPBACK_2026-11-26.md).

The standalone REALITY client's `vision` feature only adds Vision framing and
stream processing; its REALITY and VLESS TCP code remains enabled in the
`--no-default-features` profile. Its optional `--x25519mlkem768` runtime flag
offers both X25519MLKEM768 and the associated X25519 share, then validates and
uses the group selected by the server. A hybrid offer is not proof that the
completed TLS handshake selected ML-KEM.

## Compile and compatibility profiles

`ci/check-feature-profiles.sh` runs the following exact `cargo check` profiles:

1. `clash-lib --no-default-features` to verify the minimal library boundary.
2. `clash-lib` defaults to verify the library's declared default feature set.
3. `clash-rs --no-default-features --features standard,aws-lc-rs` to verify the
   headless client profile.
4. `clash-rs` defaults to verify the Dashboard-enabled client and embedded
   asset path.
5. `clash-rs --no-default-features --features hysteria-perf` to verify the
   minimal Hysteria client profile without DNS DoH3.
6. `clash-rs --no-default-features --features reality-perf` to verify the
   minimal REALITY client profile.

CI runs this matrix on Linux after downloading the separately built Dashboard
artifact. `cargo clippy -p clash-lib --all-targets --all-features` and the
all-feature LAN test remain compatibility checks, not a release profile: they
combine features and dependencies beyond the recommended user-facing builds.
`ci/verify-quality-gates.sh --full` runs the same profile script after building
the Dashboard.

The feature-forwarding check (`python3 ci/check-feature-forwarding.py`) validates
that CLI feature aliases refer to existing core features. The `perf` CLI feature
is an aggregate alias and does not enable jemalloc. Cross-target jobs that use
`plus` verify compilation for those targets; they do not constitute real-device,
TUN privilege, DNS, or network interoperability testing.

The CLI `zero_copy` feature forwards to `clash-lib/zero_copy`. On Linux it allows
the dispatcher to attempt TCP splice when both stream wrappers expose compatible
raw TCP streams. Enabling the feature does not guarantee that a particular
protocol path reaches that branch; verify the runtime trace before attributing
a benchmark result to zero-copy. The benchmark profile above is for measurement
and is not a change to the normal product defaults.

## Local validation record

On 2026-10-25, `ci/check-feature-profiles.sh` passed on macOS with:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/Volumes/ChimeraBuild/chimera-feature-profiles-target \
  ci/check-feature-profiles.sh
```

All four checks completed: core without default features, core defaults, the
headless standard CLI, and the default CLI with prebuilt Dashboard assets. This
local result does not replace the Linux CI job or cross-platform runtime tests.
