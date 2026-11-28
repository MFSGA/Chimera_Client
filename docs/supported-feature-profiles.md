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

## Compile and compatibility profiles

`ci/check-feature-profiles.sh` runs the following exact `cargo check` profiles:

1. `clash-lib --no-default-features` to verify the minimal library boundary.
2. `clash-lib` defaults to verify the library's declared default feature set.
3. `clash-rs --no-default-features --features standard,aws-lc-rs` to verify the
   headless client profile.
4. `clash-rs` defaults to verify the Dashboard-enabled client and embedded
   asset path.

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
