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

Build Dashboard assets before using a Dashboard-enabled profile:

```bash
npm --prefix clash-dashboard ci
npm --prefix clash-dashboard run build
```

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
