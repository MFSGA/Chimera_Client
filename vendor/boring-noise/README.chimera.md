# Vendored WireGuard Noise implementation

This is a source snapshot of `Watfaq/boring-noise` at
`9ddf1b54d0c9679e7bc50e9151f72d526190db1a`, which is based on
Cloudflare BoringTun. Its original Rust source copyright and
`SPDX-License-Identifier: BSD-3-Clause` headers are retained.
See [LICENSE](LICENSE). No claim is made that this snapshot includes all
upstream security fixes.

Chimera changes compared to the Git snapshot:

1. `src/noise/session.rs`: zero-pad inner plaintext to a multiple of
   16 bytes *before AEAD encryption* and move the AEAD tag accordingly.
2. `src/noise/mod.rs`: a non-aligned inner IPv4 packet round-trip test,
   plus removal of an old `std::usize::MAX` deprecation warning.
3. `Cargo.toml`: no upstream benchmarking executable or `criterion`
   dev dependency, and build as `rlib` only; the original benchmark
   implementation is not part of this vendored runtime snapshot.
4. Format this vendored source using the current workspace rustfmt.

The Git SHA remains the upstream provenance reference, not a live Cargo
dependency. Updates require independent review of cryptography/handshake
behavior, nonce/counter safety, Linux/Windows/macOS builds, release
feature combinations and real WireGuard peers. This copy is **not**
a general-purpose maintained WireGuard fork.
