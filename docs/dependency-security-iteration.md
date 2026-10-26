# Dependency security iteration

## 2026-10-25: RustCrypto advisory remediation

### Baseline and scope

- Local `master` baseline: `041de8eca78bf59785510ebdc15806c77535c056`; `origin/master` matched.
- Reference submodule `ref/`: `39d06a49ccb5c812ed7cd70b3028f3efcebeae6b`.
- The stable `v0.27.3` release and the current `latest` preview lockfile still contain `crypto-bigint 0.5.5` and `ctutils 0.4.2`; neither provides this remediation.
- The affected RustCrypto releases are pulled into the current workspace through `ring-compat` and `ctutils`' other consumers.

### Changes

- Removed the unused `ring-compat` dependency from `clash-lib`. No Rust source imports `ring_compat`, and the dependency was the only path to `crypto-bigint 0.5.5`, `p256 0.13`, and `p384 0.13` in this workspace.
- Updated the lockfile to `ctutils 0.4.5`, which includes the constant-time fixes and remains reachable through `digest` and Shadowsocks crypto dependencies.
- Updated `chacha20 0.10.0` to `0.10.2`. The `0.10.0` and `0.10.1` releases were yanked because of undefined behavior in the SSE2 backend; `0.10.2` includes the upstream fix ([PR #583](https://github.com/RustCrypto/stream-ciphers/pull/583)). This is compatible with the existing `chacha20poly1305` requirement.

### Validation

- `cargo fmt --all -- --check`: passed.
- `cargo check -p clash-lib --all-features --locked`: passed.
- `cargo clippy -p clash-lib --all-targets --all-features --locked -- -D warnings`: passed.
- `cargo test -p clash-lib --test lan_proxy_tests --all-features --locked`: 3 passed.
- `cargo test -p clash-lib --test shadowsocks_integration_tests --features shadowsocks --locked -- --test-threads=1`: started but was stopped at the user's request to skip further tests; no result is claimed.
- `cargo tree` confirmed `crypto-bigint 0.5.5` is no longer in the resolved graph, `ctutils 0.4.5` remains reachable, and `chacha20 0.10.2` replaces the yanked `0.10.0`.

### Remaining integration work

The separate Android repository `MFSGA/AChimera` has its own `uniffi/Cargo.lock` and currently pins `clash-lib` to Git revision `ba1653f0e14b8cbab25288c82498e0d9dada310a` (the manifest comment identifies it as v0.27.3). This source-repository fix does not update that lockfile. A new compatible `Chimera_Client` release and an Android dependency/lockfile update are needed before that repository's CI can consume the fix.
