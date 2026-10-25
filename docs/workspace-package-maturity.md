# Workspace package maturity

This inventory follows the package names reported by `cargo metadata --no-deps`
for the root Cargo workspace. Workspace membership and successful compilation
do not by themselves mean that a package is a supported standalone product.

| Package or component | Maturity | Current role and support boundary |
| --- | --- | --- |
| `clash-rs` (`clash-bin/`) | Product | User-facing CLI entry point. Its default, headless standard, and plus build profiles are defined in [supported Cargo feature profiles](supported-feature-profiles.md). |
| `clash-lib` | Product core | Runtime library used by the CLI; contains configuration, DNS integration, routing, proxy protocols, TUN, and Controller API. This classification does not promise a stable external FFI or ABI. |
| `chimera-dns` (`clash-dns/`) | Implemented supporting package | DNS service and transport implementations used by the client; this is not an empty placeholder. |
| `watfaq-netstack` (`clash-netstack/`) | Implemented, non-production support library | smoltcp-based network stack with tests and examples. Its README explicitly says it is not intended for production use; do not describe it as a production-supported product. |
| `clash-doc` | Scaffold only | Prints the starter `Hello, world!`; it does not generate configuration documentation. See [`clash-doc/README.md`](../clash-doc/README.md). |
| `clash-ffi` | Scaffold only | Prints the starter `Hello, world!`; it exports no C, UniFFI, or other usable binding. See [`clash-ffi/README.md`](../clash-ffi/README.md). |
| `xhttp-h2-phaseb` | Experimental demo | Standalone H2C prototype. It is not the production XHTTP transport in `clash-lib`; see [`xhttp-h2-phaseb/README.md`](../xhttp-h2-phaseb/README.md). |
| `boring-noise` (`vendor/boring-noise/`) | Vendored runtime dependency | WireGuard Noise source snapshot with local changes. It is not a general maintained fork and does not claim to contain every upstream security fix; see its [provenance and update requirements](../vendor/boring-noise/README.chimera.md). |
| `sock2proc` (`vendor/sock2proc/`) | Vendored internal support dependency | Process-name attribution library with platform-specific local hardening. It is not a standalone client product; compile-only platform checks do not prove native runtime behavior. See its [support boundary](../vendor/sock2proc/README.chimera.md). |
| `clash-dashboard` | Product UI; outside the Cargo workspace | npm-built frontend embedded by the `dashboard` feature from prebuilt `clash-dashboard/dist/` assets. Cargo does not install npm dependencies or build the frontend. |

The `ref/`, `ref-mihomo/`, and `ref-meow/` directories are reference
submodules, not Cargo workspace packages or shipped client components.

Recheck this table when workspace members, package entry points, or the
Dashboard build boundary change. Use source and manifests to update the status;
do not promote a scaffold, demo, or non-production library based only on its
package name, tests, or presence in the workspace.
