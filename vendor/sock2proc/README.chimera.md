# Chimera-maintained sock2proc snapshot

Source: `https://github.com/Watfaq/sock2proc` at
`9f9e6304d62285115b2e4fa632527ae563bf0fcc`.
The upstream snapshot includes `SPDX-License-Identifier: MIT` headers in
its Linux and Windows platform implementations, but no standalone LICENSE
file. The accompanying [LICENSE](LICENSE) records that identifier and the
standard MIT terms. Confirm upstream attribution/provenance in independent
license review before redistribution.

The public API remains `find_process_name(Option<SocketAddr>,
Option<SocketAddr>, NetworkProtocol) -> Option<String>`, preserving Chimera
PROCESS-NAME and PROCESS-PATH matching semantics.

Hardening changes:

- Linux: handle unavailable socket-diag protocol/permissions without unwrap;
  validate Netlink frame bounds; safely resolve procfs symlinks using
  `std::fs::read_link` rather than invoking libc on a non-NUL-terminated path.
  Skip racy or unreadable `/proc` entries.
- macOS: convert fallible sysctl calls and invalid PCB/kernel versions to
  normal errors; validate PCB payloads and process paths before indexing;
  preserve zero-success `proc_info` semantics; add malformed-data tests.
- Windows: validate returned IP Helper table sizes and row bounds; read
  potentially unaligned structures with `read_unaligned`; validate returned
  executable image lengths; add malformed-data tests.
- Remove unused dependencies `rtnetlink`, `byteorder`, and upstream
  benchmarking dependencies. Retain original API and active platform targets.

**Important limitations:** Linux and Windows checks performed from macOS
are compile-only and do not confirm runtime behavior or kernel permissions;
Windows source still contains platform-native unsafe FFI and requires
independent code review. Process attribution may be expensive per flow.
Do not rely on `catch_unwind` in Chimera's release panic=abort build.
New failures should yield `None` and normal routing, not crash.

This local copy is not a generic maintained fork; periodically reconcile it
against upstream bug and security fixes.
