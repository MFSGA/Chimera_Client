# `clash-ffi`

**Maturity: scaffold only.** This workspace package currently prints `Hello,
world!`; it does not export the core API through C, UniFFI, or another FFI
binding.

Mobile and desktop clients must not assume this package provides a stable FFI
surface. A real binding will need an explicit API/versioning contract and
platform build checks before it can be considered usable.
