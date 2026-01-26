# AGENTS.md

## Why you open this file
- You are an agentic contributor living inside the Chimera Client workspace. This file is your quick reference for how to build, lint, test, and style the code before handing it back.
- Treat every change as part of a workspace that mirrors Clash but lives in Rust; keep things fast, observable, and safe.
- When in doubt, read this file first, then consult a crate README or the `docs/` folder for deeper context.

## Workspace at a glance
- **Rust workspace** defined in `Cargo.toml` with pinned toolchain `nightly-2025-09-15` (see `rust-toolchain.toml`).
- **Crates:**
  - `clash-bin` (`clash-rs` CLI entrypoint with `clap` parsing and `start_scaffold`).
  - `clash-lib` core runtime scaffolding; contains `app/`, `common/`, `config/`, `proxy/`, and `session/` modules.
  - `clash-dns`, `clash-ffi`, `clash-doc`, `clash-netstack` are empty placeholders but keep the namespace reserved.
  - `docs/` holds human-facing explanations; `config.yaml` is the sample profile generated on first run.
- **Scripting helpers:** `start.sh`/`start.ps1` wrap `cargo watch` for quick iteration, `make` recipes live at the repo root.

## Toolchain & dependencies
- **Rust:** Always use `nightly-2025-09-15` (managed via `rust-toolchain.toml`).
- **Required native tools:** CMake ≥3.29, LLVM/libclang, nasm (Windows), protoc for proto generation; install via your platform package manager.
- **Notifications:** `cargo fmt`, `cargo clippy --all-targets --all-features`, and `cargo test --all` are treated as basic hygiene before any PR.

## Build/Lint/Test commands

### Build
- `cargo build` – builds the entire workspace in debug mode (default). Run this when you need the latest artifacts.
- `cargo build --release` – builds optimized artifacts; only run if you need release performance.
- `cargo check --all` – fastest full-workspace sanity check; recommended before `cargo fmt` when you just changed logic.

### Format & lint
- `cargo fmt` – canonical formatting; never skip before pushing.
- `cargo clippy --all-targets --all-features` – catches lints across libs and binaries. Use `-- -D warnings` only when lint clean-up is on your TODO list.

### Tests
- `cargo test --all` – runs all tests across every crate.
- `CLASH_RS_CI=true cargo test --all --all-features` – CI-like invocation that enables extra guards.
- `make test-no-docker` – wraps the same tests without Docker; helpful if you rely on local tooling.
- `cargo test -p clash-lib` (or another crate name) – narrow the scope to a single crate.

### Running a single test (or subset)
- Use `cargo test -p <crate> <substring>` to run focused tests. Example: `cargo test -p clash-lib parser_can_load_config`.
- Add `-- --exact` when you need an exact test name; append `--nocapture` to see `tracing` logs.
- When you need specific features, combine `-p` with `--features shadowsocks,tuic` and `-- --test-threads=1` for deterministic output.

### Running the client
- `cargo run -p clash-rs -- -c config.yaml` – mimics the user experience: loads `config.yaml`, sets up logging, starts the async runtime.
- `./start.sh` (or `start.ps1` on Windows) – wraps `cargo watch -x "run -p clash-rs -- -c config.yaml"` for live reload.
- Pass `-t` to test config, `--help-improve` to toggle telemetry, `--directory` to point to a profile folder, or `--config` for alternate files.

### Documentation
- `make docs` – rebuilds documentation for `docs/` pages and other static assets.
- `cargo doc -p clash_doc --no-deps` – regenerates API docs for the config reference generator.
- `cargo doc` – when you need to inspect generated docs for any crate.

## Code style & contribution guidance

### Imports & grouping
- Group imports by origin: first `std`, then external crates (`tokio`, `tracing`, `serde`, etc.), then workspace crates (`clash_lib::app`).
- Keep groups sorted alphabetically within braces for readability. Example in `clash-lib/src/lib.rs`: `use std::{collections::HashMap, ...};`.
- Avoid wildcard imports unless you are re-exporting a whole module; prefer explicit items for clarity.

### Formatting & spacing
- Four spaces per indent level; blank lines to separate logical blocks (e.g., between `use` statements and module declarations).
- Wrap long argument lists across lines with trailing commas and alignment. Follow `rustfmt` output without custom tweaks.
- Doc comments use `///` for exported APIs and `//` for quick TODOs; limit horizontal comment length to 100 columns.

### Module & crate organization
- Keep each module in its own file or nested folder; prefer `mod foo;` near the top-level and keep definitions in `foo.rs` or `foo/mod.rs`.
- Modules that expose APIs should re-export key symbols near the bottom of their `mod` files (e.g., `pub use session::Session;`).
- For feature-gated modules, use `#[cfg(feature = "tun")]` near declarations to keep code minimal when features are disabled.

### Naming conventions
- Types, structs, enums, traits: `CamelCase` (e.g., `RuntimeController`, `StatsManager`).
- Functions, methods, variables: `snake_case`. Constants and static references: `SCREAMING_SNAKE_CASE` (e.g., `DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL`).
- Module names: lowercase with underscores to match crate layout (e.g., `app::dispatcher`).
- Keep acronyms consistent (`DnsResolver`, not `DNSResolver` everywhere) but allow conventional PascalCase when it feels natural.

### Types & traits
- Prefer strong types over primitives when modeling configs; wrap `PathBuf`, `Arc`, `Mutex` inside structs rather than passing raw strings.
- Define `type Result<T> = std::result::Result<T, Error>;` in each crate when a shared error type exists.
- Use `thiserror::Error` to annotate error enums, keep messages descriptive, and prefer transparent conversions (`#[error(transparent)]`).

### Error handling principles
- Use `?` as the default propagation mechanism. Reserve `unwrap()`/`expect()` for places that truly cannot fail (bootstrapping, tests).
- Convert third-party errors via `map_err(|e| Error::DNSError(e.to_string()))` or similar so the crate-level error type stays consistent.
- When logging before returning an error, use `tracing::error!` with structured fields rather than `println!`.

### Async & runtime patterns
- Tokio runtime setup happens in `start_scaffold` using `tokio::runtime::Builder`. Favor `MultiThread` for general use but keep `SingleThread` available for tests.
- Spawn background tasks with `tokio::spawn` and wrap them in `Box::pin` when collecting multiple runners.
- Use `Arc<dyn Trait>` to share handlers between components (`OutboundHandler`, `Dispatcher`). When mutation is needed, wrap state in `Mutex` or `RwLock` guarded by `tokio::sync` primitives.

### Logging & diagnostics
- Favor `tracing::{debug, info, warn, error}` and attach context (e.g., `info!(port = %port, "listener started")`).
- Log errors right before returning them if they are about to cross thread boundaries; otherwise trust `?` to bubble them up and log closer to the failure site.
- Emit structured events (e.g., `EventCollector`) when wiring the `LogEvent` channel, then filter them via subscriber layers.

### Configuration & parsing
- Parse configs via `serde_yaml` and apply anchors/aliases through `Value::apply_merge` to match Clash semantics.
- Keep the `config::def` modules focused on raw deserialization; move conversions into `config::internal` for runtime-friendly structures.
- Provide helpers such as `Config::File`, `Config::Str`, and `Config::Internal` so CLI, tests, and FFI consumers can pass data flexibly.

### Tests & fixtures
- Put unit tests beside the module they cover; integration tests live under `clash_lib/tests/` (e.g., `smoke_tests.rs`).
- Use `#[tokio::test]` with `async fn` when testing async components.
- Keep helper fixtures (e.g., parsed configs) in `tests/data/` so they can be reused without duplicating YAML strings.

### Feature gates & conditional logic
- Wrap optional systems (`tun`, `onion`, `shadowquic`) with `#[cfg(feature = "...")]` and document their toggles in the README or crate docs.
- Prefer runtime checks with `cfg!(feature = "foo")` sparingly; compile-time gating keeps the binary lean.

### Dependencies & re-exports
- Re-export cross-crate helpers (e.g., `pub use session::Session`) near the end of files to provide a stable API surface.
- Keep dependency versions in sync with upstream Clash when practical, but favor the safe `nightly` toolchain pinned in this workspace.

## Development workflow
- `cargo watch -x "run -p clash-rs -- -c config.yaml"` is the tight feedback loop; `start.sh`/`start.ps1` wrap it so you can keep iterating without rebuilding manually.
- Keep `config.yaml` close to the workspace root; the CLI will auto-generate a stub with `port: 7890` if the file is missing.
- Expect runtime scaffolding to early-`todo!()` in many places; plan work by replacing `todo!()` markers with concrete implementations and keep state in `clash-lib` until readiness.
- When experimenting, run the multi-crate build (`cargo check --all`) before pushing to catch cross-crate integration issues early.
- Use `cargo fmt && cargo clippy` immediately after refactoring modules or changing public APIs; these are fast enough to run before each push.
- After you edit `config.yaml`, rerun the CLI once (`cargo run -p clash-rs -- -c config.yaml`) to ensure the generated `cache.db` paths and watchers stay aligned.

## Observability & debugging
- Wire every long-lived component through `tracing` so you can lower the log level to debug or trace when investigating issues.
- Emit structured events (e.g., `log_event::EventCollector`) and reuse `LogEvent` across tasks to avoid scattering emitters.
- Prefer `tokio::sync::broadcast`/`mpsc` channels for control paths (reload signals, shutdown events) and log their state transitions explicitly.
- Keep `cache.db` in the workspace root so replaying flows is easy; log cache/reset operations when hitting profile edges.
- Use `RUST_LOG` (or the CLI logging flags) to tune verbosity; prefer structured logs that include `component` and `port` metadata.
- Keep telemetry toggles behind the `--help-improve` flag until support is ready so we do not emit data unless users opt in.

## Local config & caches
- The CLI will create or update `config.yaml` with a default stub if it is missing, so version this file and keep the sample in sync with the runtime.
- `profile::ThreadSafeCacheFile` expects `cache.db` in the workspace root; do not scatter cache files across the tree.
- When you modify cache handling, add log statements and consider clearing `cache.db` to avoid stale entries while testing.

## Release & publishing
- Keep `Cargo.lock` checked in and in sync with the workspace; regenerate with `cargo update` only when dependencies need bumps.
- Document new public APIs in `clash-doc` whenever you change configuration parsing or runtime wiring so the auto docs stay current.
- When publishing, coordinate updates to `clash-doc` and the `docs/` website so CLI reference sections remain consistent.
- When landing releases, rerun `cargo test --all` and the `CLASH_RS_CI=true` guarded run to ensure platform parity before tagging.

## Git etiquette
- Never amend commits unless explicitly requested; if a commit fails due to hooks, fix the issue and create a new commit.
- Avoid destructive commands like `git reset --hard` or `git checkout --` unless the user explicitly asks for them.
- Do not push to the remote repository unless the user explicitly asks you to do so.

## Cursor / Copilot notes
- No `.cursor/rules/` or `.cursorrules` files exist today; follow this document and the Rust standard library guidance instead.
- There is no `.github/copilot-instructions.md`, so Copilot-specific hooks are unused; if you add one, describe the rule and update this section.
