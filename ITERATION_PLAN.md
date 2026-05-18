# Iteration Plan

## Execution Mode

- Iterate task by task.
- Do not mix multiple tasks in one implementation cycle.
- Do not ask for confirmation during normal iteration.
- If a task cannot be solved, skip it and record the reason.
- Each completed task must be committed as one separate git commit.
- Do not push, amend commits, rewrite history, or modify unrelated files.

## Per-Task Workflow

1. Read the current implementation.
2. Locate and study the corresponding implementation in `ref`.
3. Treat `ref` as the preferred behavior and implementation reference.
4. Only diverge from `ref` if it is confirmed to contain a bug or conflicts with this Rust architecture.
5. Implement the smallest correct change.
6. Add tests for the task.
7. Run relevant verification commands.
8. Fix failures until the task passes or is explicitly skipped.
9. Commit only the files related to the current task.
10. Move to the next task.

## Testing Requirements

Every task must include a test case.

Preferred test order:

1. Unit tests for parsing, conversion, pure logic, and boundary behavior.
2. Integration tests for cross-module behavior.
3. End-to-end tests for CLI, runtime, config loading, and network flow behavior.

If automated testing is not feasible, record the reason and provide a manual or semi-automated verification path.

## Verification Commands

Use the narrowest useful command first.

Common commands:

- `cargo fmt`
- `cargo test -p <crate> <test>`
- `cargo check --all`
- `cargo clippy --all-targets --all-features`
- `cargo test --all`

## Commit Rules

Before each commit:

1. Run `git status`.
2. Run `git diff`.
3. Run `git log --oneline -10`.
4. Stage only files related to the current task.
5. Commit with a concise English message.

Rules:

- One task equals one commit.
- Do not commit unrelated changes.
- Do not revert user changes.
- Do not push unless explicitly requested.
- Do not amend unless explicitly requested.

## Skip Record Format

If a task cannot be completed, record it as:

```text
Skipped task: <task name>
Reason: <why it cannot be completed now>
Attempts: <what was tried>
Follow-up: <recommended next step>
```

## Ref Alignment Phase

After the current task list is completed:

1. Compare the current project with the latest `ref` code.
2. Identify features or behavior not yet implemented.
3. Add missing items to a new iteration task list.
4. Continue iterating task by task.
5. Repeat until the current project matches `ref` functionality.

## Mihomo Alignment Phase

After matching `ref`:

1. Use `https://github.com/MetaCubeX/mihomo/tree/Meta` as the upstream feature reference.
2. Compare current project functionality with mihomo.
3. Convert missing features into new iteration tasks.
4. Implement, test, and commit one task at a time.
5. Continue until the current project fully aligns with mihomo features.

## Model Constraint

- Use only free models when model selection is required.
- Do not intentionally configure or invoke paid models.
- If the execution environment externally fixes the active model, do not attempt paid-model-specific configuration.

## Completion Definition

There are no new tasks only when:

1. All planned tasks are completed or explicitly recorded as skipped.
2. The project is functionally aligned with `ref`.
3. The project is functionally aligned with mihomo Meta.
4. All completed tasks have tests.
5. All completed tasks have individual commits.

## Initial Ref Alignment Backlog

This backlog is the first task batch found by comparing the current workspace against `ref`.
Each item must be implemented, tested, and committed separately.

### Task 1: Align TUN + Fake-IP Runtime Behavior With Mihomo

- Reference: `ref` TUN/DNS implementation first, then mihomo Meta behavior from `https://github.com/MetaCubeX/mihomo/tree/Meta`.
- Current gap: when `tun + fake-ip` is enabled, the default DNS server behavior must be tied to the TUN gateway, and domain traffic must follow mihomo-style fake-ip routing semantics.
- Expected behavior: enabling `tun + fake-ip` makes domain website access receive a fake IP first, then dispatch by the original domain rule context.
- Expected behavior: when the selected outbound is a proxy, the core must not resolve the real destination IP locally; real domain resolution is delegated to the proxy node.
- Expected behavior: direct or otherwise IP-required paths may resolve real IPs only when routing requires it.
- Privilege note: TUN feature verification may require root privileges. Full root permission can be granted for this task when needed.
- Test environment note: root permission is required for real TUN verification.
- Test environment note: when enumerating local network interfaces, the configured virtual TUN interface is expected to appear.
- Expected behavior: the virtual TUN interface must use a DNS server endpoint in the same address family/network as the TUN gateway, not the gateway IP itself and not a public IP address.
- Expected behavior: the designed DNS server endpoint should generally be the next host address after the gateway, for example gateway `192.168.10.1` maps to DNS server `192.168.10.2`; confirm the exact behavior against mihomo core before implementation.
- Expected test: unit or integration test proving DNS listener/gateway defaults are derived from TUN settings when fake-ip is active.
- Expected test: root-enabled E2E test proving the virtual TUN interface has the expected LAN-style gateway/DNS address after startup.
- Expected test: integration or end-to-end test proving a domain query returns a fake IP and dispatch keeps the original domain for proxy routing.
- Suggested verification: focused `cargo test -p clash-lib <tun_fake_ip_test>`, `cargo test -p clash-lib <dns_config_test>`, and root-enabled E2E verification for real TUN behavior.

### Task 2: Restore Proxy Group API Response Parity

- Reference: `ref/clash-lib/src/proxy/group/mod.rs`.
- Current gap: group API responses do not include `hidden` and `testUrl`, and `icon` is omitted instead of defaulting to an empty string.
- Expected test: unit or API serialization test proving selector/url-test/fallback group responses match the `ref` response shape.
- Suggested verification: `cargo test -p clash-lib <group_api_response_test>` and `cargo fmt`.

### Task 3: Add Relay Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/relay/`.
- Current gap: `relay` groups are absent from `OutboundGroupProtocol`, runtime group modules, and group conversion wiring.
- Expected test: config parsing test for a `proxy-groups` entry with `type: relay`, including proxy list validation.
- Suggested verification: `cargo test -p clash-lib <relay_group_test>` and `cargo check -p clash-lib`.

### Task 4: Add Load-Balance Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/loadbalance/`.
- Current gap: `load-balance` groups and `LoadBalanceStrategy` are absent.
- Expected test: config parsing test covering `consistent-hashing` and `round-robin` strategy values.
- Suggested verification: `cargo test -p clash-lib <load_balance_group_test>` and `cargo check -p clash-lib`.

### Task 5: Add Smart Proxy Group Config Parsing

- Reference: `ref/clash-lib/src/config/internal/proxy.rs` and `ref/clash-lib/src/proxy/group/smart/`.
- Current gap: `smart` groups are absent from config and runtime group modules.
- Expected test: config parsing test for `type: smart` with health-check fields and proxy references.
- Suggested verification: `cargo test -p clash-lib <smart_group_test>` and `cargo check -p clash-lib`.

### Task 6: Add VMess Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/vmess/`, and `ref/clash-lib/src/proxy/converters/vmess.rs`.
- Current gap: `vmess` is missing from outbound config, converter wiring, `OutboundType`, and runtime proxy modules.
- Expected test: config/converter test that builds a VMess outbound from YAML, including TLS and network options supported by `ref`.
- Suggested verification: `cargo test -p clash-lib <vmess_test>` and `cargo check -p clash-lib`.

### Task 7: Add Shadowsocks Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/shadowsocks/`, and `ref/clash-lib/src/proxy/converters/shadowsocks.rs`.
- Current gap: `ss`/Shadowsocks support and the `shadowsocks` feature are absent from the current implementation.
- Expected test: config/converter test for an AEAD Shadowsocks proxy and a supported 2022 cipher case if dependencies permit.
- Suggested verification: `cargo test -p clash-lib <shadowsocks_test>` and `cargo check -p clash-lib --features shadowsocks`.

### Task 8: Add AnyTLS Outbound Config And Converter

- Reference: `ref/clash-lib/src/config/internal/proxy.rs`, `ref/clash-lib/src/proxy/anytls/`, and `ref/clash-lib/src/proxy/converters/anytls.rs`.
- Current gap: `anytls` is missing even though `ref` treats it as a normal outbound protocol.
- Expected test: config/converter test for AnyTLS password, SNI, ALPN, and certificate verification options.
- Suggested verification: `cargo test -p clash-lib <anytls_test>` and `cargo check -p clash-lib`.

### Task 9: Add TProxy And Redir Module Gates

- Reference: `ref/clash-lib/src/proxy/tproxy/` and `ref/clash-lib/src/proxy/redir/`.
- Current gap: feature flags exist in `Cargo.toml`, but corresponding proxy modules are not wired in `proxy/mod.rs`.
- Expected test: compile-gated smoke test or focused `cargo check` proving `tproxy` and `redir` feature builds include the modules on supported platforms.
- Suggested verification: `cargo check -p clash-lib --features tproxy,redir` on Linux.

### Task 10: Add Socks5 Converter Module Parity

- Reference: `ref/clash-lib/src/proxy/converters/socks5.rs`.
- Current gap: outbound Socks5 config exists, but converter module parity with `ref` is missing.
- Expected test: converter test for username/password, UDP flag, and TLS-related fields when enabled.
- Suggested verification: `cargo test -p clash-lib <socks5_converter_test>` and `cargo check -p clash-lib`.

### Task 11: Add First Advanced Optional Protocol Feature Skeletons

- Reference: `ref/clash-lib/src/proxy/tuic/`, `shadowquic/`, `ssh/`, `wg/`, `tailscale/`, and `tor/`.
- Current gap: optional protocol feature flags and modules are missing or incomplete compared with `ref`.
- Expected test: one feature-gated config parsing test per protocol before runtime implementation is expanded.
- Suggested verification: run focused `cargo check` with each added feature.
