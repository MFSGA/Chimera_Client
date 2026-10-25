# Built-in Dashboard API contract

The built-in Dashboard consumes the Controller over HTTP and WebSocket. The
wire handlers under `clash-lib/src/app/api/` define the serialized response;
the Dashboard's corresponding TypeScript models live in
`clash-dashboard/src/lib/api.ts` and `clash-dashboard/src/hooks/useFlows.ts`.
These models are maintained in both languages rather than generated from an
OpenAPI document, so the executable contract is the paired Rust response tests
and the Dashboard TypeScript build.

| Dashboard data or action | Controller route | Dashboard model | Contract coverage |
| --- | --- | --- | --- |
| Version and runtime capabilities | `GET /version`, `GET /capabilities` | `Version`, `Capabilities` | `api_smoke_tests` |
| Current settings and reload | `GET /configs`, `PATCH /configs`, `PUT /configs` | `ClashConfig`, `PatchableConfig` | `api_smoke_tests`, `api_tests`, `api_reload_tests` |
| Proxy collection and selection | `GET /proxies`, `PUT /proxies/{name}` | `Proxy` | `api_smoke_tests`, `api_selector_tests`, `ref_api_compat_tests` |
| Proxy and provider delay | `/proxies/{name}/delay`, `/providers/proxies/{provider}/{proxy}/healthcheck` | `{ delay, overall }` | `api_delay_tests`, `api_provider_tests` |
| Proxy and rule providers | `/providers/proxies`, `/providers/rules` and their detail routes | `ProxyProvider`, `RuleProvider` | `api_smoke_tests`, `api_provider_tests` |
| Rules and connections | `GET /rules`, `GET /connections` | `Rule[]`, `ConnectionsData`, `Connection` | `api_smoke_tests`, `connection_chain_tests` |
| DNS lookup | `GET /dns/query` | `DNSQueryResult` | DNS handler tests |
| Live traffic, connections, logs, and flows | `/ws/traffic`, `/ws/connections`, `/ws/logs`, `/ws/flows` | `TrafficData`, `ConnectionsData`, `LogEntry`, `FlowRecord` | WebSocket contract tests, log WebSocket integration test, logging and flow handler tests |

`ci/test-dashboard-api-contract.sh` runs these focused checks on Linux CI. The
Dashboard job runs `npm run lint` and `npm run build`, which type-check the
frontend models and their consumers. The HTTP request helper sends bearer
authentication and accepts either a plain-text error body or JSON with a
`message`; WebSocket authentication uses the `token` query parameter. The
contract tests cover unauthorized HTTP requests, rejected WebSocket tokens,
and the plain-text not-found response.

The contract follows the Controller's existing Clash/Mihomo-compatible wire
shape. In particular, DNS answer TTL is `TTL`, DNS questions contain `qtype`
and `qclass`, and connection ports are JSON numbers. Delay responses include
both `delay` and `overall`. The Dashboard API module no longer exposes a
`GET /group/{name}` helper because the server only provides the group delay
route.

When changing a Controller response or Dashboard API method, update the
matching TypeScript model and add or adjust the focused contract assertion in
the same change. Preserve the existing route and field names unless a separate
compatibility change is intended.

## Iteration record

### 2026-10-25 — establish an executable Dashboard API contract

- Baseline: local `master` at `14989ff0cd21177bc59a019324f2abf07c3f5352`;
  `origin/master` at `e6a849f83deca4f7b1f5b7d39329bafde67b9697`.
- This slice fixes the DNS answer TTL key to the existing Clash/Mihomo wire
  name, aligns Dashboard types for DNS questions, delay results, connection
  ports, and optional flow metadata, and removes the unsupported group lookup
  helper. It adds HTTP/WebSocket contract coverage and a focused Linux CI step.
- Passed: `cargo fmt --all -- --check`, `git diff --check`,
  `bash -n ci/test-dashboard-api-contract.sh`, Ruby YAML parsing of
  `.github/workflows/ci.yml`, Dashboard lint, Dashboard production build, and
  `cargo check -p clash-lib --no-default-features --features port,dashboard,ws
  --test api_smoke_tests --test dashboard_websocket_contract_tests --locked`
  (with temporary debug-info/incremental overrides). The complete focused Rust
  script passed locally on macOS using a dedicated build volume: 6 HTTP smoke,
  3 selector, 2 delay, 1 proxy-provider, 1 provider-delay, 1 config-validation,
  1 reload, 11 DNS/API handler, 1 logging, 4 connection/flow, 2 WebSocket, 1
  log WebSocket, and 3 Clash-compatibility tests (37 passed total). The
  WebSocket tests reserve both test ports together, and the proxy provider
  assertion verifies a real file-backed provider and its returned proxy list.
- A first runtime assertion exposed that the HTTP smoke fixture's escaped Rust
  string had stripped indentation from nested YAML. The fixture now uses a raw
  multiline string, and the rule-provider response assertions pass against a
  configured inline provider.
- Remote Linux CI was not run and no push was made. The workflow now runs the
  focused contract script on Linux; its platform-specific CI result remains
  pending until a separately authorized push.
