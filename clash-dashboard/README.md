# Clash RS Dashboard

A web dashboard for [clash-rs](https://github.com/watfaq/clash-rs) proxy software.

Node.js is pinned in `.node-version`; CI reads that file and Nix checks its
locked Node.js package against it. The `packageManager` field in `package.json`
pins pnpm for CI and Nix, while `pnpm-lock.yaml` pins the complete dependency graph.
Use a version manager that reads `.node-version`, or enter the repository's
`nix develop` shell for the matching local Node.js and pnpm versions.

## Stack

- **Vite** + **React 19** + **TypeScript**
- **Tailwind CSS v4** for styling
- **shadcn/ui** for UI components
- **React Router v7** for client-side routing
- **TanStack Query v5** for REST data fetching
- **uPlot** for real-time traffic charts
- **lucide-react** for icons

## Code organization

- `src/App.tsx` defines the route table and lazy-loads each screen.
- `src/app/` holds routing shell, providers, and shared client configuration.
- `src/features/<name>/` holds the screen for one user-facing feature.
- Feature-only UI stays under its feature; `src/components/` contains UI shared by multiple features.
- `src/lib/api/` groups controller requests and response types by API domain; `src/lib/queryKeys.ts`
  keeps server-state caches scoped to the configured controller URL.
- `src/hooks/` and `src/lib/` contain cross-feature hooks and utilities.

Keep feature-specific state and UI close to its screen. Promote code to the
shared directories when multiple features use it.

## Development

```bash
pnpm install --frozen-lockfile
pnpm dev
```

The dashboard connects to the clash-rs API at `window.location.origin` by default. To develop against a local clash-rs instance:

1. Open Settings page in the dashboard
2. Set the API URL to your clash-rs address (e.g., `http://localhost:9090`)
3. Set the secret if configured

Or set `localStorage['clash-api-url']` before loading the page.

## Build

```bash
pnpm build
```

Output goes to `dist/`. This is a static SPA — no server-side rendering.

Run the same frontend quality gate used by CI before submitting changes:

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm build
```

## Embedding in the Binary

The dashboard is served by clash-rs when the `dashboard` feature flag is enabled. The built `dist/` folder is embedded into the binary at compile time and served under `/ui/`.

The app uses `base: './'` in Vite config to support being served from any path prefix.

Cargo builds with the `dashboard` feature embed the existing `dist/` output; they
do not install Node.js dependencies or invoke pnpm. Build the frontend before a
dashboard-enabled CLI build:

```bash
pnpm install --frozen-lockfile
pnpm build
cargo build -p clash-rs
```

CI builds and validates the Dashboard in its own job, then shares the resulting
static assets with Rust jobs. This keeps frontend tooling out of core Rust builds
and cross-compilation containers.
