# Clash RS Dashboard

A web dashboard for [clash-rs](https://github.com/watfaq/clash-rs) proxy software.

## Stack

- **Vite** + **React 19** + **TypeScript**
- **Tailwind CSS v4** for styling
- **shadcn/ui** for UI components
- **React Router v7** for client-side routing
- **TanStack Query v5** for REST data fetching
- **uPlot** for real-time traffic charts
- **lucide-react** for icons

## Development

```bash
npm install
npm run dev
```

The dashboard connects to the clash-rs API at `window.location.origin` by default. To develop against a local clash-rs instance:

1. Open Settings page in the dashboard
2. Set the API URL to your clash-rs address (e.g., `http://localhost:9090`)
3. Set the secret if configured

Or set `localStorage['clash-api-url']` before loading the page.

## Build

```bash
npm run build
```

Output goes to `dist/`. This is a static SPA — no server-side rendering.

Run the same frontend quality gate used by CI before submitting changes:

```bash
npm ci
npm run lint
npm run build
```

## Embedding in the Binary

The dashboard is served by clash-rs when the `dashboard` feature flag is enabled. The built `dist/` folder is embedded into the binary at compile time and served under `/ui/`.

The app uses `base: './'` in Vite config to support being served from any path prefix.

Cargo builds with the `dashboard` feature embed the existing `dist/` output; they
do not install Node.js dependencies or invoke npm. Build the frontend before a
dashboard-enabled CLI build:

```bash
npm ci
npm run build
cargo build -p clash-rs
```

CI builds and validates the Dashboard in its own job, then shares the resulting
static assets with Rust jobs. This keeps frontend tooling out of core Rust builds
and cross-compilation containers.
