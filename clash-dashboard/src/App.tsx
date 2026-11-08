import { lazy, Suspense, type ReactNode } from 'react';
import { HashRouter as BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './app/Layout';
import { useApiSettingsRevision } from './hooks/useApiSettingsRevision';
const Overview = lazy(() => import('./features/overview/Overview').then(({ Overview }) => ({ default: Overview })));
const ProxyList = lazy(() => import('./features/proxies/ProxyList').then(({ ProxyList }) => ({ default: ProxyList })));
const Connections = lazy(() => import('./features/connections/Connections').then(({ Connections }) => ({ default: Connections })));
const Flows = lazy(() => import('./features/flows/Flows').then(({ Flows }) => ({ default: Flows })));
const Rules = lazy(() => import('./features/rules/Rules').then(({ Rules }) => ({ default: Rules })));
const Logs = lazy(() => import('./features/logs/Logs').then(({ Logs }) => ({ default: Logs })));
const DNS = lazy(() => import('./features/dns/DNS').then(({ DNS }) => ({ default: DNS })));
const Settings = lazy(() => import('./features/settings/Settings').then(({ Settings }) => ({ default: Settings })));

const Network = lazy(() => import('./features/network/Network').then(({ Network }) => ({ default: Network })));

function LazyPage({ children, message = 'Loading page…' }: { children: ReactNode; message?: string }) {
  return (
    <Suspense fallback={<div className="p-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>{message}</div>}>
      {children}
    </Suspense>
  );
}

export default function App() {
  useApiSettingsRevision();

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<LazyPage><Overview /></LazyPage>} />
          <Route path="proxies" element={<LazyPage><ProxyList /></LazyPage>} />
          <Route path="providers" element={<LazyPage><ProxyList /></LazyPage>} />
          <Route path="connections" element={<LazyPage><Connections /></LazyPage>} />
          <Route path="flows" element={<LazyPage><Flows /></LazyPage>} />
          <Route path="rules" element={<LazyPage><Rules /></LazyPage>} />
          <Route path="logs" element={<LazyPage><Logs /></LazyPage>} />
          <Route path="dns" element={<LazyPage><DNS /></LazyPage>} />
          <Route
            path="network"
            element={(
              <LazyPage message="Loading network diagnostics…">
                <Network />
              </LazyPage>
            )}
          />
          <Route path="settings" element={<LazyPage><Settings /></LazyPage>} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
