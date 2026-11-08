import { lazy, Suspense, type ReactNode } from 'react';
import { HashRouter as BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/Layout';
const Overview = lazy(() => import('./pages/Overview').then(({ Overview }) => ({ default: Overview })));
const ProxyList = lazy(() => import('./pages/ProxyList').then(({ ProxyList }) => ({ default: ProxyList })));
const Connections = lazy(() => import('./pages/Connections').then(({ Connections }) => ({ default: Connections })));
const Flows = lazy(() => import('./pages/Flows').then(({ Flows }) => ({ default: Flows })));
const Rules = lazy(() => import('./pages/Rules').then(({ Rules }) => ({ default: Rules })));
const Logs = lazy(() => import('./pages/Logs').then(({ Logs }) => ({ default: Logs })));
const DNS = lazy(() => import('./pages/DNS').then(({ DNS }) => ({ default: DNS })));
const Settings = lazy(() => import('./pages/Settings').then(({ Settings }) => ({ default: Settings })));

const Network = lazy(() => import('./pages/Network').then(({ Network }) => ({ default: Network })));

function LazyPage({ children, message = 'Loading page…' }: { children: ReactNode; message?: string }) {
  return (
    <Suspense fallback={<div className="p-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>{message}</div>}>
      {children}
    </Suspense>
  );
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
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
    </QueryClientProvider>
  );
}
