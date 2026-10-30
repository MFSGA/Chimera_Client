import { lazy, Suspense } from 'react';
import { HashRouter as BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/Layout';
import { Overview } from './pages/Overview';
import { ProxyList } from './pages/ProxyList';
import { Connections } from './pages/Connections';
import { Flows } from './pages/Flows';
import { Rules } from './pages/Rules';
import { Logs } from './pages/Logs';
import { DNS } from './pages/DNS';
import { Settings } from './pages/Settings';

const Network = lazy(() => import('./pages/Network').then(({ Network }) => ({ default: Network })));

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
            <Route index element={<Overview />} />
            <Route path="proxies" element={<ProxyList />} />
            <Route path="providers" element={<ProxyList />} />
            <Route path="connections" element={<Connections />} />
            <Route path="flows" element={<Flows />} />
            <Route path="rules" element={<Rules />} />
            <Route path="logs" element={<Logs />} />
            <Route path="dns" element={<DNS />} />
            <Route
              path="network"
              element={(
                <Suspense fallback={<div className="p-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading network diagnostics…</div>}>
                  <Network />
                </Suspense>
              )}
            />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
