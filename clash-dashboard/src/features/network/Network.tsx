import { queryKeys } from '@/lib/queryKeys';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Clock3, RefreshCw, Route, Wifi } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { getEffectiveNetworkPaths, getNetworkPathDecisions, getNetworkPathPreference, getNetworkStatus } from '@/lib/api/network';
import { ErrorNotice } from '@/features/network/components/ErrorNotice';
import { PathPreferenceEditor } from '@/features/network/components/PathPreferenceEditor';
import { DecisionsTable, Metric, RecoverySummary, RuntimeComponents } from '@/features/network/components/NetworkStatusSections';
import { formatTimestamp, phaseLabel, phaseVariant, samePath } from '@/features/network/networkUtils';

export function Network() {
  const status = useQuery({ queryKey: queryKeys.network.status(), queryFn: getNetworkStatus, refetchInterval: 5000, retry: 0 });
  const paths = useQuery({ queryKey: queryKeys.network.paths(), queryFn: getEffectiveNetworkPaths, refetchInterval: 5000, retry: 0 });
  const decisions = useQuery({ queryKey: queryKeys.network.decisions(), queryFn: getNetworkPathDecisions, refetchInterval: 5000, retry: 0 });
  const preference = useQuery({ queryKey: queryKeys.network.pathPreference(), queryFn: getNetworkPathPreference, refetchInterval: 5000, retry: 0 });

  const refreshing = status.isFetching || paths.isFetching || decisions.isFetching || preference.isFetching;

  async function refresh() {
    await Promise.all([status.refetch(), paths.refetch(), decisions.refetch(), preference.refetch()]);
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>Network</h1>
          <p className="mt-1 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Recovery status, available local paths, and recent connection decisions.</p>
        </div>
        <Button variant="outline" onClick={() => void refresh()} disabled={refreshing}>
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          Refresh
        </Button>
      </div>

      {status.isLoading ? (
        <div className="liquid-glass-card rounded-xl p-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading network status…</div>
      ) : status.isError ? (
        <ErrorNotice message={status.error instanceof Error ? status.error.message : 'Could not load network status.'} />
      ) : status.data ? (
        <>
          {!status.data.automaticSupported && (
            <div className="flex items-start gap-3 rounded-xl p-4" style={{ background: 'rgba(255,149,0,0.08)', border: '1px solid rgba(255,149,0,0.2)' }}>
              <AlertTriangle size={18} className="mt-0.5 flex-shrink-0" style={{ color: '#ff9500' }} />
              <div>
                <div className="text-[13px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Automatic network recovery is unavailable</div>
                <div className="mt-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>The running core does not report automatic network observation support for this platform.</div>
              </div>
            </div>
          )}

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Recovery" value={phaseLabel(status.data.phase)} detail={`${phaseLabel(status.data.application.phase)} · ${phaseLabel(status.data.application.health)}`} />
            <Metric label="Network version" value={String(status.data.networkVersion)} detail={`Configuration version ${status.data.configVersion}`} />
            <Metric label="Recovery operations" value={String(status.data.generation)} detail={`${status.data.failures} failed · policy version ${status.data.policyVersion ?? '—'}`} />
            <Metric label="Last observation" value={status.data.lastObservedAtMs == null ? 'Not recorded' : formatTimestamp(status.data.lastObservedAtMs)} detail={status.data.nextRetryAtMs == null ? (status.data.observationError ?? status.data.lastError ?? 'Status refreshes every 5 seconds') : `Next retry ${formatTimestamp(status.data.nextRetryAtMs)}`} />
          </div>

          {(status.data.observationError || status.data.lastError) && <ErrorNotice message={status.data.observationError ?? status.data.lastError ?? ''} />}
          <RecoverySummary status={status.data} />
          <RuntimeComponents components={status.data.components ?? []} />
          <PathPreferenceEditor paths={paths.data} preference={preference} />

          <section className="liquid-glass-card rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
              <Wifi size={16} style={{ color: '#0071e3' }} />
              <div>
                <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Available paths</h2>
                <p className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>“Preferred now” is the path the current planner would choose for new DIRECT traffic. A verified binding only confirms the local source address can bind; it does not prove internet reachability.</p>
              </div>
            </div>
            {paths.isLoading ? (
              <div className="px-4 py-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading paths…</div>
            ) : paths.isError ? (
              <div className="p-4"><ErrorNotice message={paths.error instanceof Error ? paths.error.message : 'Could not load available paths.'} /></div>
            ) : paths.data?.paths.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13px]">
                  <thead><tr className="border-b text-[11px] uppercase tracking-wide" style={{ borderColor: 'var(--color-separator)', color: 'var(--color-text-secondary)' }}>
                    <th className="px-4 py-3 font-semibold">Interface</th><th className="px-4 py-3 font-semibold">Address</th><th className="px-4 py-3 font-semibold">Current choice</th><th className="px-4 py-3 font-semibold">Binding</th><th className="px-4 py-3 font-semibold">Traffic evidence</th><th className="px-4 py-3 font-semibold">Preference</th><th className="px-4 py-3 font-semibold">Cooldown ends</th><th className="px-4 py-3 font-semibold">Default route</th>
                  </tr></thead>
                  <tbody>{paths.data.paths.map((path) => (
                    <tr key={`${path.path.interface.name}-${path.family}-${path.sourceAddress}`} className="border-b last:border-0" style={{ borderColor: 'var(--color-separator)' }}>
                      <td className="px-4 py-3"><div className="font-medium" style={{ color: 'var(--color-text-primary)' }}>{path.path.interface.name}</div><div className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>{phaseLabel(path.interfaceKind)} · {path.path.interface.index}</div></td>
                      <td className="px-4 py-3 font-mono text-[12px]" style={{ color: 'var(--color-text-primary)' }}>{path.sourceAddress} · {phaseLabel(path.family)}</td>
                      <td className="px-4 py-3">{paths.data.effectivePreferredPath && samePath(path.path, paths.data.effectivePreferredPath[path.family]) ? <Badge variant="blue">Preferred now</Badge> : <span style={{ color: 'var(--color-text-tertiary)' }}>—</span>}</td>
                      <td className="px-4 py-3"><Badge variant={path.binding === 'verified' ? 'green' : 'red'}>{phaseLabel(path.binding)}</Badge>{path.bindingError && <div className="mt-1 max-w-xs text-[11px]" style={{ color: '#ff3b30' }}>{path.bindingError}</div>}</td>
                      <td className="px-4 py-3"><Badge variant={phaseVariant(path.health)}>{phaseLabel(path.health)}</Badge></td>
                      <td className="px-4 py-3" style={{ color: 'var(--color-text-secondary)' }}>{path.preferenceRank == null ? 'Default order' : `Priority ${path.preferenceRank}`}</td>
                      <td className="whitespace-nowrap px-4 py-3" style={{ color: 'var(--color-text-secondary)' }}>{formatTimestamp(path.cooldownUntilMs)}</td>
                      <td className="px-4 py-3" style={{ color: 'var(--color-text-secondary)' }}>{phaseLabel(path.defaultRouteEvidence)}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : (
              <div className="px-4 py-8 text-center text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
                {paths.data?.automaticSupported ? 'No local paths are currently available.' : 'Path observations are not available.'}
              </div>
            )}
          </section>

          <section className="liquid-glass-card rounded-xl overflow-hidden">
            <div className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
              <div className="flex items-center gap-2"><Route size={16} style={{ color: '#0071e3' }} /><h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Recent path decisions</h2></div>
              <div className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>Recent records expire automatically</div>
            </div>
            {decisions.isLoading ? (
              <div className="px-4 py-6 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading decisions…</div>
            ) : decisions.isError ? (
              <div className="p-4"><ErrorNotice message={decisions.error instanceof Error ? decisions.error.message : 'Could not load path decisions.'} /></div>
            ) : (
              <DecisionsTable records={decisions.data ?? []} />
            )}
          </section>

          <div className="flex items-center gap-2 text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
            <Clock3 size={13} /> Path decisions expire automatically; preference changes affect new connections and do not move existing sessions.
          </div>
        </>
      ) : null}
    </div>
  );
}
