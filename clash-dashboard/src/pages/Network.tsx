import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Clock3, RefreshCw, Route, Wifi } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import {
  getEffectiveNetworkPaths,
  getNetworkPathDecisions,
  getNetworkStatus,
} from '../lib/api';
import type {
  NetworkPathDecisionRecord,
  NetworkPathIdView,
  RuntimeNetworkStatus,
} from '../lib/api';

function phaseLabel(value: string): string {
  const labels: Record<string, string> = {
    observing: 'Monitoring',
    unsupported: 'Not available',
    recovering: 'Recovering',
    awaitingTraffic: 'Waiting for traffic',
    trafficVerified: 'Traffic verified',
    waitingForNetwork: 'Waiting for a network',
    degraded: 'Needs attention',
    starting: 'Starting',
    running: 'Running',
    reloading: 'Reloading',
    stopping: 'Stopping',
    stopped: 'Stopped',
    failed: 'Failed',
    healthy: 'Healthy',
    unknown: 'Not yet verified',
    available: 'Traffic observed',
    unavailable: 'Repeated failures',
    networkChanged: 'Network changed',
    manualReset: 'Manual refresh',
    retry: 'Retry',
    succeeded: 'Completed',
    cancelled: 'Cancelled',
    superseded: 'Replaced by newer change',
    refreshed: 'Refreshed',
    skipped: 'Skipped',
    timedOut: 'Timed out',
    primaryDefaultRoute: 'Primary route',
    otherInterface: 'Other interface',
    ambiguousDefaultRoute: 'Ambiguous route',
    noPrimaryRouteObserved: 'No primary route observed',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    ethernet: 'Ethernet',
    wifi: 'Wi-Fi',
    cellular: 'Cellular',
    vpn: 'VPN',
    virtual: 'Virtual',
    loopback: 'Loopback',
    other: 'Other',
  };
  return labels[value] ?? value;
}

function phaseVariant(value: string): 'green' | 'amber' | 'red' | 'gray' | 'blue' {
  if (['healthy', 'running', 'observing', 'trafficVerified', 'succeeded', 'connected'].includes(value)) {
    return 'green';
  }
  if (['recovering', 'awaitingTraffic', 'waitingForNetwork', 'starting', 'reloading'].includes(value)) {
    return 'amber';
  }
  if (['degraded', 'failed', 'dialFailed', 'pathPlanningFailed', 'staleNetworkDiscarded'].includes(value)) {
    return 'red';
  }
  if (['unsupported', 'stopped'].includes(value)) return 'gray';
  return 'blue';
}

function pathLabel(path: NetworkPathIdView | null): string {
  if (!path) return 'No path selected';
  const name = path.interface?.name || 'Unknown interface';
  const family = path.family === 'ipv4' ? 'IPv4' : path.family === 'ipv6' ? 'IPv6' : path.family;
  return `${name} · ${family} · ${path.sourceAddress ?? 'source address unavailable'}`;
}

function formatTimestamp(timestamp: number | null | undefined): string {
  if (timestamp == null || !Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toLocaleString();
}

function samePath(left: NetworkPathIdView | null | undefined, right: NetworkPathIdView | null | undefined): boolean {
  return Boolean(left && right
    && left.interface.name === right.interface.name
    && left.interface.index === right.interface.index
    && left.family === right.family
    && left.sourceAddress === right.sourceAddress
    && left.networkGeneration === right.networkGeneration);
}

function ErrorNotice({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-xl p-3 text-[13px]"
      style={{ background: 'rgba(255,59,48,0.08)', border: '1px solid rgba(255,59,48,0.2)', color: '#ff3b30' }}
    >
      <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
      <span>{message}</span>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="liquid-glass-card rounded-xl p-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em]" style={{ color: 'var(--color-text-secondary)' }}>{label}</div>
      <div className="mt-2 text-[20px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>{value}</div>
      {detail && <div className="mt-1 text-[12px]" style={{ color: 'var(--color-text-tertiary)' }}>{detail}</div>}
    </div>
  );
}

function RecoverySummary({ status }: { status: RuntimeNetworkStatus }) {
  const operation = status.lastOperation;
  return (
    <section className="liquid-glass-card rounded-xl overflow-hidden">
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
        <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Most recent recovery</h2>
      </div>
      {!operation ? (
        <div className="px-4 py-5 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
          No recovery operation has been recorded yet.
        </div>
      ) : (
        <div className="grid gap-4 p-4 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--color-text-tertiary)' }}>Cause</div>
            <div className="mt-1 text-[13px] font-medium" style={{ color: 'var(--color-text-primary)' }}>{phaseLabel(operation.cause)}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--color-text-tertiary)' }}>Result</div>
            <Badge className="mt-1" variant={phaseVariant(operation.outcome)}>{phaseLabel(operation.outcome)}</Badge>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--color-text-tertiary)' }}>Duration</div>
            <div className="mt-1 text-[13px] font-medium" style={{ color: 'var(--color-text-primary)' }}>
              {operation.durationMs == null ? 'In progress' : `${operation.durationMs} ms`}
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide" style={{ color: 'var(--color-text-tertiary)' }}>Started</div>
            <div className="mt-1 text-[13px] font-medium" style={{ color: 'var(--color-text-primary)' }}>{formatTimestamp(operation.startedAtMs)}</div>
          </div>
          {operation.report && (
            <div className="sm:col-span-2 lg:col-span-4">
              <div className="flex flex-wrap gap-2">
                <Badge variant={phaseVariant(operation.report.dns.phase)}>DNS: {phaseLabel(operation.report.dns.phase)} · {operation.report.dns.count}</Badge>
                <Badge variant={phaseVariant(operation.report.pools.phase)}>Connection pools: {phaseLabel(operation.report.pools.phase)} · {operation.report.pools.count}</Badge>
                {operation.report.offline && <Badge variant="red">No usable network path</Badge>}
              </div>
              {(operation.report.dns.error || operation.report.pools.error || operation.report.observationError) && (
                <div className="mt-3 space-y-1">
                  {[operation.report.dns.error, operation.report.pools.error, operation.report.observationError]
                    .filter((error): error is string => Boolean(error))
                    .map((error) => <div key={error} className="text-[12px]" style={{ color: '#ff3b30' }}>{error}</div>)}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function DecisionsTable({ records }: { records: NetworkPathDecisionRecord[] }) {
  if (records.length === 0) {
    return <div className="px-4 py-8 text-center text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>No recent path decisions.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead>
          <tr className="border-b text-[11px] uppercase tracking-wide" style={{ borderColor: 'var(--color-separator)', color: 'var(--color-text-secondary)' }}>
            <th className="px-4 py-3 font-semibold">Time</th>
            <th className="px-4 py-3 font-semibold">Route</th>
            <th className="px-4 py-3 font-semibold">Result</th>
            <th className="px-4 py-3 font-semibold">Selected path</th>
            <th className="px-4 py-3 font-semibold">Details</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <tr key={record.flowId} className="border-b last:border-0" style={{ borderColor: 'var(--color-separator)' }}>
              <td className="whitespace-nowrap px-4 py-3" style={{ color: 'var(--color-text-secondary)' }}>{formatTimestamp(record.recordedAtMs)}</td>
              <td className="px-4 py-3 font-medium" style={{ color: 'var(--color-text-primary)' }}>
                <div>{record.route.outbound}</div>
                <div className="text-[11px] font-normal" style={{ color: 'var(--color-text-tertiary)' }}>{record.route.rule ?? 'Mode selection'}</div>
              </td>
              <td className="px-4 py-3"><Badge variant={phaseVariant(record.outcome)}>{phaseLabel(record.outcome)}</Badge></td>
              <td className="min-w-56 px-4 py-3" style={{ color: 'var(--color-text-primary)' }}>{pathLabel(record.selectedPath)}</td>
              <td className="max-w-md px-4 py-3" style={{ color: record.failureKind ? '#ff3b30' : 'var(--color-text-secondary)' }}>
                {record.failureKind ? `${record.failureKind}: ` : ''}{record.reason}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Network() {
  const status = useQuery({ queryKey: ['network-status'], queryFn: getNetworkStatus, refetchInterval: 5000, retry: 0 });
  const paths = useQuery({ queryKey: ['network-effective-paths'], queryFn: getEffectiveNetworkPaths, refetchInterval: 5000, retry: 0 });
  const decisions = useQuery({ queryKey: ['network-path-decisions'], queryFn: getNetworkPathDecisions, refetchInterval: 5000, retry: 0 });

  async function refresh() {
    await Promise.all([status.refetch(), paths.refetch(), decisions.refetch()]);
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>Network</h1>
          <p className="mt-1 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Recovery status, available local paths, and recent connection decisions.</p>
        </div>
        <Button variant="outline" onClick={() => void refresh()} disabled={status.isFetching || paths.isFetching || decisions.isFetching}>
          <RefreshCw size={14} className={status.isFetching || paths.isFetching || decisions.isFetching ? 'animate-spin' : ''} />
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
            <Clock3 size={13} /> Path decisions are temporary diagnostics; the page does not change network preferences or reset connections.
          </div>
        </>
      ) : null}
    </div>
  );
}
