import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseQueryResult } from '@tanstack/react-query';
import { AlertTriangle, Clock3, RefreshCw, Route, Wifi } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import {
  getEffectiveNetworkPaths,
  getNetworkPathDecisions,
  getNetworkPathPreference,
  getNetworkStatus,
  clearTemporaryNetworkPathPreference,
  updateNetworkPathPreference,
} from '../lib/api';
import type {
  EffectiveNetworkPaths,
  NetworkPathDecisionRecord,
  NetworkPathIdView,
  PathPreferencePriority,
  PathPreferenceView,
  RuntimeNetworkStatus,
} from '../lib/api';

const PATH_PREFERENCE_QUERY_KEY = ['network-path-preference'] as const;
const PREFERENCE_INTERFACES: PathPreferencePriority['interface'][] = [
  'ethernet', 'wifi', 'cellular', 'vpn', 'virtual', 'loopback', 'other',
];

function phaseLabel(value: string): string {
  const labels: Record<string, string> = {
    observing: 'Monitoring',
    unsupported: 'Unsupported',
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
    ready: 'Ready',
    notConfigured: 'Not configured',
    unknown: 'Not yet verified',
    available: 'Traffic observed',
    unavailable: 'Unavailable after repeated failures',
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
    control: 'Control plane',
    api: 'Controller API',
    dns: 'DNS',
    inbound: 'Inbound listeners',
    tun: 'TUN',
    requiredIntentMismatch: 'Does not match a required preference',
    endpointFamilyMismatch: 'Address family does not match',
  };
  return labels[value] ?? value;
}

function phaseVariant(value: string): 'green' | 'amber' | 'red' | 'gray' | 'blue' {
  if (['healthy', 'running', 'ready', 'observing', 'trafficVerified', 'succeeded', 'connected'].includes(value)) {
    return 'green';
  }
  if (['recovering', 'awaitingTraffic', 'waitingForNetwork', 'starting', 'reloading'].includes(value)) {
    return 'amber';
  }
  if (['degraded', 'failed', 'dialFailed', 'pathPlanningFailed', 'staleNetworkDiscarded', 'staleDecisionDiscarded'].includes(value)) {
    return 'red';
  }
  if (['unsupported', 'notConfigured', 'stopped'].includes(value)) return 'gray';
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

function priorityKey(priority: PathPreferencePriority): string {
  return `${priority.interface}:${priority.family}`;
}

function samePriority(left: PathPreferencePriority, right: PathPreferencePriority): boolean {
  return left.interface === right.interface && left.family === right.family;
}

function isPreferenceInterface(value: string): value is PathPreferencePriority['interface'] {
  return PREFERENCE_INTERFACES.includes(value as PathPreferencePriority['interface']);
}

function pathKey(path: NetworkPathIdView): string {
  return JSON.stringify([
    path.interface.name,
    path.interface.index,
    path.family,
    path.sourceAddress,
    path.networkGeneration,
  ]);
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

function PathPreferenceEditor({
  paths,
  preference,
}: {
  paths: EffectiveNetworkPaths | undefined;
  preference: UseQueryResult<PathPreferenceView, Error>;
}) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<PathPreferencePriority[]>([]);
  const [lifetime, setLifetime] = useState('unchanged');
  const [candidateKey, setCandidateKey] = useState('');
  const syncedPreference = useRef('');

  useEffect(() => {
    const current = preference.data;
    if (!current) return;
    const versionKey = JSON.stringify([
      current.policyVersion,
      current.source,
      current.createdAtMs,
      current.expiresAtMs,
      current.priority,
    ]);
    if (syncedPreference.current === versionKey) return;
    syncedPreference.current = versionKey;
    setDraft(current.priority);
    setLifetime('unchanged');
  }, [preference.data]);

  const save = useMutation({
    mutationFn: ({ priority, ttlMs }: { priority: PathPreferencePriority[]; ttlMs?: number }) =>
      updateNetworkPathPreference(priority, ttlMs),
    onSuccess: (data: PathPreferenceView) => {
      queryClient.setQueryData(PATH_PREFERENCE_QUERY_KEY, data);
    },
  });
  const clearTemporary = useMutation({
    mutationFn: clearTemporaryNetworkPathPreference,
    onSuccess: (data: PathPreferenceView) => {
      queryClient.setQueryData(PATH_PREFERENCE_QUERY_KEY, data);
    },
  });

  const priorityOptions = new Map<string, PathPreferencePriority>();
  for (const path of paths?.paths ?? []) {
    if (!isPreferenceInterface(path.interfaceKind)) continue;
    const priority = {
      interface: path.interfaceKind,
      family: path.family,
    };
    priorityOptions.set(priorityKey(priority), priority);
  }
  const addableOptions = [...priorityOptions.values()].filter(
    (option) => !draft.some((entry) => samePriority(entry, option)),
  );
  const isTemporary = preference.data?.source === 'temporaryOverride';
  const busy = save.isPending || clearTemporary.isPending;
  const mutationError = save.error ?? clearTemporary.error;
  const draftMatchesCurrent = preference.data
    ? JSON.stringify(draft) === JSON.stringify(preference.data.priority)
    : false;

  function applyPreference(priority: PathPreferencePriority[]) {
    const ttlMs = lifetime === 'runtime'
      ? undefined
      : lifetime === 'unchanged'
        ? (preference.data?.expiresAtMs == null
          ? undefined
          : Math.max(1000, Math.min(86_400_000, preference.data.expiresAtMs - Date.now())))
        : Number(lifetime);
    save.mutate({ priority, ttlMs });
  }

  function movePriority(index: number, offset: -1 | 1) {
    setDraft((current) => {
      const targetIndex = index + offset;
      if (targetIndex < 0 || targetIndex >= current.length) return current;
      const next = [...current];
      [next[index], next[targetIndex]] = [next[targetIndex], next[index]];
      return next;
    });
  }

  return (
    <section className="liquid-glass-card rounded-xl overflow-hidden">
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
        <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Path preference</h2>
        <p className="mt-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
          Order interface type and address-family preferences for new connections that use automatic path selection. This does not change system routes or override a required interface.
        </p>
      </div>

      {preference.isLoading ? (
        <div className="px-4 py-5 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading path preference…</div>
      ) : preference.isError ? (
        <div className="p-4"><ErrorNotice message={preference.error instanceof Error ? preference.error.message : 'Could not load path preference.'} /></div>
      ) : preference.data ? (
        <div className="space-y-4 p-4">
          {!preference.data.automaticSupported && (
            <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
              Path preferences are unavailable because this platform does not report automatic network paths.
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={isTemporary ? 'amber' : 'gray'}>{isTemporary ? 'Temporary override' : 'Runtime preference'}</Badge>
            <span className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Policy version {preference.data.policyVersion}
              {preference.data.expiresAtMs == null ? ' · cleared when the core exits' : ` · expires ${formatTimestamp(preference.data.expiresAtMs)}`}
            </span>
          </div>

          {draft.length === 0 ? (
            <div className="rounded-lg px-3 py-2 text-[13px]" style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}>
              No explicit preference is set; the core uses its default path-selection rules.
            </div>
          ) : (
            <ol className="space-y-2">
              {draft.map((priority, index) => {
                const observed = (paths?.paths ?? []).some(
                  (path) => path.interfaceKind === priority.interface && path.family === priority.family,
                );
                return (
                  <li key={priorityKey(priority)} className="flex flex-wrap items-center justify-between gap-2 rounded-lg px-3 py-2" style={{ background: 'var(--color-fill-subtle)' }}>
                    <div className="flex items-center gap-2 text-[13px]" style={{ color: 'var(--color-text-primary)' }}>
                      <span className="font-semibold">{index + 1}.</span>
                      <span>{phaseLabel(priority.interface)} · {phaseLabel(priority.family)}</span>
                      {!observed && <Badge variant="gray">Not currently observed</Badge>}
                    </div>
                    <div className="flex gap-1">
                      <Button size="xs" variant="outline" aria-label={`Move preference ${index + 1} up`} disabled={busy || index === 0} onClick={() => movePriority(index, -1)}>↑</Button>
                      <Button size="xs" variant="outline" aria-label={`Move preference ${index + 1} down`} disabled={busy || index === draft.length - 1} onClick={() => movePriority(index, 1)}>↓</Button>
                      <Button size="xs" variant="outline" aria-label={`Remove preference ${index + 1}`} disabled={busy} onClick={() => setDraft((current) => current.filter((_, itemIndex) => itemIndex !== index))}>Remove</Button>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}

          <div className="flex flex-wrap items-end gap-2">
            <label className="min-w-52 flex-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Add an observed path
              <select
                value={candidateKey}
                onChange={(event) => setCandidateKey(event.target.value)}
                disabled={!preference.data.automaticSupported || addableOptions.length === 0 || busy}
                className="mt-1 w-full rounded-lg border px-3 py-2 text-[13px]"
                style={{ background: 'var(--color-input-bg)', borderColor: 'var(--color-separator)', color: 'var(--color-text-primary)' }}
              >
                <option value="">Select interface type and family…</option>
                {addableOptions.map((option) => <option key={priorityKey(option)} value={priorityKey(option)}>{phaseLabel(option.interface)} · {phaseLabel(option.family)}</option>)}
              </select>
            </label>
            <Button
              variant="outline"
              disabled={!candidateKey || busy || !preference.data.automaticSupported}
              onClick={() => {
                const selected = priorityOptions.get(candidateKey);
                if (selected && !draft.some((entry) => samePriority(entry, selected))) setDraft((current) => [...current, selected]);
                setCandidateKey('');
              }}
            >Add preference</Button>

            <label className="min-w-52 flex-1 text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
              Lifetime
              <select
                value={lifetime}
                onChange={(event) => setLifetime(event.target.value)}
                disabled={!preference.data.automaticSupported || busy}
                className="mt-1 w-full rounded-lg border px-3 py-2 text-[13px]"
                style={{ background: 'var(--color-input-bg)', borderColor: 'var(--color-separator)', color: 'var(--color-text-primary)' }}
              >
                <option value="unchanged">Keep current lifetime</option>
                <option value="runtime">Until the core exits</option>
                <option value="900000">15 minutes</option>
                <option value="3600000">1 hour</option>
                <option value="86400000">24 hours</option>
              </select>
            </label>
          </div>

          <p className="text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
            Preferences apply to new connections. Existing connections are not moved, and runtime preferences are not written to the YAML configuration.
          </p>
          {mutationError && (
            <ErrorNotice message={mutationError instanceof Error ? mutationError.message : 'Could not update path preference.'} />
          )}
          {(save.isSuccess || clearTemporary.isSuccess) && !mutationError && lifetime === 'unchanged' && draftMatchesCurrent && (
            <div role="status" className="text-[13px]" style={{ color: '#34a853' }}>Path preference updated.</div>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            {isTemporary && (
              <Button variant="outline" disabled={busy} onClick={() => clearTemporary.mutate()}>
                Clear temporary override
              </Button>
            )}
            <Button variant="outline" disabled={busy || !preference.data.automaticSupported} onClick={() => save.mutate({ priority: [] })}>
              Use core default
            </Button>
            <Button disabled={busy || !preference.data.automaticSupported} onClick={() => applyPreference(draft)}>
              {busy ? 'Applying…' : 'Apply preference'}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
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
                <Badge variant={phaseVariant(operation.report.interface.phase)}>Interface: {phaseLabel(operation.report.interface.phase)} · {operation.report.interface.count}</Badge>
                <Badge variant={phaseVariant(operation.report.dns.phase)}>DNS: {phaseLabel(operation.report.dns.phase)} · {operation.report.dns.count}</Badge>
                <Badge variant={phaseVariant(operation.report.pools.phase)}>Connection pools: {phaseLabel(operation.report.pools.phase)} · {operation.report.pools.count}</Badge>
                {operation.report.offline && <Badge variant="red">No usable network path</Badge>}
              </div>
              {(operation.report.interface.error || operation.report.dns.error || operation.report.pools.error || operation.report.observationError) && (
                <div className="mt-3 space-y-1">
                  {[operation.report.interface.error, operation.report.dns.error, operation.report.pools.error, operation.report.observationError]
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

function RuntimeComponents({ components }: { components: RuntimeNetworkStatus['components'] }) {
  return (
    <section className="liquid-glass-card rounded-xl overflow-hidden">
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--color-separator)' }}>
        <h2 className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>Runtime components</h2>
        <p className="text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>A running process does not mean every configured component is ready.</p>
      </div>
      {components.length === 0 ? (
        <div className="px-4 py-5 text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>No component readiness details were reported.</div>
      ) : (
        <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
          {components.map((component) => (
            <div key={component.name} className="rounded-xl p-3" style={{ background: 'var(--color-fill-subtle)' }}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-[13px] font-medium" style={{ color: 'var(--color-text-primary)' }}>{phaseLabel(component.name)}</div>
                <Badge variant={phaseVariant(component.phase)}>{phaseLabel(component.phase)}</Badge>
              </div>
              <div className="mt-1 text-[11px]" style={{ color: 'var(--color-text-tertiary)' }}>
                {component.required ? 'Required' : 'Optional'} · since {formatTimestamp(component.sinceMs)}
              </div>
              {component.error && <div className="mt-2 break-words text-[12px]" style={{ color: '#ff3b30' }}>{component.error}</div>}
            </div>
          ))}
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
                <div>{record.route.outbound === 'notEvaluated' ? 'Not evaluated' : record.route.outbound}</div>
                <div className="text-[11px] font-normal" style={{ color: 'var(--color-text-tertiary)' }}>
                  {record.route.outbound === 'notEvaluated' ? 'Selection skipped' : record.route.rule ?? 'Mode selection'}
                </div>
              </td>
              <td className="px-4 py-3"><Badge variant={phaseVariant(record.outcome)}>{phaseLabel(record.outcome)}</Badge></td>
              <td className="min-w-56 px-4 py-3" style={{ color: 'var(--color-text-primary)' }}>{pathLabel(record.selectedPath)}</td>
              <td className="max-w-md px-4 py-3" style={{ color: record.failureKind ? '#ff3b30' : 'var(--color-text-secondary)' }}>
                {record.failureKind ? `${record.failureKind}: ` : ''}{record.reason}
                <details className="mt-2">
                  <summary className="cursor-pointer select-none text-[12px]" style={{ color: '#0071e3' }}>
                    Decision details
                  </summary>
                  <div className="mt-2 space-y-3 rounded-lg p-3" style={{ background: 'var(--color-fill-subtle)' }}>
                    <dl className="grid gap-x-3 gap-y-2 sm:grid-cols-2">
                      {record.destination && (
                        <div className="min-w-0">
                          <dt className="text-[11px] font-semibold uppercase tracking-wide">Destination</dt>
                          <dd className="mt-0.5 break-all font-mono text-[11px]">{record.destination}</dd>
                        </div>
                      )}
                      <div className="min-w-0">
                        <dt className="text-[11px] font-semibold uppercase tracking-wide">Flow ID</dt>
                        <dd className="mt-0.5 break-all font-mono text-[11px]">{record.flowId}</dd>
                      </div>
                      <div>
                        <dt className="text-[11px] font-semibold uppercase tracking-wide">Operation</dt>
                        <dd className="mt-0.5">{record.operationId}</dd>
                      </div>
                      <div>
                        <dt className="text-[11px] font-semibold uppercase tracking-wide">Configuration version</dt>
                        <dd className="mt-0.5">
                          {record.configVersionAtCompletion == null
                            ? record.configVersion
                            : `${record.configVersion} → ${record.configVersionAtCompletion}`}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-[11px] font-semibold uppercase tracking-wide">Network / policy version</dt>
                        <dd className="mt-0.5">{record.networkVersion} / {record.policyVersion}</dd>
                      </div>
                    </dl>
                    {record.configVersionAtCompletion != null
                      && record.configVersionAtCompletion !== record.configVersion && (
                        <div role="status" className="rounded-md px-2 py-1.5 text-[12px]" style={{ background: 'rgba(255,149,0,0.1)', color: '#b55b00' }}>
                          The connection completed after the configuration changed. The recorded route reflects configuration version {record.configVersion}.
                        </div>
                      )}
                    {((record.candidatePaths?.length ?? 0) > 0 || (record.rejected?.length ?? 0) > 0) && (
                      <div>
                        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide">
                          Path explanation ({record.candidatePaths?.length ?? 0} candidates, {record.rejected?.length ?? 0} rejected)
                        </div>
                        <div className="space-y-2">
                          <div>
                            <div className="mb-1 text-[11px] font-semibold">Candidate paths</div>
                            {record.candidatePaths?.length ? (
                              <ul className="space-y-1">
                                {(record.candidatePaths ?? []).map((path) => <li key={pathKey(path)}>{pathLabel(path)}</li>)}
                              </ul>
                            ) : <div>No path candidate was recorded.</div>}
                          </div>
                          {(record.rejected?.length ?? 0) > 0 && (
                            <div>
                              <div className="mb-1 text-[11px] font-semibold">Rejected paths</div>
                              <ul className="space-y-1">
                                {(record.rejected ?? []).map((rejection) => (
                                  <li key={`${pathKey(rejection.path)}-${rejection.reason}-${rejection.intentIndex ?? 'none'}`}>
                                    {pathLabel(rejection.path)} — {phaseLabel(rejection.reason)}
                                    {rejection.intentIndex == null ? '' : ` (preference ${rejection.intentIndex + 1})`}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </details>
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
  const preference = useQuery({ queryKey: PATH_PREFERENCE_QUERY_KEY, queryFn: getNetworkPathPreference, refetchInterval: 5000, retry: 0 });

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
