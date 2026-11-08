import { Badge } from '@/components/ui/badge';
import type { NetworkPathDecisionRecord, RuntimeNetworkStatus } from '@/lib/api/types/network';
import { formatTimestamp, pathKey, pathLabel, phaseLabel, phaseVariant } from '@/features/network/networkUtils';

export function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="liquid-glass-card rounded-xl p-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em]" style={{ color: 'var(--color-text-secondary)' }}>{label}</div>
      <div className="mt-2 text-[20px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>{value}</div>
      {detail && <div className="mt-1 text-[12px]" style={{ color: 'var(--color-text-tertiary)' }}>{detail}</div>}
    </div>
  );
}

export function RecoverySummary({ status }: { status: RuntimeNetworkStatus }) {
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

export function RuntimeComponents({ components }: { components: RuntimeNetworkStatus['components'] }) {
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

export function DecisionsTable({ records }: { records: NetworkPathDecisionRecord[] }) {
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
                <div>{record.failureKind === 'fakeIpMappingMissing' && record.route.outbound === 'notEvaluated' ? 'Not evaluated' : record.route.outbound}</div>
                <div className="text-[11px] font-normal" style={{ color: 'var(--color-text-tertiary)' }}>
                  {record.failureKind === 'fakeIpMappingMissing' && record.route.outbound === 'notEvaluated' ? 'Selection skipped' : record.route.rule ?? 'Mode selection'}
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
