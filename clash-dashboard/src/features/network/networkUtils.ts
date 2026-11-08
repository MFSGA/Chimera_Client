import type { NetworkPathIdView, PathPreferencePriority } from '@/lib/api/types/network';

const PREFERENCE_INTERFACES: PathPreferencePriority['interface'][] = [
  'ethernet', 'wifi', 'cellular', 'vpn', 'virtual', 'loopback', 'other',
];

export function phaseLabel(value: string): string {
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

export function phaseVariant(value: string): 'green' | 'amber' | 'red' | 'gray' | 'blue' {
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

export function pathLabel(path: NetworkPathIdView | null): string {
  if (!path) return 'No path selected';
  const name = path.interface?.name || 'Unknown interface';
  const family = path.family === 'ipv4' ? 'IPv4' : path.family === 'ipv6' ? 'IPv6' : path.family;
  return `${name} · ${family} · ${path.sourceAddress ?? 'source address unavailable'}`;
}

export function formatTimestamp(timestamp: number | null | undefined): string {
  if (timestamp == null || !Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toLocaleString();
}

export function samePath(left: NetworkPathIdView | null | undefined, right: NetworkPathIdView | null | undefined): boolean {
  return Boolean(left && right
    && left.interface.name === right.interface.name
    && left.interface.index === right.interface.index
    && left.family === right.family
    && left.sourceAddress === right.sourceAddress
    && left.networkGeneration === right.networkGeneration);
}

export function priorityKey(priority: PathPreferencePriority): string {
  return `${priority.interface}:${priority.family}`;
}

export function samePriority(left: PathPreferencePriority, right: PathPreferencePriority): boolean {
  return left.interface === right.interface && left.family === right.family;
}

export function isPreferenceInterface(value: string): value is PathPreferencePriority['interface'] {
  return PREFERENCE_INTERFACES.includes(value as PathPreferencePriority['interface']);
}

export function pathKey(path: NetworkPathIdView): string {
  return JSON.stringify([
    path.interface.name,
    path.interface.index,
    path.family,
    path.sourceAddress,
    path.networkGeneration,
  ]);
}
