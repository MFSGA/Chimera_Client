export interface NetworkPathIdView {
  interface: { name: string; index: number };
  family: 'ipv4' | 'ipv6';
  sourceAddress: string | null;
  networkGeneration: number;
}
export interface RuntimeNetworkStatus {
  automaticSupported: boolean;
  phase: string;
  generation: number;
  failures: number;
  lastError: string | null;
  application: { phase: string; health: string; reason: string };
  components: Array<{
    name: string;
    required: boolean;
    phase: string;
    sinceMs: number;
    error: string | null;
  }>;
  configVersion: number;
  networkVersion: number;
  lastObservedAtMs: number | null;
  observationError: string | null;
  nextRetryAtMs: number | null;
  policyVersion: number;
  lastOperation: {
    cause: string;
    outcome: string;
    startedAtMs: number;
    finishedAtMs: number | null;
    durationMs: number | null;
    report: {
      interface: { phase: string; count: number; error: string | null };
      dns: { phase: string; count: number; error: string | null };
      pools: { phase: string; count: number; error: string | null };
      observationError: string | null;
      offline: boolean;
    } | null;
  } | null;
}
export interface EffectiveNetworkPaths {
  automaticSupported: boolean;
  policyVersion: number;
  networkVersion: number;
  effectivePreferredPath: {
    ipv4: NetworkPathIdView | null;
    ipv6: NetworkPathIdView | null;
  };
  paths: Array<{
    path: NetworkPathIdView;
    interfaceKind: string;
    family: 'ipv4' | 'ipv6';
    sourceAddress: string;
    defaultRouteEvidence: string;
    binding: string;
    bindingError: string | null;
    health: string;
    preferenceRank: number | null;
    cooldownUntilMs: number | null;
  }>;
}
export interface NetworkPathDecisionRecord {
  flowId: string;
  configVersion: number;
  configVersionAtCompletion?: number;
  policyVersion: number;
  networkVersion: number;
  operationId: number;
  outcome: string;
  route: { outbound: string; rule: string | null };
  destination?: string;
  candidatePaths: NetworkPathIdView[];
  selectedPath: NetworkPathIdView | null;
  rejected: Array<{
    path: NetworkPathIdView;
    reason: string;
    intentIndex: number | null;
  }>;
  failureKind?: string;
  reason: string;
  recordedAtMs: number;
}
export type PathPreferenceInterface =
  | 'ethernet'
  | 'wifi'
  | 'cellular'
  | 'vpn'
  | 'virtual'
  | 'loopback'
  | 'other';
export interface PathPreferencePriority {
  interface: PathPreferenceInterface;
  family: 'ipv4' | 'ipv6';
}
export interface PathPreferenceView {
  automaticSupported: boolean;
  policyVersion: number;
  source: string;
  priority: PathPreferencePriority[];
  createdAtMs: number | null;
  expiresAtMs: number | null;
}
