import { request } from './client';
import type { ApiSettingsSnapshot } from './client';
import type { EffectiveNetworkPaths, NetworkPathDecisionRecord, PathPreferencePriority, PathPreferenceView, RuntimeNetworkStatus } from './types';

// Network recovery diagnostics
export const getNetworkStatus = () => request<RuntimeNetworkStatus>('/runtime');
export const getEffectiveNetworkPaths = () =>
  request<EffectiveNetworkPaths>('/runtime/network/effective-paths');
export const getNetworkPathDecisions = () =>
  request<NetworkPathDecisionRecord[]>('/runtime/network/path-decisions');
export const getNetworkPathPreference = () =>
  request<PathPreferenceView>('/runtime/network/path-preference');
export const updateNetworkPathPreference = (
  priority: PathPreferencePriority[],
  ttlMs?: number,
  settings?: ApiSettingsSnapshot,
) => request<PathPreferenceView>('/runtime/network/path-preference', {
  method: 'PUT',
  body: JSON.stringify({ priority, ...(ttlMs == null ? {} : { ttlMs }) }),
}, settings);
export const clearTemporaryNetworkPathPreference = (settings?: ApiSettingsSnapshot) =>
  request<PathPreferenceView>('/runtime/network/path-preference', { method: 'DELETE' }, settings);
