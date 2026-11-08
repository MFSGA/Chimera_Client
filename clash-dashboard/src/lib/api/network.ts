import { request } from './client';
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
) => request<PathPreferenceView>('/runtime/network/path-preference', {
  method: 'PUT',
  body: JSON.stringify({ priority, ...(ttlMs == null ? {} : { ttlMs }) }),
});
export const clearTemporaryNetworkPathPreference = () =>
  request<PathPreferenceView>('/runtime/network/path-preference', { method: 'DELETE' });
