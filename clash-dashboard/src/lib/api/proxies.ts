import { request } from './client';
import type { ApiSettingsSnapshot } from './client';
import type { Proxy } from './types';

// Proxies
export const getProxies = () => request<{ proxies: Record<string, Proxy> }>('/proxies');
export const selectProxy = (
  groupName: string,
  proxyName: string,
  settings?: ApiSettingsSnapshot,
) =>
  request<void>(`/proxies/${encodeURIComponent(groupName)}`, {
    method: 'PUT',
    body: JSON.stringify({ name: proxyName }),
  }, settings);
export const getProxyDelay = (name: string, url: string, timeout: number) =>
  request<{ delay: number; overall: number }>(
    `/proxies/${encodeURIComponent(name)}/delay?url=${encodeURIComponent(url)}&timeout=${timeout}`
  );

// Groups
export const getGroupDelay = (
  name: string,
  url: string,
  timeout: number,
  settings?: ApiSettingsSnapshot,
) =>
  request<Record<string, number>>(
    `/group/${encodeURIComponent(name)}/delay?url=${encodeURIComponent(url)}&timeout=${timeout}`,
    undefined,
    settings,
  );
