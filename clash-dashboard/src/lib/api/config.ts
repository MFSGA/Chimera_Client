import { request } from './client';
import type { ClashConfig, PatchableConfig } from './types';

// Config
export const getConfigs = () => request<ClashConfig>('/configs');
export const updateConfigs = (config: Partial<ClashConfig>) =>
  request<void>('/configs', { method: 'PUT', body: JSON.stringify(config) });
export const reloadConfigs = (path: string) =>
  request<void>('/configs', { method: 'PUT', body: JSON.stringify({ path }) });
export const patchConfigs = (patch: PatchableConfig) =>
  request<void>('/configs', { method: 'PATCH', body: JSON.stringify(patch) });
