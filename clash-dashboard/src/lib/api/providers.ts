import { request } from './client';
import type { ProxyProvider, RuleProvider } from './types';

// Providers
export const getProxyProviders = () =>
  request<{ providers: Record<string, ProxyProvider> }>('/providers/proxies');
export const updateProxyProvider = (name: string) =>
  request<void>(`/providers/proxies/${encodeURIComponent(name)}`, { method: 'PUT' });
export const healthcheckProvider = (name: string) =>
  request<void>(`/providers/proxies/${encodeURIComponent(name)}/healthcheck`);
export const getProviderProxyDelay = (providerName: string, proxyName: string, url: string, timeout: number) =>
  request<{ delay: number; overall: number }>(
    `/providers/proxies/${encodeURIComponent(providerName)}/${encodeURIComponent(proxyName)}/healthcheck?url=${encodeURIComponent(url)}&timeout=${timeout}`
  );

// Rule Providers
export const getRuleProviders = () =>
  request<{ providers: Record<string, RuleProvider> }>('/providers/rules');
export const updateRuleProvider = (name: string) =>
  request<void>(`/providers/rules/${encodeURIComponent(name)}`, { method: 'PUT' });
export const getRuleProviderRules = (name: string) =>
  request<{ rules: string[] }>(`/providers/rules/${encodeURIComponent(name)}/rules`);
export const matchRuleProvider = (name: string, target: string) =>
  request<{ match: boolean; rule?: string }>(`/providers/rules/${encodeURIComponent(name)}/match?target=${encodeURIComponent(target)}`);
