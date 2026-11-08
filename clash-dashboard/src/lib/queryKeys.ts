import { getApiUrl, getSettingsRevision } from './settings';

const controller = (apiUrl?: string) => ['controller', apiUrl || getApiUrl(), getSettingsRevision()] as const;

export const queryKeys = {
  all: ['controller'] as const,
  version: (apiUrl?: string) => [...controller(apiUrl), 'version'] as const,
  capabilities: (apiUrl?: string) => [...controller(apiUrl), 'capabilities'] as const,
  configs: (apiUrl?: string) => [...controller(apiUrl), 'configs'] as const,
  memory: (apiUrl?: string) => [...controller(apiUrl), 'memory'] as const,
  proxies: (apiUrl?: string) => [...controller(apiUrl), 'proxies'] as const,
  proxyProviders: (apiUrl?: string) => [...controller(apiUrl), 'proxy-providers'] as const,
  ruleProviders: (apiUrl?: string) => [...controller(apiUrl), 'rule-providers'] as const,
  ruleProviderRules: (name: string, apiUrl?: string) =>
    [...controller(apiUrl), 'rule-provider-rules', name] as const,
  ruleProviderMatch: (name: string, target: string | null, apiUrl?: string) =>
    [...controller(apiUrl), 'rule-provider-match', name, target] as const,
  rules: (apiUrl?: string) => [...controller(apiUrl), 'rules'] as const,
  connections: (apiUrl?: string) => [...controller(apiUrl), 'connections'] as const,
  network: {
    status: (apiUrl?: string) => [...controller(apiUrl), 'network-status'] as const,
    paths: (apiUrl?: string) => [...controller(apiUrl), 'network-effective-paths'] as const,
    decisions: (apiUrl?: string) => [...controller(apiUrl), 'network-path-decisions'] as const,
    pathPreference: (apiUrl?: string) => [...controller(apiUrl), 'network-path-preference'] as const,
  },
};
