import type { Proxy } from './proxies';

export interface ProxyProvider {
  name: string;
  type: string;
  vehicleType: string;
  updatedAt?: string;
  subscriptionInfo?: Record<string, unknown>;
  proxies: Proxy[];
}
