import { request } from './client';
import type { DNSQueryResult } from './types';

// DNS
export const queryDNS = (name: string, type: string) =>
  request<DNSQueryResult>(`/dns/query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`);
