export interface InboundEndpoint {
  name: string;
  type: string;
  port: number;
  active: boolean;
}
export interface DnsListenInfo {
  udp?: string;
  tcp?: string;
  doh?: string;
  dot?: string;
  doh3?: string;
}
export interface ClashConfig {
  port?: number;
  'socks-port'?: number;
  'redir-port'?: number;
  'tproxy-port'?: number;
  'mixed-port'?: number;
  'bind-address'?: string;
  mode?: string;
  'log-level'?: string;
  ipv6?: boolean;
  'allow-lan'?: boolean;
  listeners?: InboundEndpoint[];
  'lan-ips'?: string[];
  'dns-listen'?: DnsListenInfo;
}

/** Fields that can be patched via PATCH /configs */
export type PatchableConfig = Omit<ClashConfig, 'listeners' | 'lan-ips' | 'dns-listen'>;
