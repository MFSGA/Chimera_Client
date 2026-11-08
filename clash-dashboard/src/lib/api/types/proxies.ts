export interface Proxy {
  name: string;
  type: string;
  udp: boolean;
  history: Array<{ time: string; delay: number }>;
  all?: string[];
  now?: string;
  alive?: boolean;
  extra?: Record<string, unknown>;
}
