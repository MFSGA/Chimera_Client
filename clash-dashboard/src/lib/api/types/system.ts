export interface Version {
  version: string;
  meta: boolean;
}
export interface Capabilities {
  platform: {
    os: string;
    architecture: string;
  };
  outboundProtocols: string[];
  features: string[];
}
export interface MemoryData {
  inuse: number;
  oslimit: number;
}
