export interface Connection {
  id: string;
  metadata: {
    network: string;
    type: string;
    host: string;
    sourceIP: string;
    sourcePort: number;
    destinationPort: number;
    destinationIP?: string;
    inboundIP?: string;
    inboundPort?: string;
    inboundName?: string;
    inboundUser?: string;
    process?: string;
    processPath?: string;
    remoteDestination?: string;
    sniffHost?: string;
    asn?: string;
  };
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rulePayload: string;
}
export interface ConnectionsData {
  connections: Connection[];
  downloadTotal: number;
  uploadTotal: number;
  memory?: number;
}
