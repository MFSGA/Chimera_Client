export interface DNSQueryResult {
  Answer?: Array<{
    TTL: number;
    data: string;
    name: string;
    type: number;
  }>;
  Authority?: Array<{
    TTL: number;
    data: string;
    name: string;
    type: number;
  }>;
  Additional?: Array<{
    TTL: number;
    data: string;
    name: string;
    type: number;
  }>;
  Question: Array<{ name: string; qtype: number; qclass: number }>;
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
}
