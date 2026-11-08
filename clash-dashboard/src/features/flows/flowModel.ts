import type { DefaultLink, DefaultNode } from '@nivo/sankey';
import type { FlowRecord } from '@/hooks/useFlows';

// ─── Formatting ────────────────────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)}MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)}GB`;
}

export function formatRelative(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diffMs / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

export function countryFlag(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return '';
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(code.charCodeAt(0) + offset) +
         String.fromCodePoint(code.charCodeAt(1) + offset);
}

// ─── Protocol colours ───────────────────────────────────────────────────────────

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#0071e3',
  UDP: '#ff9500',
  QUIC: '#5ac8fa',
  HTTP: '#34c759',
  HTTPS: '#30d158',
};

export function protocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol.toUpperCase()] ?? '#8e8e93';
}

// ─── Sankey types ───────────────────────────────────────────────────────────────

export type FlowNode = DefaultNode;

export interface FlowLink extends DefaultLink {
  protocol: string;
  uploadTotal: number;
  downloadTotal: number;
  connCount: number;
  rule: string;
}

// ─── Sankey data builder ────────────────────────────────────────────────────────

interface SankeyData {
  nodes: FlowNode[];
  links: FlowLink[];
}

export function buildSankeyData(flows: FlowRecord[]): SankeyData {
  if (flows.length === 0) return { nodes: [], links: [] };

  const top15 = [...flows].sort((a, b) => b.bytesTotal - a.bytesTotal).slice(0, 15);

  const allSrcIps = new Set<string>();
  top15.forEach(f => f.srcIps.forEach(ip => allSrcIps.add(ip)));
  const groupSrcs = allSrcIps.size > 5;

  interface LinkAgg {
    bytes: number;
    upload: number;
    download: number;
    connCount: number;
    protocol: string;
    rule: string;
  }

  const linkAgg = new Map<string, Map<string, LinkAgg>>();

  for (const flow of top15) {
    const dstId = `dst:${flow.dstHost || `port-${flow.dstPort}`}`;
    const srcIps = flow.srcIps.length > 0 ? flow.srcIps : ['unknown'];
    const perIp = 1 / srcIps.length;

    for (const ip of srcIps) {
      const srcId = groupSrcs ? 'src:Local Network' : `src:${ip}`;
      if (!linkAgg.has(srcId)) linkAgg.set(srcId, new Map());
      const dstMap = linkAgg.get(srcId)!;
      const linkKey = `${dstId}|${flow.protocol.toUpperCase()}|${flow.dstPort}`;
      const existing = dstMap.get(linkKey);
      if (existing) {
        existing.bytes += flow.bytesTotal * perIp;
        existing.upload += flow.uploadTotal * perIp;
        existing.download += flow.downloadTotal * perIp;
        existing.connCount += flow.connCount * perIp;
      } else {
        dstMap.set(linkKey, {
          bytes: flow.bytesTotal * perIp,
          upload: flow.uploadTotal * perIp,
          download: flow.downloadTotal * perIp,
          connCount: flow.connCount * perIp,
          protocol: flow.protocol,
          rule: flow.rule,
        });
      }
    }
  }

  const nodeIds = new Set<string>();
  const links: FlowLink[] = [];

  for (const [srcId, dstMap] of linkAgg) {
    nodeIds.add(srcId);
    for (const [linkKey, agg] of dstMap) {
      const dstId = linkKey.split('|')[0];
      nodeIds.add(dstId);
      const color = protocolColor(agg.protocol);
      links.push({
        source: srcId,
        target: dstId,
        value: Math.max(1, Math.round(agg.bytes)),
        startColor: color,
        endColor: color,
        protocol: agg.protocol,
        uploadTotal: Math.round(agg.upload),
        downloadTotal: Math.round(agg.download),
        connCount: agg.connCount,
        rule: agg.rule,
      });
    }
  }

  const nodes: FlowNode[] = Array.from(nodeIds).map(id => ({ id }));
  return { nodes, links };
}
