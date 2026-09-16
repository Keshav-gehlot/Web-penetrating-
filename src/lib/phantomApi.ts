const API_BASE = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

export type Scan = {
  id: string;
  target: string;
  host: string;
  profile: string;
  modules: string[];
  status: string;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  error?: string | null;
};

export type FindingEvent = {
  id: string;
  module: string;
  title: string;
  severity: string;
  confidence: number;
};

export type ScanEvent =
  | { event: 'connected' | 'scan.created' | 'scan.started' | 'scan.completed'; scan_id: string }
  | { event: 'scan.failed'; scan_id: string; error: string }
  | { event: 'module.started' | 'module.completed'; scan_id: string; module: string; index: number; total: number; finding_count?: number }
  | { event: 'finding.created'; scan_id: string; finding: FindingEvent };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `PHANTOM API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function createScan(target: string, profile: 'quick' | 'standard' | 'deep' = 'standard') {
  return request<Scan>('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify({ target, profile }),
  });
}

export function getScan(scanId: string) {
  return request<Scan & { findings: FindingEvent[] }>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
}

export function scanSocket(scanId: string): WebSocket {
  const base = new URL(API_BASE);
  base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
  base.pathname = `/ws/scans/${encodeURIComponent(scanId)}`;
  base.search = '';
  return new WebSocket(base.toString());
}
