import { authHeaders } from './auth';

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

async function request(path: string, init?: RequestInit) {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: { ...authHeaders(), ...(init?.headers ?? {}) },
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

export type WorkspaceScope = {
  id: string | null;
  workspace_id: string | null;
  configured: boolean;
  enabled: boolean;
  authorized_targets: string[];
  excluded_targets: string[];
  allowed_ports: number[];
  allowed_paths: string[];
  blocked_paths: string[];
  max_requests: number;
  max_concurrency: number;
  max_redirects: number;
  authorization_acknowledged: boolean;
  authorization_acknowledged_at: string | null;
  acknowledged_by: string | null;
  approval_status: "pending" | "approved" | "rejected";
  approved_at: string | null;
  approved_by: string | null;
  approval_comment: string | null;
  created_at: string | null;
  updated_at: string | null;
  effective_limits: { max_requests: number; max_concurrency: number; max_redirects: number };
};

export async function getScope(): Promise<WorkspaceScope> {
  return request('/api/v1/scope');
}

export async function saveScope(payload: Omit<WorkspaceScope, 'id' | 'workspace_id' | 'configured' | 'authorization_acknowledged_at' | 'acknowledged_by' | 'created_at' | 'updated_at' | 'effective_limits'>): Promise<WorkspaceScope> {
  return request('/api/v1/scope', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function checkScopeTarget(target: string): Promise<{ allowed: boolean; target?: string; host?: string; port?: number; reason?: string }> {
  const query = new URLSearchParams({ target });
  return request(`/api/v1/scope/check?${query.toString()}`, { method: 'POST' });
}


export async function approveScope(comment?: string): Promise<WorkspaceScope> {
  const query = comment?.trim() ? `?comment=${encodeURIComponent(comment.trim())}` : '';
  return request(`/api/v1/scope/approve${query}`, { method: 'POST' });
}

export async function rejectScope(comment?: string): Promise<WorkspaceScope> {
  const query = comment?.trim() ? `?comment=${encodeURIComponent(comment.trim())}` : '';
  return request(`/api/v1/scope/reject${query}`, { method: 'POST' });
}
