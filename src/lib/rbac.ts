import { authHeaders, getSession } from './auth';

export type Role = 'owner' | 'admin' | 'security_lead' | 'analyst' | 'developer' | 'viewer';

export type Permission =
  | 'workspace:manage'
  | 'scope:approve'
  | 'users:manage'
  | 'scan:create'
  | 'scan:view'
  | 'scan:cancel'
  | 'finding:view'
  | 'finding:edit'
  | 'finding:assign'
  | 'finding:close'
  | 'report:create'
  | 'report:export'
  | 'audit:view';

export type RBACProfile = {
  user_id: string;
  actor: string;
  role: Role;
  workspace_id: string;
  permissions: Permission[];
  permission_matrix: Record<Role, Permission[]>;
  all_permissions: Permission[];
};

const API = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');

let cached: RBACProfile | null = null;

export async function loadRBAC(): Promise<RBACProfile | null> {
  const session = getSession();
  if (!session) {
    cached = null;
    return null;
  }
  try {
    const response = await fetch(`${API}/api/v1/auth/me`, { headers: authHeaders() });
    if (!response.ok) {
      if (response.status === 401) cached = null;
      return cached;
    }
    cached = await response.json() as RBACProfile;
    return cached;
  } catch {
    return cached;
  }
}

export function getRBAC(): RBACProfile | null {
  return cached;
}

export function hasPermission(permission: Permission): boolean {
  const profile = cached;
  return Boolean(profile && (profile.permissions.includes(permission) || profile.role === 'owner'));
}

export function canManageTeam(): boolean {
  return hasPermission('users:manage');
}

export function canManageRole(targetRole: Role): boolean {
  const profile = cached;
  if (!profile) return false;
  if (profile.role === 'owner') return true;
  const levels: Record<Role, number> = {
    owner: 6, admin: 5, security_lead: 4, analyst: 3, developer: 2, viewer: 1,
  };
  return levels[targetRole] <= levels[profile.role];
}

export function canAccessPath(path: string): boolean {
  const permissionByPath: Array<[string, Permission]> = [
    ['/scope', 'workspace:manage'],
    ['/scans', 'scan:view'],
    ['/schedules', 'scan:create'],
    ['/assets', 'scan:view'],
    ['/topology', 'scan:view'],
    ['/vulnerabilities', 'finding:view'],
    ['/investigation', 'finding:view'],
    ['/reports', 'report:export'],
    ['/audit', 'audit:view'],
    ['/team', 'users:manage'],
  ];
  const match = permissionByPath.find(([prefix]) => path === prefix || path.startsWith(`${prefix}/`));
  return match ? hasPermission(match[1]) : true;
}
