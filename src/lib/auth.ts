export type Session = {
  access_token: string;
  token_type: string;
  actor: string;
  role: string;
  workspace_id: string;
  user_id?: string;
  expires_at?: number;
};

const KEY = 'phantom.session';
export const AUTH_EXPIRED_EVENT = 'phantom:auth-expired';

function isValidSession(value: unknown): value is Session {
  if (!value || typeof value !== 'object') return false;
  const s = value as Partial<Session>;
  return typeof s.access_token === 'string' &&
    s.access_token.length > 0 &&
    typeof s.token_type === 'string' &&
    typeof s.actor === 'string' &&
    typeof s.role === 'string' &&
    typeof s.workspace_id === 'string';
}

function tokenExpiry(token: string): number | undefined {
  const parts = token.split('|');
  if (parts.length !== 6) return undefined;
  const expiresAt = Number(parts[4]);
  return Number.isFinite(expiresAt) ? expiresAt : undefined;
}

export function getSession(): Session | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!isValidSession(parsed)) {
      clearSession(false);
      return null;
    }
    const session = parsed as Session;
    const expiresAt = session.expires_at ?? tokenExpiry(session.access_token);
    if (expiresAt !== undefined && expiresAt <= Math.floor(Date.now() / 1000)) {
      clearSession(false);
      return null;
    }
    if (expiresAt !== session.expires_at) {
      const normalized = { ...session, expires_at: expiresAt };
      localStorage.setItem(KEY, JSON.stringify(normalized));
      return normalized;
    }
    return session;
  } catch {
    clearSession(false);
    return null;
  }
}

export function setSession(session: Session) {
  if (!isValidSession(session)) throw new Error('Invalid authentication session.');
  const expiresAt = session.expires_at ?? tokenExpiry(session.access_token);
  localStorage.setItem(KEY, JSON.stringify({ ...session, expires_at: expiresAt }));
}

export function clearSession(notify = true) {
  localStorage.removeItem(KEY);
  if (notify && typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
  }
}

export async function login(email: string, password: string, workspace_id = 'default'): Promise<Session> {
  const { apiRequest } = await import('./api');
  const session = await apiRequest<Session>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password, workspace_id }),
  });
  if (!session?.access_token) throw new Error('Authentication response did not contain an access token.');
  setSession(session);
  return getSession()!;
}
