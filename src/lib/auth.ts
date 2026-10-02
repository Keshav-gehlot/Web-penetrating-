export type Session = { access_token: string; token_type: string; actor: string; role: string; workspace_id: string; user_id?: string };
const KEY = 'phantom.session';

export function getSession(): Session | null {
  try { return JSON.parse(localStorage.getItem(KEY) || 'null') as Session | null; } catch { return null; }
}
export function setSession(session: Session) { localStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(KEY); }

export async function login(email: string, password: string, workspace_id = 'default'): Promise<Session> {
  const { apiRequest } = await import('./api');
  const session = await apiRequest<Session>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password, workspace_id }),
  });
  if (!session?.access_token) throw new Error('Authentication response did not contain an access token.');
  setSession(session);
  return session;
}

export function authHeaders(): Record<string,string> {
  const s = getSession();
  return s?.access_token ? { Authorization: `Bearer ${s.access_token}` } : {};
}
