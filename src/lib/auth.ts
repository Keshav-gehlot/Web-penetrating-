export type Session = { access_token: string; token_type: string; actor: string; role: string; workspace_id: string };
const KEY = 'phantom.session';
export function getSession(): Session | null { try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { return null; } }
export function setSession(session: Session) { localStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(KEY); }
export async function login(email: string, password: string, workspace_id = 'default'): Promise<Session> {
  const base = (import.meta.env.VITE_PHANTOM_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');
  const r = await fetch(`${base}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, workspace_id }) });
  if (!r.ok) throw new Error((await r.text()) || 'Authentication failed');
  const session = await r.json() as Session; setSession(session); return session;
}
export function authHeaders(): Record<string,string> { const s = getSession(); return s ? { Authorization: `Bearer ${s.access_token}`, 'X-PHANTOM-Role': s.role, 'X-PHANTOM-Actor': s.actor } : {}; }
