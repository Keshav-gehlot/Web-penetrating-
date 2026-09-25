export type Session = { access_token: string; refresh_token: string; token_type: string; actor: string; role: string; workspace_id: string; user_id?: string; expires_at?: string };
const KEY = 'phantom.session';
const API_BASE = (import.meta.env.VITE_PHANTOM_API_URL ?? (import.meta.env.PROD ? '' : 'http://localhost:8000')).replace(/\/$/, '');
export function getSession(): Session | null { try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { return null; } }
export function setSession(session: Session) { localStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(KEY); }
export async function login(email: string, password: string, workspace_id = 'default'): Promise<Session> {
  const r = await fetch(`${API_BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, workspace_id }) });
  if (!r.ok) throw new Error((await r.text()) || 'Authentication failed');
  const session = await r.json() as Session; setSession(session); return session;
}
export function authHeaders(): Record<string,string> { const s = getSession(); return s ? { Authorization: `Bearer ${s.access_token}` } : {}; }

export async function refreshSession(): Promise<Session | null> {
  const current=getSession(); if(!current?.refresh_token) return null;
  const r=await fetch(`${API_BASE}/api/v1/auth/refresh`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:current.refresh_token})});
  if(!r.ok){clearSession();return null;} const session=await r.json() as Session; setSession(session); return session;
}
export async function logout(): Promise<void> {
  const s=getSession(); try { if(s) await fetch(`${API_BASE}/api/v1/auth/logout`,{method:'POST',headers:authHeaders()}); } finally { clearSession(); }
}
