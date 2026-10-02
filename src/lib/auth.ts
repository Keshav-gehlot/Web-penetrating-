export type Session = { access_token: string; refresh_token: string; token_type: string; actor: string; role: string; workspace_id: string; user_id?: string; expires_at?: string };
const KEY = 'phantom.session';
const API_BASE = (import.meta.env.VITE_PHANTOM_API_URL ?? (import.meta.env.PROD ? '' : 'http://localhost:8000')).replace(/\/$/, '');
function isCurrentAccessToken(token: unknown): token is string {
  if (typeof token !== 'string' || !token) return false;
  const parts = token.split('|');
  if (parts.length !== 7) return false;
  const expiry = Number(parts[4]);
  return Number.isSafeInteger(expiry) && expiry > Math.floor(Date.now() / 1000);
}
function isSession(value: unknown): value is Session {
  if (!value || typeof value !== 'object') return false;
  const session = value as Partial<Session>;
  return isCurrentAccessToken(session.access_token) &&
    typeof session.refresh_token === 'string' && session.refresh_token.length >= 20 &&
    session.token_type?.toLowerCase() === 'bearer' &&
    typeof session.actor === 'string' && session.actor.length > 0 &&
    typeof session.role === 'string' && session.role.length > 0 &&
    typeof session.workspace_id === 'string' && session.workspace_id.length > 0 &&
    typeof session.user_id === 'string' && session.user_id.length > 0;
}
export function getSession(): Session | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const value: unknown = JSON.parse(raw);
    if (!isSession(value)) {
      localStorage.removeItem(KEY);
      return null;
    }
    return value;
  } catch {
    localStorage.removeItem(KEY);
    return null;
  }
}
export function setSession(session: Session) { localStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(KEY); }
async function readApiPayload<T>(r: Response): Promise<T> {
  const payload = await r.json() as { data?: T; error?: { message?: string } };
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'data')) {
    if (payload.error) throw new Error(payload.error.message || 'API request failed');
    return payload.data as T;
  }
  return payload as T;
}
async function errorText(r:Response,fallback:string){
  try {
    const payload = await r.json() as { detail?: string; message?: string; error?: { message?: string } };
    return payload?.error?.message || payload?.detail || payload?.message || fallback;
  } catch { return (await r.text()) || fallback; }
}
export async function login(email: string, password: string, workspace_id = 'default'): Promise<Session> {
  clearSession();
  const r = await fetch(`${API_BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, workspace_id }) });
  if (!r.ok) throw new Error(await errorText(r,'Authentication failed'));
  const session = await readApiPayload<Session>(r);
  if (!isSession(session)) throw new Error('Authentication service returned an invalid session');
  setSession(session); return session;
}
export async function requestPasswordReset(email:string):Promise<{accepted:boolean;message:string;development_token?:string|null}>{
 const r=await fetch(`${API_BASE}/api/v1/auth/password/reset/request`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
 if(!r.ok)throw new Error(await errorText(r,'Unable to request password recovery'));
 return readApiPayload<{accepted:boolean;message:string;development_token?:string|null}>(r);
}
export async function confirmPasswordReset(token:string,new_password:string):Promise<{reset:boolean}>{
 const r=await fetch(`${API_BASE}/api/v1/auth/password/reset/confirm`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,new_password})});
 if(!r.ok)throw new Error(await errorText(r,'Unable to reset password'));
 return readApiPayload<{reset:boolean}>(r);
}
export function authHeaders(): Record<string,string> { const s = getSession(); return s ? { Authorization: `Bearer ${s.access_token}` } : {}; }

export async function refreshSession(): Promise<Session | null> {
  const current=getSession(); if(!current?.refresh_token) return null;
  const r=await fetch(`${API_BASE}/api/v1/auth/refresh`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:current.refresh_token})});
  if(!r.ok){clearSession();return null;} const session=await readApiPayload<Session>(r);
  if(!isSession(session)){clearSession();return null;}
  setSession(session); return session;
}
export async function logout(): Promise<void> {
  const s=getSession(); try { if(s) await fetch(`${API_BASE}/api/v1/auth/logout`,{method:'POST',headers:authHeaders()}); } finally { clearSession(); }
}
