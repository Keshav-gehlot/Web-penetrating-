const configuredBase = (import.meta.env.VITE_PHANTOM_API_URL ?? '').trim().replace(/\/$/, '');
const API_BASE = configuredBase || (import.meta.env.DEV ? 'http://localhost:8000' : '');

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(message: string, status: number, code = 'API_ERROR', requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

type ApiEnvelope<T> = {
  data: T;
  error: null | { code?: string; message?: string; details?: unknown };
  request_id?: string;
};

function buildUrl(path: string): string {
  if (!API_BASE && path.startsWith('/api/')) {
    throw new ApiError('PHANTOM API URL is not configured for this production build.', 0, 'API_URL_NOT_CONFIGURED');
  }
  return `${API_BASE}${path}`;
}

async function parseError(response: Response): Promise<never> {
  const text = await response.text();
  let payload: Partial<ApiEnvelope<never>> | null = null;
  try { payload = text ? JSON.parse(text) : null; } catch { /* non-JSON error */ }

  const error = payload?.error;
  const message = error?.message || text || `PHANTOM API request failed (${response.status})`;
  throw new ApiError(message, response.status, error?.code || 'HTTP_ERROR', payload?.request_id);
}

async function parseEnvelope<T>(response: Response): Promise<T> {
  if (!response.ok) return parseError(response);

  const text = await response.text();
  if (!text) return undefined as T;

  let payload: unknown;
  try { payload = JSON.parse(text); } catch {
    throw new ApiError('PHANTOM API returned invalid JSON.', response.status, 'INVALID_JSON');
  }

  if (payload && typeof payload === 'object' && 'data' in payload && 'error' in payload) {
    const envelope = payload as ApiEnvelope<T>;
    if (envelope.error) {
      throw new ApiError(
        envelope.error.message || 'PHANTOM API request failed.',
        response.status,
        envelope.error.code || 'API_ERROR',
        envelope.request_id,
      );
    }
    return envelope.data;
  }

  return payload as T;
}

function readAccessToken(): string | undefined {
  try {
    const raw = localStorage.getItem('phantom.session');
    if (!raw) return undefined;
    const session = JSON.parse(raw) as { access_token?: unknown };
    return typeof session.access_token === 'string' && session.access_token ? session.access_token : undefined;
  } catch {
    return undefined;
  }
}

function handleAuthenticationFailure(error: ApiError) {
  if (error.status !== 401) return;
  localStorage.removeItem('phantom.session');
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('phantom:auth-expired'));
  }
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const token = readAccessToken();
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(buildUrl(path), { ...init, headers });
  try {
    return await parseEnvelope<T>(response);
  } catch (error) {
    if (error instanceof ApiError) handleAuthenticationFailure(error);
    throw error;
  }
}

export async function apiBlob(path: string, init: RequestInit = {}): Promise<Blob> {
  const headers = new Headers(init.headers);
  const token = readAccessToken();
  if (token && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(buildUrl(path), { ...init, headers });
  try {
    if (!response.ok) return parseError(response);
    return response.blob();
  } catch (error) {
    if (error instanceof ApiError) handleAuthenticationFailure(error);
    throw error;
  }
}

export function apiUrl(path: string): string {
  return buildUrl(path);
}
