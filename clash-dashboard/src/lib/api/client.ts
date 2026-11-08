import { getApiUrl, getSecret } from '../settings';

// HTTP client
export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const baseUrl = getApiUrl();
  const secret = getSecret();
  const url = `${baseUrl}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  if (secret) {
    headers['Authorization'] = `Bearer ${secret}`;
  }

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    // Try to extract a message from the response body (plain text or JSON)
    let message = `${response.status} ${response.statusText}`;
    try {
      const ct = response.headers.get('content-type') ?? '';
      if (ct.includes('application/json')) {
        const body = await response.json() as { message?: string };
        if (body.message) message = body.message;
      } else {
        const text = await response.text();
        if (text.trim()) message = text.trim();
      }
    } catch { /* ignore */ }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get('content-type') ?? '';
  const raw = await response.text();
  if (!raw.trim() || !contentType.includes('application/json')) {
    return undefined as T;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`Invalid JSON response from ${path}`);
  }
}

// WebSocket URL helper
export function getWsUrl(path: string): string {
  const baseUrl = getApiUrl();
  const secret = getSecret();
  const wsBase = baseUrl.replace(/^http/, 'ws');
  const url = new URL(`${wsBase}${path}`);
  if (secret) {
    url.searchParams.set('token', secret);
  }
  return url.toString();
}
