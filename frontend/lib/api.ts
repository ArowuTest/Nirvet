// Thin client for the Nirvet backend API. Token is kept in localStorage for the
// scaffold; production should use an httpOnly cookie set by the backend.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8081";

const TOKEN_KEY = "nirvet_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(t: string) {
  window.localStorage.setItem(TOKEN_KEY, t);
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

function authHeaders(): HeadersInit {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function apiGet<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

export async function apiPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`POST ${path} failed: ${res.status}`);
  return res.json();
}

export async function login(email: string, password: string): Promise<void> {
  const res = await apiPost<{ token: string }>("/auth/login", { email, password });
  setToken(res.token);
}
