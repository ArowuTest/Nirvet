// Nirvet API client — ADR-0007 browser session auth.
//
// The access JWT and refresh secret live in HttpOnly cookies the browser attaches automatically; JS never sees
// them (so XSS can't exfiltrate a token). Every request therefore sends `credentials: "include"` and NO
// Authorization header. On unsafe methods we echo the double-submit CSRF token — the one cookie that IS readable
// by JS — in the X-CSRF-Token header. A 401 on a normal request triggers a silent refresh (rotating the access
// cookie) and one retry.
//
// Refresh coordination is TWO layers, because a naive per-tab guard is not enough (reviewer MEDIUM): the refresh
// token is ONE-TIME-USE, so two tabs that both 401 and each POST /auth/refresh with the same pre-rotation cookie
// would collide — one rotates, the other trips the backend's reuse-detection and the whole family is revoked,
// logging BOTH tabs out. So:
//   1. within a tab, `refreshInFlight` coalesces concurrent 401s onto one call; and
//   2. across tabs, the Web Locks API serialises refreshes browser-wide, and a shared `localStorage` timestamp
//      lets a tab that wakes just after another tab refreshed skip its own call (the cookies are already fresh in
//      the shared jar). Serialisation guarantees each refresh presents the CURRENT token — never a stale one — so
//      legitimate multi-tab use never looks like theft. The backend stays strict; the fix is purely client-side.
// Where Web Locks is unavailable we degrade to per-tab single-flight (the pre-fix behaviour).

export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8081";

const CSRF_HEADER = "X-CSRF-Token";
// The CSRF cookie is `nirvet_csrf` in dev and `__Host-nirvet_csrf` in production (Secure). Read either.
const CSRF_COOKIE_NAMES = ["__Host-nirvet_csrf", "nirvet_csrf"];

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function readCookie(names: string[]): string {
  if (typeof document === "undefined") return "";
  const jar = document.cookie ? document.cookie.split("; ") : [];
  for (const name of names) {
    const hit = jar.find((c) => c.startsWith(name + "="));
    if (hit) return decodeURIComponent(hit.slice(name.length + 1));
  }
  return "";
}

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let code = "error";
  let message = res.statusText || `HTTP ${res.status}`;
  try {
    const body = await res.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
    }
  } catch {
    /* non-JSON body */
  }
  return new ApiError(res.status, code, message);
}

// isAuthEndpoint marks paths that must NOT trigger a silent refresh-on-401: login/refresh/logout own the session
// lifecycle themselves, and a 401 from them is a real answer (bad creds, mfa_required, no refresh cookie).
function isAuthEndpoint(path: string): boolean {
  return path.startsWith("/auth/");
}

// Cross-tab freshness hint: after any tab successfully refreshes, it stamps `now` here. A tab that acquires the
// refresh lock and sees a stamp newer than this window skips its own /auth/refresh — the shared cookie jar
// already holds the rotated access cookie. Purely an optimisation; correctness comes from the lock serialisation.
const LAST_REFRESH_KEY = "nirvet_last_refresh_ms";
const REFRESH_FRESH_MS = 5_000;

function refreshedRecently(): boolean {
  try {
    const t = Number(window.localStorage.getItem(LAST_REFRESH_KEY) || 0);
    return t > 0 && Date.now() - t < REFRESH_FRESH_MS;
  } catch {
    return false;
  }
}
function markRefreshed(): void {
  try {
    window.localStorage.setItem(LAST_REFRESH_KEY, String(Date.now()));
  } catch {
    /* storage disabled — the lock alone still serialises correctly */
  }
}

// refreshOnce performs the actual rotation. It must run under the cross-tab lock (or the per-tab degrade path).
async function refreshOnce(): Promise<boolean> {
  // Another tab refreshed a moment ago → our cookies are already fresh; don't rotate again.
  if (refreshedRecently()) return true;
  try {
    // /auth/refresh is a cookie-authenticated POST, so it is CSRF-protected like any other write — echo the
    // double-submit token. (Missing this → 403 and a spurious logout.)
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const csrf = readCookie(CSRF_COOKIE_NAMES);
    if (csrf) headers[CSRF_HEADER] = csrf;
    const res = await fetch(`${API_BASE}/auth/refresh`, { method: "POST", credentials: "include", headers });
    if (res.ok) markRefreshed();
    return res.ok;
  } catch {
    return false;
  }
}

// Within-tab single-flight: concurrent 401s in THIS tab await one shared promise.
let refreshInFlight: Promise<boolean> | null = null;

// hasWebLocks narrows navigator.locks without pulling in a hard type dependency on the (recent) lib.dom entry.
function hasWebLocks(): boolean {
  return typeof navigator !== "undefined" && typeof (navigator as Navigator).locks?.request === "function";
}

function doRefresh(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        // Cross-tab serialisation: only one tab in the whole browser refreshes at a time; the rest queue on the
        // lock and then short-circuit via refreshedRecently(). This is what prevents two tabs presenting the same
        // one-time refresh token and tripping backend reuse-detection (→ family revoke → both tabs logged out).
        if (hasWebLocks()) {
          return await navigator.locks.request("nirvet-refresh", () => refreshOnce());
        }
        return await refreshOnce(); // no Web Locks → per-tab single-flight (pre-fix behaviour)
      } finally {
        // Clear AFTER settling so late arrivals during this tick still share it, but the next 401 re-refreshes.
        setTimeout(() => {
          refreshInFlight = null;
        }, 0);
      }
    })();
  }
  return refreshInFlight;
}

interface RequestOpts {
  method?: string;
  body?: unknown;
  /** internal: prevents infinite refresh recursion */
  _retried?: boolean;
}

async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const method = (opts.method || "GET").toUpperCase();
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE.has(method)) {
    const csrf = readCookie(CSRF_COOKIE_NAMES);
    if (csrf) headers[CSRF_HEADER] = csrf;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    credentials: "include",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  // Silent refresh + one retry on an expired access cookie (never for the auth endpoints themselves).
  if (res.status === 401 && !opts._retried && !isAuthEndpoint(path)) {
    if (await doRefresh()) {
      return request<T>(path, { ...opts, _retried: true });
    }
  }

  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export function apiGet<T = unknown>(path: string): Promise<T> {
  return request<T>(path, { method: "GET" });
}

export function apiPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body });
}

export function apiPut<T = unknown>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: "PUT", body });
}

export function apiDelete<T = unknown>(path: string): Promise<T> {
  return request<T>(path, { method: "DELETE" });
}

// --- Session lifecycle ---

export interface Me {
  id: string;
  email: string;
  role: string;
  tenant_id: string;
  mfa_enabled?: boolean;
}

export type LoginResult = { ok: true } | { mfaRequired: true };

/**
 * login posts credentials; the server sets the session cookies on success. If the account has MFA enabled and no
 * code was supplied, the server answers 401 `mfa_required` — surfaced here as { mfaRequired: true } so the UI can
 * show the TOTP step. Bad credentials throw an ApiError (401 unauthorized).
 */
export async function login(email: string, password: string, mfaCode?: string): Promise<LoginResult> {
  try {
    await request("/auth/login", {
      method: "POST",
      body: { email, password, ...(mfaCode ? { mfa_code: mfaCode } : {}) },
    });
    return { ok: true };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && e.code === "mfa_required") {
      return { mfaRequired: true };
    }
    throw e;
  }
}

export function getMe(): Promise<Me> {
  return apiGet<Me>("/me");
}

/** logout revokes THIS session's refresh token and clears cookies. */
export function logout(): Promise<void> {
  return apiPost<void>("/auth/logout");
}

/** logoutAll ends every session on every device (bumps the user's session generation) + clears cookies. */
export function logoutAll(): Promise<void> {
  return apiPost<void>("/auth/logout-all");
}

// SSO / SAML are top-level browser navigations (the IdP round-trip needs the address bar), not fetches.
export function ssoStartUrl(): string {
  return `${API_BASE}/auth/sso/start`;
}
export function samlStartUrl(): string {
  return `${API_BASE}/auth/sso/saml/start`;
}
