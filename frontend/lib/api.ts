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

// Cross-site CSRF: in production the SPA and API are on different registrable domains, so the __Host- CSRF cookie
// the API sets is NOT readable by the SPA (document.cookie is per-origin). Double-submit still works — the cookie
// is sent to the API automatically — but the SPA must obtain the token VALUE to echo in X-CSRF-Token. It fetches
// that value from GET /auth/csrf and holds it in memory. On same-site dev the cookie IS readable, so we prefer
// that (no round-trip). Without this, every write 403s with "CSRF token missing or invalid".
let csrfToken = "";
async function ensureCsrf(): Promise<string> {
  const fromCookie = readCookie(CSRF_COOKIE_NAMES);
  if (fromCookie) return fromCookie; // same-site (dev): cookie readable directly
  if (csrfToken) return csrfToken;
  try {
    const res = await fetch(`${API_BASE}/auth/csrf`, { credentials: "include" });
    if (res.ok) {
      const j = await res.json();
      csrfToken = j?.csrf_token || "";
    }
  } catch {
    /* offline or not yet authenticated — the next write after login will retry */
  }
  return csrfToken;
}

/** resetCsrf drops the cached token so the next write re-fetches it (call after login/logout — the cookie rotates). */
export function resetCsrf(): void {
  csrfToken = "";
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

// preAuthWrite marks the writes that run BEFORE a session exists, so they carry no auth cookie and the backend
// does not require CSRF on them. Every other write (incl. logout / logout-all, which ARE cookie-authed) needs the
// double-submit token. Fetching a token for these pre-auth writes would just 401 on GET /auth/csrf, so we skip it.
function preAuthWrite(path: string): boolean {
  return path === "/auth/login" || path === "/auth/invitations/accept" || path === "/auth/password-reset/confirm";
}

// Cross-tab freshness hint: after any tab successfully refreshes, it stamps `now` here. A tab that acquires the
// refresh lock and sees a stamp newer than this window skips its own /auth/refresh — the shared cookie jar
// already holds the rotated access cookie. Purely an optimisation; correctness comes from the lock serialisation.
const LAST_REFRESH_KEY = "nirvet_last_refresh_ms";
const REFRESH_FRESH_MS = 5_000;
// Hard bound on the /auth/refresh request. The cross-tab Web Lock is held for the duration of this fetch, so a
// HUNG (not errored) server must not pin the lock until the browser's TCP timeout — that would block every tab's
// refresh. On abort the fetch rejects → we fail closed and the lock releases promptly.
const REFRESH_TIMEOUT_MS = 10_000;

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
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REFRESH_TIMEOUT_MS);
  try {
    // /auth/refresh is a cookie-authenticated POST, so it is CSRF-protected like any other write — echo the
    // double-submit token. Cross-site the SPA can't read the cookie, so obtain the value via ensureCsrf().
    // (Missing this → 403 and a spurious logout.)
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const csrf = await ensureCsrf();
    if (csrf) headers[CSRF_HEADER] = csrf;
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers,
      signal: ctl.signal,
    });
    if (res.ok) markRefreshed();
    return res.ok;
  } catch {
    return false; // network error OR abort (timeout) → fail closed; caller clears the session
  } finally {
    clearTimeout(timer);
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
  /** internal: prevents infinite CSRF-refetch recursion */
  _csrfRetried?: boolean;
}

async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const method = (opts.method || "GET").toUpperCase();
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE.has(method) && !preAuthWrite(path)) {
    const csrf = await ensureCsrf();
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

  // A 403 on a write may be a stale/rotated CSRF token (or a first write before the token was fetched): drop the
  // cached value, re-fetch it, and retry once. A genuine role/permission 403 simply 403s again on the retry.
  if (res.status === 403 && UNSAFE.has(method) && !opts._csrfRetried && !isAuthEndpoint(path)) {
    resetCsrf();
    if (await ensureCsrf()) {
      return request<T>(path, { ...opts, _csrfRetried: true });
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

// apiGetCached dedupes a GET across near-simultaneous callers: it shares the in-flight promise and briefly caches
// the resolved value (default 10s TTL) keyed by path. Used for hot, cheap read endpoints fetched by both the shell
// and a page on the same render (e.g. /reports/summary → nav badges + dashboard KPIs) so they hit the API once.
// A rejection is never cached. Callers wanting a forced refresh can pass ttlMs=0.
const _getCache = new Map<string, { at: number; p: Promise<unknown> }>();
export function apiGetCached<T = unknown>(path: string, ttlMs = 10000): Promise<T> {
  const now = Date.now();
  const hit = _getCache.get(path);
  if (hit && now - hit.at < ttlMs) return hit.p as Promise<T>;
  const p = request<T>(path, { method: "GET" });
  _getCache.set(path, { at: now, p });
  p.catch(() => { if (_getCache.get(path)?.p === p) _getCache.delete(path); }); // never cache a failure
  return p;
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
    // Login rotated the CSRF cookie — drop any stale in-memory token and prime a fresh one so the first write works.
    resetCsrf();
    await ensureCsrf();
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
export async function logout(): Promise<void> {
  try {
    await apiPost<void>("/auth/logout");
  } finally {
    resetCsrf();
  }
}

/** logoutAll ends every session on every device (bumps the user's session generation) + clears cookies. */
export async function logoutAll(): Promise<void> {
  try {
    await apiPost<void>("/auth/logout-all");
  } finally {
    resetCsrf();
  }
}

// SSO / SAML are top-level browser navigations (the IdP round-trip needs the address bar), not fetches.
export function ssoStartUrl(): string {
  return `${API_BASE}/auth/sso/start`;
}
export function samlStartUrl(): string {
  return `${API_BASE}/auth/sso/saml/start`;
}
