# ADR-0007 — Browser session auth: httpOnly cookies + rotating refresh + CSRF

**Status:** Accepted (owner go-ahead + reviewer-endorsed design, Jul 2026; reviewer landing pass pending)
**Stack:** Go · stateless HS256 access JWT (ADR-carried) · opaque server-side refresh tokens · Postgres

## Context

The MVP scaffold stored the access JWT in browser **localStorage** and sent it as `Authorization: Bearer`.
That is XSS-exfiltratable (any injected script can read localStorage) and has no refresh story — a short access
TTL forces re-login, a long one widens the theft window. The external reviewer named "production session auth
(httpOnly/refresh + MFA/SSO screens)" a launch-blocking P0. MFA is already challenged at `/auth/login` (TOTP),
and per-user/per-tenant **session-generation revocation** already exists (ADR-carried, `iam.MintSession`).

## Decision

**Browser sessions use httpOnly cookies with a rotating, server-side refresh token; the access token stays the
existing stateless JWT. Non-browser clients (API keys, CLI) keep the `Authorization: Bearer` path unchanged.**

1. **Access token** — the SAME stateless HS256 JWT as today, now ALSO delivered as an `HttpOnly`, `Secure`
   (production), `SameSite=Lax`, host-only cookie `nirvet_access` with a SHORT TTL (the tenant session TTL,
   capped). JS can never read it. The auth middleware accepts the token from the cookie OR the `Authorization`
   header — so API-key/CLI/programmatic callers and the existing tests are unaffected (dual delivery).
2. **Refresh token** — a new **opaque, high-entropy (256-bit)** secret, **stored only as a SHA-256 hash** in a
   new `refresh_tokens` table, delivered as an `HttpOnly`/`Secure`/`SameSite=Lax` cookie `nirvet_refresh`
   **path-scoped to `/auth/refresh`** (never sent to normal API routes). Long TTL (e.g. 30d, tenant-configurable
   later). `POST /auth/refresh` validates the presented token, **rotates it one-time** (marks the old row used,
   issues a new refresh + new access cookie), and mints the access JWT through the SAME `MintSession` chokepoint
   so the current session generation is stamped in. **Reuse detection:** presenting an already-used (rotated)
   refresh token is treated as theft — the whole token family/chain is revoked. Refresh rows also carry the
   user's session generation, so a password change / offboard (generation bump) invalidates every refresh.
3. **Logout** — `POST /auth/logout` clears both cookies and revokes the presented refresh token (marks it used).
   (Full-device sign-out = the existing generation bump; per-session logout just kills this chain.)
4. **CSRF** — cookie auth reintroduces CSRF that the header scheme was immune to. Defense-in-depth:
   (a) `SameSite=Lax` on both cookies (blocks cross-site POST cookie attachment), PLUS (b) a **double-submit CSRF
   token**: a NON-httpOnly cookie `nirvet_csrf` (readable by our JS) whose value must be echoed in an
   `X-CSRF-Token` header on every unsafe method (POST/PUT/DELETE/PATCH) of a COOKIE-authenticated request. A
   cross-site attacker can neither read the cookie value nor set a custom header, so the check fails closed.
   Header/Bearer-authenticated requests (no cookie) skip CSRF — they were never CSRF-exposed.
5. **CORS** — the SPA is a separate origin, so the API returns `Access-Control-Allow-Credentials: true` and an
   explicit (non-`*`) `Access-Control-Allow-Origin` echoing the configured `NIRVET_CORS_ORIGIN`; the SPA fetches
   with `credentials: "include"`.

## Consequences

**Positive:** the access token is no longer reachable by XSS; refresh rotation bounds a stolen refresh token to a
single use and detects reuse; revocation composes with the existing session-generation kill-switch; non-browser
clients are unaffected; MFA/SSO already exist server-side and only need screens. Accreditation-relevant controls
(session fixation resistance via rotation, CSRF, SameSite, httpOnly) are all present.

**Negative / risks:** cookie auth requires correct `Secure`/`SameSite`/CORS-credentials wiring (a
misconfiguration is a real exposure — covered by tests + the reviewer's landing pass); the double-submit token
adds a header requirement the SPA client must always send on writes (centralised in `lib/api.ts`); refresh
rotation needs a race-safe redeem (a single-statement conditional UPDATE marks-and-returns so two concurrent
refreshes can't both succeed). Refresh storage is Postgres now; a Redis fast-path is a later scale option.

## Frontend

`lib/api.ts` drops localStorage, adds `credentials:"include"` + the `X-CSRF-Token` header on writes, and a silent
`/auth/refresh` retry on a 401. The login screen gains an MFA-TOTP step and SSO (OIDC/SAML) buttons; the route
guard becomes a `/auth/me` probe (or `middleware.ts` cookie-presence check) since JS can no longer read the token.
**All screens reuse the existing design system (dark slate theme) and the existing designs — no new visual
language.**

## References

Builds on the stateless-JWT + session-generation revocation (ADR-carried), MFA (TOTP), and SSO (OIDC + SAML)
already implemented. Related: [ADR-0001](0001-multi-tenancy.md) (tenant scoping), ADR-0004 (credential vault).
