-- 0104_refresh_tokens.sql — ADR-0007 browser session auth: rotating, server-side refresh tokens.
-- Only sha256(raw) is stored; the raw secret lives only in the httpOnly `nirvet_refresh` cookie. Each token is
-- ONE-TIME-USE: /auth/refresh marks it used and issues a successor in the SAME family. Presenting an already-used
-- token = theft → the whole family is revoked (reuse detection). Rows also carry the user/tenant session
-- generation at issue, so a password change / offboard (generation bump) invalidates every refresh on next use.
-- Mirrors the password_reset_tokens pre-auth pattern (mig 0094): RLS table + SECURITY DEFINER hash lookup.

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  user_id     uuid NOT NULL,
  token_hash  text NOT NULL UNIQUE,            -- sha256(raw), hex
  family_id   uuid NOT NULL,                   -- rotation chain; reuse of a used token revokes the whole family
  user_gen    bigint NOT NULL,                 -- user session generation at issue (bump invalidates)
  tenant_gen  bigint NOT NULL,                 -- tenant session generation at issue (offboard invalidates)
  used_at     timestamptz,                     -- set on rotation; non-null = already rotated (one-time-use)
  revoked_at  timestamptz,                     -- family revocation (theft/logout)
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user   ON refresh_tokens (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens (family_id);
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON refresh_tokens;
CREATE POLICY tenant_isolation ON refresh_tokens
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO nirvet_app;

-- Pre-auth cross-tenant lookup by token hash: the /auth/refresh request carries only the cookie, no tenant/session
-- context. The token IS the capability. Mirrors auth_find_password_reset_by_hash. REVOKE PUBLIC + GRANT nirvet_app
-- (CI-guarded by check-security-definer-revoke.sh).
CREATE OR REPLACE FUNCTION auth_find_refresh_by_hash(p_hash text)
RETURNS TABLE (id uuid, tenant_id uuid, user_id uuid, family_id uuid, user_gen bigint, tenant_gen bigint,
               used_at timestamptz, revoked_at timestamptz, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, user_id, family_id, user_gen, tenant_gen, used_at, revoked_at, expires_at
    FROM refresh_tokens WHERE token_hash = p_hash LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_refresh_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_refresh_by_hash(text) TO nirvet_app;
