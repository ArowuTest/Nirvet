-- 0094_password_reset.sql — G1 admin-issued password reset (§6.2, Option 3). NO public forgot-password endpoint:
-- an authenticated admin issues a one-time, short-expiry token; the user consumes it to set a new password. Only
-- sha256(token) is stored; the raw token travels only in the emailed link (or a one-time, audited admin return).
-- Mirrors user_invitations (mig 0032) — the cleared token pattern.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  user_id     uuid NOT NULL,
  token_hash  text NOT NULL UNIQUE,          -- sha256(raw token), hex
  issued_by   uuid NOT NULL,                 -- the admin who issued it (accountability)
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,                   -- set once; a second confirm fails (one-time)
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user ON password_reset_tokens (tenant_id, user_id, used_at);
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON password_reset_tokens;
CREATE POLICY tenant_isolation ON password_reset_tokens
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON password_reset_tokens TO nirvet_app;

-- Pre-auth cross-tenant lookup by token hash (the confirm request has no tenant/session context). The token IS the
-- capability — there is NO lookup-by-email anywhere, so this flow has no user-enumeration oracle. Mirrors
-- auth_find_invitation_by_hash. REVOKE PUBLIC + GRANT nirvet_app (CI-guarded by check-security-definer-revoke.sh).
CREATE OR REPLACE FUNCTION auth_find_password_reset_by_hash(p_hash text)
RETURNS TABLE (id uuid, tenant_id uuid, user_id uuid, expires_at timestamptz, used_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, user_id, expires_at, used_at
    FROM password_reset_tokens WHERE token_hash = p_hash LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_password_reset_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_password_reset_by_hash(text) TO nirvet_app;
