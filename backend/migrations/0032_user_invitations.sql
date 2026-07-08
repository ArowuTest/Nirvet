-- Temporary user invitation links (SRS §6.2 IAM-001/008). An admin invites a user by email +
-- role; a one-time, expiring token lets the invitee self-serve activation (set a password)
-- without the admin ever knowing it. Only sha256(token) is stored; the raw token is shown once.

CREATE TABLE IF NOT EXISTS user_invitations (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  email       text NOT NULL,
  role        text NOT NULL,                 -- never platform_admin; same domain as the inviter
  token_hash  text NOT NULL UNIQUE,          -- sha256(raw token), hex
  invited_by  text NOT NULL DEFAULT '',
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,                   -- set once; a second accept fails
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_invitations_tenant ON user_invitations (tenant_id, accepted_at);
ALTER TABLE user_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON user_invitations;
CREATE POLICY tenant_isolation ON user_invitations
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON user_invitations TO nirvet_app;

-- Pre-auth cross-tenant lookup by token hash (the acceptance request has no tenant context).
-- Mirrors auth_find_user_by_email / auth_find_api_key_by_prefix.
CREATE OR REPLACE FUNCTION auth_find_invitation_by_hash(p_hash text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, role text, expires_at timestamptz, accepted_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, role, expires_at, accepted_at
    FROM user_invitations WHERE token_hash = p_hash LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_invitation_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_invitation_by_hash(text) TO nirvet_app;
