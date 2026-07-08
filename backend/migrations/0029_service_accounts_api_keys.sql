-- Service accounts + API keys (SRS §6.2: IAM-001 non-human principals, IAM-005 least-
-- privilege programmatic credentials + rotation, IAM-008 lifecycle). Enables connectors /
-- customer scripts to authenticate without a human password.
--
-- Only sha256(rawKey) + the public prefix are stored — the secret is shown once at creation
-- and is never retrievable. API keys are high-entropy random tokens, so a fast hash (sha256)
-- is the correct choice (unlike passwords, which use bcrypt).

CREATE TABLE IF NOT EXISTS service_accounts (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  name       text NOT NULL,
  role       text NOT NULL,          -- effective role; platform_admin is rejected at the service layer
  active     boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON service_accounts;
CREATE POLICY tenant_isolation ON service_accounts
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON service_accounts TO nirvet_app;

CREATE TABLE IF NOT EXISTS api_keys (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL DEFAULT app_current_tenant(),
  service_account_id uuid NOT NULL,
  prefix             text NOT NULL UNIQUE,   -- public, indexed lookup handle
  key_hash           text NOT NULL,          -- sha256(rawKey), hex
  label              text NOT NULL DEFAULT '',
  role               text NOT NULL,          -- denormalized from the service account for fast auth
  expires_at         timestamptz,            -- NULL = no expiry
  last_used_at       timestamptz,
  revoked_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS api_keys_tenant ON api_keys (tenant_id, service_account_id);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON api_keys;
CREATE POLICY tenant_isolation ON api_keys
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO nirvet_app;

-- Pre-auth cross-tenant lookup by prefix (the request has no tenant context yet). Mirrors
-- auth_find_user_by_email: the single controlled RLS hole for API-key authentication.
-- Returns minimal fields; the caller verifies the hash + revoked/expired status.
CREATE OR REPLACE FUNCTION auth_find_api_key_by_prefix(p_prefix text)
RETURNS TABLE (id uuid, tenant_id uuid, service_account_id uuid, key_hash text, role text,
               expires_at timestamptz, revoked_at timestamptz, sa_active boolean)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT k.id, k.tenant_id, k.service_account_id, k.key_hash, k.role,
         k.expires_at, k.revoked_at, s.active
    FROM api_keys k JOIN service_accounts s ON s.id = k.service_account_id
   WHERE k.prefix = p_prefix LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_api_key_by_prefix(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_api_key_by_prefix(text) TO nirvet_app;
