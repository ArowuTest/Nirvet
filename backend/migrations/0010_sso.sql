-- SSO (OIDC) — per-tenant IdP connections (SRS §6.2 IAM-001). The client secret is
-- vault-encrypted (bytea, ADR-0004). Tenant-scoped under RLS like every other
-- tenant-owned table; the unauthenticated OIDC callback resolves a connection via
-- a SECURITY DEFINER function (the controlled cross-tenant hole, mirroring the
-- connector poller lookup).

CREATE TABLE IF NOT EXISTS sso_connections (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL DEFAULT app_current_tenant(),
  protocol         text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc')),
  issuer           text NOT NULL,               -- OIDC issuer (used for discovery)
  client_id        text NOT NULL,
  client_secret    bytea NOT NULL,              -- vault-sealed (tenant AAD)
  redirect_uri     text NOT NULL,
  default_role     text NOT NULL DEFAULT 'customer_viewer',
  email_domain     text NOT NULL DEFAULT '',    -- allowlist; '' = any (discouraged)
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sso_connections_tenant ON sso_connections (tenant_id);
-- One enabled OIDC connection per (tenant, email_domain) keeps domain resolution unambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS sso_connections_domain
  ON sso_connections (lower(email_domain)) WHERE email_domain <> '' AND enabled;

ALTER TABLE sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON sso_connections;
CREATE POLICY tenant_isolation ON sso_connections
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON sso_connections TO nirvet_app;

-- Controlled cross-tenant read for the unauthenticated OIDC callback: resolve a
-- connection (and its tenant) by id. Read-only, minimal columns, owner-defined.
DROP FUNCTION IF EXISTS sso_get_connection(uuid);
CREATE FUNCTION sso_get_connection(p_id uuid)
RETURNS TABLE (id uuid, tenant_id uuid, protocol text, issuer text, client_id text,
               client_secret bytea, redirect_uri text, default_role text, email_domain text, enabled boolean)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, protocol, issuer, client_id, client_secret, redirect_uri,
         default_role, email_domain, enabled
    FROM sso_connections WHERE id = p_id AND enabled
$$;
GRANT EXECUTE ON FUNCTION sso_get_connection(uuid) TO nirvet_app;

-- Resolve an enabled connection by email domain (for domain-initiated login start).
DROP FUNCTION IF EXISTS sso_find_by_domain(text);
CREATE FUNCTION sso_find_by_domain(p_domain text)
RETURNS TABLE (id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM sso_connections
   WHERE enabled AND email_domain <> '' AND lower(email_domain) = lower(p_domain)
   LIMIT 1
$$;
GRANT EXECUTE ON FUNCTION sso_find_by_domain(text) TO nirvet_app;
