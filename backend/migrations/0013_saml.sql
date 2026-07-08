-- SAML 2.0 SSO — per-tenant IdP connections (SRS §6.2 IAM-001). Unlike OIDC there
-- is no client secret: the idp_certificate is the IdP's PUBLIC signing cert (used
-- to validate the signed SAML Response), so no vault is needed. Tenant-scoped under
-- RLS; the unauthenticated ACS resolves a connection via a SECURITY DEFINER lookup
-- (the controlled cross-tenant hole, mirroring the OIDC callback).

CREATE TABLE IF NOT EXISTS saml_connections (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL DEFAULT app_current_tenant(),
  idp_entity_id    text NOT NULL,               -- IdP issuer / entityID (validated vs assertion issuer)
  idp_sso_url      text NOT NULL,               -- IdP SingleSignOnService (HTTP-Redirect)
  idp_certificate  text NOT NULL,               -- IdP signing cert (PEM, public)
  sp_entity_id     text NOT NULL,               -- our SP entityID == audience the IdP asserts to
  acs_url          text NOT NULL,               -- our Assertion Consumer Service URL
  email_attribute  text NOT NULL DEFAULT '',    -- SAML attribute holding email; '' => use NameID
  default_role     text NOT NULL DEFAULT 'customer_viewer',
  email_domain     text NOT NULL DEFAULT '',    -- allowlist; '' = any (discouraged)
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_connections_tenant ON saml_connections (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS saml_connections_domain
  ON saml_connections (lower(email_domain)) WHERE email_domain <> '' AND enabled;

ALTER TABLE saml_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON saml_connections;
CREATE POLICY tenant_isolation ON saml_connections
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON saml_connections TO nirvet_app;

-- Controlled cross-tenant read for the unauthenticated ACS.
DROP FUNCTION IF EXISTS saml_get_connection(uuid);
CREATE FUNCTION saml_get_connection(p_id uuid)
RETURNS TABLE (id uuid, tenant_id uuid, idp_entity_id text, idp_sso_url text, idp_certificate text,
               sp_entity_id text, acs_url text, email_attribute text, default_role text, email_domain text, enabled boolean)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, acs_url,
         email_attribute, default_role, email_domain, enabled
    FROM saml_connections WHERE id = p_id AND enabled
$$;
GRANT EXECUTE ON FUNCTION saml_get_connection(uuid) TO nirvet_app;

DROP FUNCTION IF EXISTS saml_find_by_domain(text);
CREATE FUNCTION saml_find_by_domain(p_domain text)
RETURNS TABLE (id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM saml_connections
   WHERE enabled AND email_domain <> '' AND lower(email_domain) = lower(p_domain)
   LIMIT 1
$$;
GRANT EXECUTE ON FUNCTION saml_find_by_domain(text) TO nirvet_app;
