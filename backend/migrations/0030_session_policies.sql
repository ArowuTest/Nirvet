-- Session & access policy (SRS §6.2 IAM-007): configurable session timeout, IP allow-list,
-- and login/geo-anomaly logging — per tenant, admin-configurable. Replaces the hardcoded
-- global access-token TTL: login now issues a token with the tenant's configured TTL.
--
-- Owner rule (no hardcoding): the TTL and IP policy are DB records with seeded defaults
-- (the column DEFAULTs), overridable via the admin API — never code constants.

CREATE TABLE IF NOT EXISTS session_policies (
  tenant_id           uuid PRIMARY KEY DEFAULT app_current_tenant(),
  access_ttl_seconds  int  NOT NULL DEFAULT 900   CHECK (access_ttl_seconds BETWEEN 60 AND 86400),
  ip_allowlist        text[] NOT NULL DEFAULT '{}', -- empty = no restriction; else CIDR/Iel entries
  geo_anomaly_logging boolean NOT NULL DEFAULT true, -- log access from outside the allow-list
  updated_at          timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE session_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON session_policies;
CREATE POLICY tenant_isolation ON session_policies
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON session_policies TO nirvet_app;

-- Seed a default policy for existing tenants (runs as superuser, bypasses RLS). New tenants
-- self-heal a default row on first access.
INSERT INTO session_policies (tenant_id)
  SELECT id FROM tenants ON CONFLICT (tenant_id) DO NOTHING;
