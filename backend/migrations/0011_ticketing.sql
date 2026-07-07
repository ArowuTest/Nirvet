-- Outbound ticketing — per-tenant ServiceNow/Jira connections (SRS §6.16, §8).
-- The credential (ServiceNow password / Jira API token) is vault-encrypted
-- (bytea, ADR-0004). Tenant-scoped under RLS. The incident-open path runs in the
-- tenant context, so normal RLS applies — no SECURITY DEFINER needed here.

CREATE TABLE IF NOT EXISTS ticketing_connections (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  provider     text NOT NULL CHECK (provider IN ('servicenow','jira')),
  base_url     text NOT NULL,
  auth_user    text NOT NULL DEFAULT '',   -- ServiceNow user / Jira account email
  credential   bytea NOT NULL,             -- vault-sealed (tenant AAD)
  config       jsonb NOT NULL DEFAULT '{}', -- e.g. {"project_key":"SOC","assignment_group":"..."}
  enabled      boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ticketing_connections_tenant ON ticketing_connections (tenant_id);

ALTER TABLE ticketing_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticketing_connections FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ticketing_connections;
CREATE POLICY tenant_isolation ON ticketing_connections
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON ticketing_connections TO nirvet_app;
