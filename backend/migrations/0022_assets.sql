-- Asset inventory (SRS §6.15). A tenant's monitored assets (hosts, users, services,
-- cloud resources) with a business criticality, so an incident affecting a critical
-- asset can be triaged accordingly. Assets are matched to alerts/incidents by their
-- canonical ref (e.g. host:FIN-01, user:jane@acme.com), which the event pipeline
-- already carries as actor_ref / target_ref. Tenant-scoped (RLS), Postgres is the
-- system of record.

CREATE TABLE IF NOT EXISTS assets (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  ref         text NOT NULL,                 -- canonical reference (matches actor_ref/target_ref)
  name        text NOT NULL,
  kind        text NOT NULL DEFAULT 'host'   CHECK (kind IN ('host','user','service','cloud','network','other')),
  criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low','medium','high','critical')),
  owner       text NOT NULL DEFAULT '',
  tags        text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, ref)
);
CREATE INDEX IF NOT EXISTS assets_tenant_kind ON assets (tenant_id, kind);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON assets;
CREATE POLICY tenant_isolation ON assets
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO nirvet_app;
