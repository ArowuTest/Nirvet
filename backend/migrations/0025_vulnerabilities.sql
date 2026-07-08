-- Vulnerability & exposure management (SRS §6.15 slice 2; ASSET-004/002/006/007). Open
-- vulnerabilities mapped to assets by the same canonical ref the event pipeline + asset
-- registry use (host:FIN-01, user:jane@…), so no join table — the ref is the key. Feeds
-- exposure summaries and enriches incident/investigation/evidence with what a case is
-- actually exposed to. Tenant-scoped (RLS); Postgres is the system of record.

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL DEFAULT app_current_tenant(),
  ref             text NOT NULL,                 -- affected asset ref (matches assets.ref / actor_ref / target_ref)
  cve             text NOT NULL DEFAULT '',      -- CVE id or vendor id ('' if none)
  title           text NOT NULL,
  severity        text NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
  cvss            numeric(3,1) NOT NULL DEFAULT 0,  -- 0.0–10.0
  exploited       boolean NOT NULL DEFAULT false,   -- known-exploited / active-exploitation intel (KEV)
  status          text NOT NULL DEFAULT 'open'   CHECK (status IN ('open','remediating','accepted','resolved')),
  remediation_due timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, ref, cve)
);
CREATE INDEX IF NOT EXISTS vulnerabilities_tenant_status ON vulnerabilities (tenant_id, status);
CREATE INDEX IF NOT EXISTS vulnerabilities_tenant_ref    ON vulnerabilities (tenant_id, ref);

ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vulnerabilities;
CREATE POLICY tenant_isolation ON vulnerabilities
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON vulnerabilities TO nirvet_app;
