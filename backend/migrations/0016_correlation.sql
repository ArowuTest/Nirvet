-- Alert correlation & risk scoring (SRS §6.7). Related alerts — those sharing an
-- entity (a host/user/ip) within a time window — are clustered into a correlation
-- with an aggregate risk score, so analysts triage one prioritised cluster instead
-- of N independent alerts. Tenant-scoped (RLS).

CREATE TABLE IF NOT EXISTS correlations (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  entity       text NOT NULL,                 -- the shared actor/target ref (e.g. host:FIN-01)
  status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open','promoted','closed')),
  alert_count  int  NOT NULL DEFAULT 0,
  max_severity text NOT NULL DEFAULT 'informational',
  risk_score   int  NOT NULL DEFAULT 0,        -- 0-100 aggregate
  techniques   text[] NOT NULL DEFAULT '{}',   -- distinct ATT&CK techniques in the cluster
  incident_id  uuid,
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now(),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS correlations_tenant_entity ON correlations (tenant_id, entity, status);
CREATE INDEX IF NOT EXISTS correlations_risk ON correlations (tenant_id, risk_score DESC);

ALTER TABLE correlations ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON correlations;
CREATE POLICY tenant_isolation ON correlations
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON correlations TO nirvet_app;

-- Alerts carry their individual risk and a link to their correlation cluster.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score     int NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_id uuid;
