-- Threat intelligence watchlist (SRS §6.10) and billing entitlements (SRS §6.17).

CREATE TABLE IF NOT EXISTS threat_indicators (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  type       text NOT NULL,               -- ip | domain | url | hash | email | user | host
  value      text NOT NULL,
  tlp        text NOT NULL DEFAULT 'amber',
  score      int  NOT NULL DEFAULT 50,     -- 0-100 malicious confidence
  tags       text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, type, value)
);
CREATE INDEX IF NOT EXISTS threat_indicators_lookup ON threat_indicators (tenant_id, value);

ALTER TABLE threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_indicators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON threat_indicators;
CREATE POLICY tenant_isolation ON threat_indicators
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON threat_indicators TO nirvet_app;

CREATE TABLE IF NOT EXISTS entitlements (
  tenant_id        uuid PRIMARY KEY DEFAULT app_current_tenant(),
  tier             text NOT NULL DEFAULT 'standard',
  events_per_day   bigint NOT NULL DEFAULT 100000,
  max_integrations int NOT NULL DEFAULT 10,
  retention_days   int NOT NULL DEFAULT 90,
  ir_hours         int NOT NULL DEFAULT 0,
  updated_at       timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON entitlements;
CREATE POLICY tenant_isolation ON entitlements
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON entitlements TO nirvet_app;
