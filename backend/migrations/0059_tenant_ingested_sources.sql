-- 0059_tenant_ingested_sources.sql
-- §6.6 M3 (perf, P1 class): the detection-coverage endpoint previously ran DISTINCT source over a 90-day
-- raw_events window on an unindexed column on every call. Maintain a tiny per-tenant materialised set of
-- ingested sources instead (one row per (tenant, source), upserted on ingest behind an in-memory guard),
-- so coverage reads a small PK-indexed table. Tenant-scoped RLS.

CREATE TABLE IF NOT EXISTS tenant_ingested_sources (
  tenant_id uuid NOT NULL,
  source    text NOT NULL,
  last_seen timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source)
);
-- Coverage reads by tenant + recency window.
CREATE INDEX IF NOT EXISTS tenant_ingested_sources_recency ON tenant_ingested_sources (tenant_id, last_seen);

ALTER TABLE tenant_ingested_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_ingested_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_ingested_sources_rw ON tenant_ingested_sources;
CREATE POLICY tenant_ingested_sources_rw ON tenant_ingested_sources
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_ingested_sources TO nirvet_app;
