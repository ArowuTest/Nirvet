-- 0061_normalization_quality.sql
-- §6.5 slice A: normalization data-quality + drift observability (NORM-003/009) and its config
-- (NORM-006 threshold). Both tenant-scoped RLS, config lazy-defaulted.

-- Per-(tenant, source, day) rolling aggregate maintained by the worker (in-memory accumulator flushed
-- once per batch — no per-event write). avg_confidence = sum_confidence / events; a source whose
-- avg falls below the tenant's min_confidence is flagged as drifting.
CREATE TABLE IF NOT EXISTS normalization_quality (
  tenant_id      uuid NOT NULL,
  source         text NOT NULL,
  day            int  NOT NULL,                 -- day-of-year bucket
  events         bigint NOT NULL DEFAULT 0,
  sum_confidence bigint NOT NULL DEFAULT 0,
  parser         text NOT NULL DEFAULT '',
  parser_version int  NOT NULL DEFAULT 0,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source, day)
);
CREATE INDEX IF NOT EXISTS normalization_quality_recency ON normalization_quality (tenant_id, updated_at);

ALTER TABLE normalization_quality ENABLE ROW LEVEL SECURITY;
ALTER TABLE normalization_quality FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS normalization_quality_rw ON normalization_quality;
CREATE POLICY normalization_quality_rw ON normalization_quality
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON normalization_quality TO nirvet_app;

-- Per-tenant normalization tuning (lazy default).
CREATE TABLE IF NOT EXISTS normalization_settings (
  tenant_id      uuid PRIMARY KEY,
  min_confidence int NOT NULL DEFAULT 50 CHECK (min_confidence >= 0 AND min_confidence <= 100),
  window_days    int NOT NULL DEFAULT 7  CHECK (window_days >= 1 AND window_days <= 90),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE normalization_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE normalization_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS normalization_settings_rw ON normalization_settings;
CREATE POLICY normalization_settings_rw ON normalization_settings
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON normalization_settings TO nirvet_app;
