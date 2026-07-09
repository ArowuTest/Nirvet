-- 0056_detection_slice_c.sql
-- §6.6 detection slice C → FULL: DET-005 test-against-sample, DET-007 FP-disposition feedback loop,
-- DET-009 data-source-dependency coverage. Config-first via detection_settings. All tenant-owned,
-- RLS own-only; feedback is append-only (no UPDATE/DELETE grant).

-- DET-005: named test cases per rule. sample is a partial normalized event (jsonb); expected_match is
-- the assertion the runner checks. Tenant-owned; a tenant may author tests against any rule it can see.
CREATE TABLE IF NOT EXISTS detection_test_cases (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  rule_id        uuid NOT NULL,
  name           text NOT NULL,
  sample         jsonb NOT NULL,               -- partial NormalizedEvent (class_name/severity/data/...)
  expected_match boolean NOT NULL,
  created_by     uuid,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS detection_test_cases_rule ON detection_test_cases (tenant_id, rule_id);

ALTER TABLE detection_test_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_test_cases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_test_cases_rw ON detection_test_cases;
CREATE POLICY detection_test_cases_rw ON detection_test_cases
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, DELETE ON detection_test_cases TO nirvet_app;

-- DET-007: append-only false-positive/disposition feedback attributed to the firing rule.
CREATE TABLE IF NOT EXISTS detection_feedback (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL,
  rule_id     uuid NOT NULL,
  alert_id    uuid,
  disposition text NOT NULL CHECK (disposition IN ('true_positive','false_positive','benign','duplicate')),
  reason      text NOT NULL DEFAULT '',
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS detection_feedback_rule ON detection_feedback (tenant_id, rule_id);

ALTER TABLE detection_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_feedback_select ON detection_feedback;
DROP POLICY IF EXISTS detection_feedback_insert ON detection_feedback;
-- Append-only: read + insert own-tenant; NO update/delete grant (feedback is an audit signal).
CREATE POLICY detection_feedback_select ON detection_feedback
  FOR SELECT USING (tenant_id = app_current_tenant());
CREATE POLICY detection_feedback_insert ON detection_feedback
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON detection_feedback TO nirvet_app;

-- Config (no hardcoding): per-tenant tuning thresholds + coverage window + promotion-gate toggle.
-- Lazy default — a tenant with no row uses the column defaults (service returns them); Set upserts.
CREATE TABLE IF NOT EXISTS detection_settings (
  tenant_id                    uuid PRIMARY KEY,
  fp_rate_threshold            numeric NOT NULL DEFAULT 0.30 CHECK (fp_rate_threshold >= 0 AND fp_rate_threshold <= 1),
  min_feedback_sample          int     NOT NULL DEFAULT 20   CHECK (min_feedback_sample >= 1),
  coverage_window_days         int     NOT NULL DEFAULT 7    CHECK (coverage_window_days >= 1 AND coverage_window_days <= 90),
  require_tests_for_production  boolean NOT NULL DEFAULT true,
  updated_at                   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE detection_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_settings_rw ON detection_settings;
CREATE POLICY detection_settings_rw ON detection_settings
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON detection_settings TO nirvet_app;
