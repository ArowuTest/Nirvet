-- §6.6 detection slice B: detection-as-code lifecycle (DET-001/006, SRS §9.4). Adds the promotion
-- lifecycle stage, a version counter, an owner, and declared data-source dependencies to detection
-- rules, plus a version-snapshot history table for rollback.
--
-- Non-breaking: stage defaults to 'production' so every existing rule keeps firing, and the engine's
-- active-rule filter (enabled AND stage in pilot/production/tuned) leaves current behavior unchanged.

ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS stage        text NOT NULL DEFAULT 'production';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS version      int  NOT NULL DEFAULT 1;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS owner_id     uuid;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS source_dependencies text[] NOT NULL DEFAULT '{}';
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_transition_at timestamptz;

ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_stage_chk;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_stage_chk
  CHECK (stage IN ('draft','peer_review','qa','pilot','production','tuned','retired'));

-- Version-snapshot history for rollback (DET-001). Each snapshot captures the rule body at a version.
-- Tenant-scoped; snapshots of global rules are provider-managed (tenant_id NULL, seeded by migrations).
CREATE TABLE IF NOT EXISTS detection_rule_versions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid,                          -- NULL = snapshot of a global rule
  rule_id    uuid NOT NULL,
  version    int  NOT NULL,
  stage      text NOT NULL DEFAULT 'draft',
  snapshot   jsonb NOT NULL,                -- full rule body at this version
  note       text NOT NULL DEFAULT '',
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (rule_id, version)
);
CREATE INDEX IF NOT EXISTS detection_rule_versions_rule ON detection_rule_versions (rule_id, version DESC);

ALTER TABLE detection_rule_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rule_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS detection_rule_versions_select ON detection_rule_versions;
DROP POLICY IF EXISTS detection_rule_versions_insert ON detection_rule_versions;
-- Read own + global-rule snapshots; write own-tenant only (append-only: no update/delete grant).
CREATE POLICY detection_rule_versions_select ON detection_rule_versions
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY detection_rule_versions_insert ON detection_rule_versions
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON detection_rule_versions TO nirvet_app;
