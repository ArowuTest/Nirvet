-- LAUNCH #4 (#187) slice A — playbook authoring. Tenants can now create/update/enable tenant-owned playbooks
-- through the API (previously playbooks came ONLY from seed migrations). Adds a version pointer to playbooks and
-- an append-only playbook_versions snapshot table (mirrors detection_rule_versions) — a containment-driving
-- artifact needs a change-history trail (reviewer condition 2 answer). Authoring never touches GLOBAL playbooks
-- (tenant_id NULL, provider-managed): the repo filters `tenant_id IS NOT NULL` and RLS WITH CHECK pins writes to
-- the current tenant.

ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS version    integer     NOT NULL DEFAULT 1;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

-- Append-only version history. nirvet_app gets SELECT + INSERT only (no UPDATE/DELETE) — the snapshot trail is
-- immutable, like detection_rule_versions. Rollback (a NEW version restoring an old body) is #181 depth.
CREATE TABLE IF NOT EXISTS playbook_versions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL DEFAULT app_current_tenant(),
  playbook_id      uuid NOT NULL,
  version          integer NOT NULL,
  name             text NOT NULL,
  description      text NOT NULL DEFAULT '',
  trigger_category text NOT NULL DEFAULT '*',
  steps            jsonb NOT NULL DEFAULT '[]',
  note             text NOT NULL DEFAULT '',
  created_by       uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, playbook_id, version)
);
CREATE INDEX IF NOT EXISTS playbook_versions_lookup ON playbook_versions (tenant_id, playbook_id, version DESC);

ALTER TABLE playbook_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON playbook_versions;
CREATE POLICY tenant_isolation ON playbook_versions
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON playbook_versions TO nirvet_app;
