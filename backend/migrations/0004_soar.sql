-- SOAR: playbooks, runs, and per-tenant authority-to-act (SRS §6.11; doc 03 §6, doc 04 §7).

-- Authority-to-act mode per tenant (governs which actions may auto-run).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS authority_mode text NOT NULL DEFAULT 'observe';
ALTER TABLE tenants ADD CONSTRAINT tenants_authority_chk
  CHECK (authority_mode IN ('observe','approval','pre_authorised','emergency'));

-- Playbooks: global (tenant_id NULL) or tenant-owned. steps is an ordered array of
-- {name, connector_key, action, risk, requires_approval}.
CREATE TABLE IF NOT EXISTS playbooks (
  id               uuid PRIMARY KEY,
  tenant_id        uuid,
  name             text NOT NULL,
  description      text NOT NULL DEFAULT '',
  trigger_category text NOT NULL DEFAULT '*',
  steps            jsonb NOT NULL DEFAULT '[]',
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON playbooks TO nirvet_app;

INSERT INTO playbooks (id, tenant_id, name, description, trigger_category, steps) VALUES
 (gen_random_uuid(), NULL, 'Suspected compromised account',
  'Enrich, then contain a compromised identity under authority-to-act.', 'identity',
  '[{"name":"Enrich user sign-ins & MFA","connector_key":"entra-id","action":"enrich","risk":"low","requires_approval":false},
    {"name":"Check mailbox rules & OAuth grants","connector_key":"microsoft-365","action":"inspect_mailbox","risk":"low","requires_approval":false},
    {"name":"Revoke sessions","connector_key":"entra-id","action":"revoke_sessions","risk":"high","requires_approval":true},
    {"name":"Reset password","connector_key":"entra-id","action":"reset_password","risk":"high","requires_approval":true}]');

ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON playbooks;
CREATE POLICY tenant_isolation ON playbooks
  USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)
  WITH CHECK (tenant_id = app_current_tenant());

-- Playbook runs (execution instances with approval + results).
CREATE TABLE IF NOT EXISTS playbook_runs (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  playbook_id  uuid NOT NULL,
  incident_id  uuid,
  status       text NOT NULL DEFAULT 'running'
                 CHECK (status IN ('pending_approval','running','completed','failed','rejected')),
  steps_result jsonb NOT NULL DEFAULT '[]',
  requested_by uuid,
  approved_by  uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS playbook_runs_tenant ON playbook_runs (tenant_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON playbook_runs TO nirvet_app;

ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON playbook_runs;
CREATE POLICY tenant_isolation ON playbook_runs
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
