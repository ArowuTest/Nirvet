-- §6.8 case management slice B: tasks (CASE-005), parent/child + major incidents (CASE-006),
-- config-driven category templates (CASE-007).

-- ── CASE-005: investigation tasks / checklist ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_tasks (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  incident_id  uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  title        text NOT NULL,
  description  text NOT NULL DEFAULT '',
  assignee_id  uuid,
  status       text NOT NULL DEFAULT 'open',   -- open | in_progress | done | cancelled
  due_at       timestamptz,
  created_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CONSTRAINT incident_tasks_status_chk CHECK (status IN ('open','in_progress','done','cancelled'))
);
CREATE INDEX IF NOT EXISTS incident_tasks_lookup ON incident_tasks (tenant_id, incident_id);

ALTER TABLE incident_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_tasks;
CREATE POLICY tenant_isolation ON incident_tasks
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_tasks TO nirvet_app;

-- ── CASE-006: parent/child (major incident) ─────────────────────────────────────────────────────────
-- parent_id links a child incident to an umbrella "major" incident. ON DELETE SET NULL so removing a
-- parent orphans children rather than cascading. is_major flags the umbrella case.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS parent_id uuid REFERENCES incidents(id) ON DELETE SET NULL;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS is_major boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS incidents_parent ON incidents (parent_id) WHERE parent_id IS NOT NULL;

-- ── CASE-007: category templates (config, not free-text) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_categories (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid,                       -- NULL = global template
  key              text NOT NULL,              -- malware | phishing | ...
  name             text NOT NULL,
  description      text NOT NULL DEFAULT '',
  default_severity text NOT NULL DEFAULT 'medium',
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, key),
  CONSTRAINT incident_categories_sev_chk CHECK (default_severity IN ('informational','low','medium','high','critical'))
);
CREATE INDEX IF NOT EXISTS incident_categories_key ON incident_categories (key);

ALTER TABLE incident_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_categories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS incident_categories_select ON incident_categories;
DROP POLICY IF EXISTS incident_categories_insert ON incident_categories;
DROP POLICY IF EXISTS incident_categories_update ON incident_categories;
DROP POLICY IF EXISTS incident_categories_delete ON incident_categories;
CREATE POLICY incident_categories_select ON incident_categories
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY incident_categories_insert ON incident_categories
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY incident_categories_update ON incident_categories
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY incident_categories_delete ON incident_categories
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON incident_categories TO nirvet_app;

-- Seed the global default category set (doc 03 §5 taxonomy). uncategorised keeps the current default valid.
INSERT INTO incident_categories (tenant_id, key, name, default_severity, description) VALUES
  (NULL,'malware',             'Malware',                'high',    'Malicious code detected on an asset.'),
  (NULL,'phishing',            'Phishing',               'medium',  'Credential-harvesting or lure email/site.'),
  (NULL,'unauthorized_access', 'Unauthorized Access',    'high',    'Access without authorization / suspicious sign-in.'),
  (NULL,'data_exfiltration',   'Data Exfiltration',      'critical','Suspected exfiltration of data.'),
  (NULL,'denial_of_service',   'Denial of Service',      'high',    'Availability impact / DoS.'),
  (NULL,'policy_violation',    'Policy Violation',       'low',     'Acceptable-use or security-policy breach.'),
  (NULL,'reconnaissance',      'Reconnaissance',         'low',     'Scanning / enumeration activity.'),
  (NULL,'misconfiguration',    'Misconfiguration',       'medium',  'Insecure configuration / exposure.'),
  (NULL,'insider_threat',      'Insider Threat',         'high',    'Malicious or negligent insider activity.'),
  (NULL,'uncategorised',       'Uncategorised',          'medium',  'Not yet categorised.')
ON CONFLICT (tenant_id, key) DO NOTHING;
