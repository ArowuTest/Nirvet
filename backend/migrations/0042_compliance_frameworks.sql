-- §6.14 compliance — config-driven control frameworks + per-tenant assessment (COMP-001/002/004).
--
-- Replaces the hardcoded static NIST-CSF struct (identical for every tenant) with:
--   * compliance_frameworks  — framework catalogue (global templates + tenant-custom)
--   * compliance_controls    — controls within a framework, each carrying a seeded auto_signal MAPPING
--                              (which live platform signal proves it); the mapping is config, the signal
--                              resolver is code.
--   * compliance_control_status — per-tenant assessed status (auto cache + manual override).
-- Frameworks/controls follow the detection_rules/stix_objects global-or-own guardrail: shared templates
-- (tenant_id NULL) are read-only to tenants; a tenant can add its own but cannot re-home/delete a global.

CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid,                       -- NULL = global template
  key         text NOT NULL,              -- nist_csf_2_0 | cis_v8_1 | iso_27001_2022 | <tenant-custom>
  name        text NOT NULL,
  version     text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, key)
);
CREATE INDEX IF NOT EXISTS compliance_frameworks_key ON compliance_frameworks (key);

ALTER TABLE compliance_frameworks ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_frameworks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_frameworks_select ON compliance_frameworks;
DROP POLICY IF EXISTS compliance_frameworks_insert ON compliance_frameworks;
DROP POLICY IF EXISTS compliance_frameworks_update ON compliance_frameworks;
DROP POLICY IF EXISTS compliance_frameworks_delete ON compliance_frameworks;
CREATE POLICY compliance_frameworks_select ON compliance_frameworks
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY compliance_frameworks_insert ON compliance_frameworks
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY compliance_frameworks_update ON compliance_frameworks
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY compliance_frameworks_delete ON compliance_frameworks
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_frameworks TO nirvet_app;

CREATE TABLE IF NOT EXISTS compliance_controls (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid,                     -- NULL = global template control
  framework_key text NOT NULL,
  control_ref   text NOT NULL,            -- GV, GV.OC, ID.AM, ...
  parent_ref    text NOT NULL DEFAULT '', -- '' = top-level function; else the parent control_ref
  title         text NOT NULL,
  description   text NOT NULL DEFAULT '',
  weight        int  NOT NULL DEFAULT 1,
  auto_signal   text NOT NULL DEFAULT '', -- '' = rollup-only (function) ; 'manual' = no auto ; else a signal key
  auto_config   jsonb NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, framework_key, control_ref),
  CONSTRAINT compliance_controls_weight_chk CHECK (weight BETWEEN 1 AND 100)
);
CREATE INDEX IF NOT EXISTS compliance_controls_fw ON compliance_controls (framework_key, tenant_id);

ALTER TABLE compliance_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_controls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compliance_controls_select ON compliance_controls;
DROP POLICY IF EXISTS compliance_controls_insert ON compliance_controls;
DROP POLICY IF EXISTS compliance_controls_update ON compliance_controls;
DROP POLICY IF EXISTS compliance_controls_delete ON compliance_controls;
CREATE POLICY compliance_controls_select ON compliance_controls
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY compliance_controls_insert ON compliance_controls
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY compliance_controls_update ON compliance_controls
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY compliance_controls_delete ON compliance_controls
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_controls TO nirvet_app;

CREATE TABLE IF NOT EXISTS compliance_control_status (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL DEFAULT app_current_tenant(),
  framework_key       text NOT NULL,
  control_ref         text NOT NULL,
  status              text NOT NULL DEFAULT 'gap',   -- met | partial | gap | not_applicable
  score               int  NOT NULL DEFAULT 0,        -- 0-100
  source              text NOT NULL DEFAULT 'manual', -- auto | manual
  note                text NOT NULL DEFAULT '',
  evidence_incident_id uuid,
  evidence_ref        text NOT NULL DEFAULT '',
  assessed_by         uuid,
  assessed_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, framework_key, control_ref),
  CONSTRAINT compliance_status_status_chk CHECK (status IN ('met','partial','gap','not_applicable')),
  CONSTRAINT compliance_status_source_chk CHECK (source IN ('auto','manual')),
  CONSTRAINT compliance_status_score_chk  CHECK (score BETWEEN 0 AND 100)
);
CREATE INDEX IF NOT EXISTS compliance_status_lookup ON compliance_control_status (tenant_id, framework_key);

ALTER TABLE compliance_control_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_control_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON compliance_control_status;
CREATE POLICY tenant_isolation ON compliance_control_status
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_control_status TO nirvet_app;

-- ── Seed global framework templates ─────────────────────────────────────────────────────────────────
INSERT INTO compliance_frameworks (tenant_id, key, name, version, description) VALUES
  (NULL, 'nist_csf_2_0',   'NIST Cybersecurity Framework', '2.0',    'NIST CSF 2.0 functions and categories.'),
  (NULL, 'cis_v8_1',       'CIS Critical Security Controls','8.1',    'CIS Controls v8.1 (subset seeded).'),
  (NULL, 'iso_27001_2022', 'ISO/IEC 27001',                '2022',    'ISO/IEC 27001:2022 Annex A (subset seeded).')
ON CONFLICT (tenant_id, key) DO NOTHING;

-- ── Seed NIST CSF 2.0 controls: 6 functions (rollup-only) + core categories mapped to live signals ──
INSERT INTO compliance_controls (tenant_id, framework_key, control_ref, parent_ref, title, weight, auto_signal, auto_config) VALUES
  (NULL,'nist_csf_2_0','GV','',   'Govern',   1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','ID','',   'Identify', 1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','PR','',   'Protect',  1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','DE','',   'Detect',   1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','RS','',   'Respond',  1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','RC','',   'Recover',  1,'','{}'::jsonb),
  (NULL,'nist_csf_2_0','GV.OC','GV','Organizational Context',    1,'platform_capability','{"note":"RBAC, immutable audit, tenant governance policy."}'),
  (NULL,'nist_csf_2_0','GV.RR','GV','Roles, Responsibilities & Authorities',1,'platform_capability','{"note":"Role model + authority-to-act policy gating."}'),
  (NULL,'nist_csf_2_0','ID.AM','ID','Asset Management',          1,'asset_inventory','{}'),
  (NULL,'nist_csf_2_0','ID.RA','ID','Risk Assessment',           1,'threat_intel','{}'),
  (NULL,'nist_csf_2_0','PR.AA','PR','Identity Management & Access Control',1,'platform_capability','{"note":"RLS tenant isolation + least-privilege scopes + MFA/SSO."}'),
  (NULL,'nist_csf_2_0','PR.DS','PR','Data Security',             1,'platform_capability','{"note":"Credential vault (KMS) + encrypted evidence store."}'),
  (NULL,'nist_csf_2_0','DE.CM','DE','Continuous Monitoring',     2,'detection_coverage','{}'),
  (NULL,'nist_csf_2_0','DE.AE','DE','Adverse Event Analysis',    1,'detection_coverage','{}'),
  (NULL,'nist_csf_2_0','RS.MA','RS','Incident Management',       2,'incident_response','{}'),
  (NULL,'nist_csf_2_0','RS.MI','RS','Incident Mitigation',       1,'soar_automation','{}'),
  (NULL,'nist_csf_2_0','RC.RP','RC','Incident Recovery Plan Execution',1,'not_implemented','{"note":"Recovery/continuity tracking not yet built in-platform."}'),
  (NULL,'nist_csf_2_0','RC.CO','RC','Incident Recovery Communication',1,'not_implemented','{"note":"Recovery communication workflow not yet built."}')
ON CONFLICT (tenant_id, framework_key, control_ref) DO NOTHING;

-- CIS v8.1 / ISO 27001 seeded minimally (framework + a couple of mapped controls) — full catalogues are a
-- data-load task, not logic. They prove the model is multi-framework.
INSERT INTO compliance_controls (tenant_id, framework_key, control_ref, parent_ref, title, weight, auto_signal, auto_config) VALUES
  (NULL,'cis_v8_1','CIS-1','', 'Inventory and Control of Enterprise Assets',1,'asset_inventory','{}'),
  (NULL,'cis_v8_1','CIS-8','', 'Audit Log Management',                      1,'platform_capability','{"note":"Immutable, tenant-scoped audit log."}'),
  (NULL,'cis_v8_1','CIS-13','','Network Monitoring and Defense',            1,'detection_coverage','{}'),
  (NULL,'cis_v8_1','CIS-17','','Incident Response Management',              1,'incident_response','{}'),
  (NULL,'iso_27001_2022','A.5.7', '','Threat Intelligence',        1,'threat_intel','{}'),
  (NULL,'iso_27001_2022','A.8.15','','Logging',                    1,'platform_capability','{"note":"Immutable audit logging."}'),
  (NULL,'iso_27001_2022','A.8.16','','Monitoring Activities',      1,'detection_coverage','{}'),
  (NULL,'iso_27001_2022','A.5.26','','Response to Information Security Incidents',1,'incident_response','{}')
ON CONFLICT (tenant_id, framework_key, control_ref) DO NOTHING;
