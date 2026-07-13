-- 0082_sovereign_compliance_baseline.sql — GENERIC sovereign/government compliance baseline (§6.14).
--
-- Two GLOBAL framework templates (config-first, tenant_id NULL), reusable across ANY sovereign/government
-- deployment — NOT country-specific. They sit alongside the nist_csf_2_0 / cis_v8_1 / iso_27001_2022 global
-- templates and share the same engine: controls map to the platform's existing auto_signal resolvers where a
-- live signal proves them; process/governance controls are `manual`.
--
-- WHY GENERIC: national CII directives and data-protection acts share a common backbone (governance, risk,
-- protection, detection, incident reporting + vulnerability disclosure, audit; and the standard data-protection
-- principles). Seeding a generic baseline means every sovereign customer gets a sensible starting point with
-- ZERO new code. COUNTRY-SPECIFIC details — exact reporting windows (e.g. 24h/72h), the named national
-- regulator, statute references — are added per customer as TENANT-CUSTOM refinements via the compliance API,
-- not as core migrations. Adding a new sovereign never requires SQL or code, only data.
--
-- Reference model (provenance): derived from the Ghana CSA Directive for the Protection of Critical Information
-- Infrastructure (Cybersecurity Act 2020, Act 1038) and the eight data-protection principles pattern (e.g. Ghana
-- Data Protection Act 2012, Act 843) — generalised so it fits any comparable national regime.
-- Valid auto_signal resolvers: asset_inventory | detection_coverage | incident_response |
--   platform_capability (reads {"note":...}, resolves Met) | soar_automation | threat_intel | manual | '' (rollup).

-- ================= Framework 1: Sovereign / Government CII Cybersecurity Baseline =================
INSERT INTO compliance_frameworks (tenant_id, key, name, version, description) VALUES
  (NULL, 'sovereign_cii_baseline', 'Sovereign / Government CII Cybersecurity Baseline',
   '1.0', 'Generic baseline cybersecurity requirements for designated critical-information-infrastructure owners under a national cybersecurity regime. Reusable template — add country-specific windows/regulator/statute as tenant-custom refinements.')
ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (tenant_id, framework_key, control_ref, parent_ref, title, weight, auto_signal, auto_config) VALUES
  -- top-level functions (rollups)
  (NULL,'sovereign_cii_baseline','GOV',  '', 'Governance',             2,'','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','RISK', '', 'Risk Management',        2,'','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','PROT', '', 'Protection',             2,'','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','DET',  '', 'Detection',              2,'','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','RESP', '', 'Response and Reporting', 3,'','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','AUD',  '', 'Audit and Assurance',    2,'','{}'::jsonb),
  -- governance
  (NULL,'sovereign_cii_baseline','GOV.1','GOV','Board-approved cybersecurity policy',        2,'manual','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','GOV.2','GOV','Appointed accountable security officer',      2,'manual','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','GOV.3','GOV','Cybersecurity governance structure',          1,'manual','{}'::jsonb),
  -- risk
  (NULL,'sovereign_cii_baseline','RISK.1','RISK','Regular risk assessments',                  2,'manual','{}'::jsonb),
  -- protection
  (NULL,'sovereign_cii_baseline','PROT.1','PROT','Asset protection and inventory',            2,'asset_inventory','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','PROT.2','PROT','Access control',                            2,'platform_capability','{"note":"RLS tenant isolation + least-privilege scopes + MFA/SSO."}'::jsonb),
  (NULL,'sovereign_cii_baseline','PROT.3','PROT','Employee security training',                1,'manual','{}'::jsonb),
  -- detection
  (NULL,'sovereign_cii_baseline','DET.1','DET','Security monitoring and detection coverage',  3,'detection_coverage','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','DET.2','DET','Threat intelligence',                         1,'threat_intel','{}'::jsonb),
  -- response and reporting
  (NULL,'sovereign_cii_baseline','RESP.1','RESP','Incident response capability',              3,'incident_response','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','RESP.2','RESP','Incident reporting to the national regulator within the mandated window', 3,'manual','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','RESP.3','RESP','Vulnerability disclosure within the mandated window',                     2,'manual','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','RESP.4','RESP','Automated containment and response',        2,'soar_automation','{}'::jsonb),
  -- audit and assurance
  (NULL,'sovereign_cii_baseline','AUD.1','AUD','Periodic security audits',                    2,'manual','{}'::jsonb),
  (NULL,'sovereign_cii_baseline','AUD.2','AUD','Immutable audit trail',                       2,'platform_capability','{"note":"Immutable, tenant-scoped audit log."}'::jsonb)
ON CONFLICT DO NOTHING;

-- ================= Framework 2: Sovereign Data Protection Baseline =================
INSERT INTO compliance_frameworks (tenant_id, key, name, version, description) VALUES
  (NULL, 'sovereign_data_protection', 'Sovereign Data Protection Baseline',
   '1.0', 'The standard data-protection principles common to national data-protection laws. Reusable template — add the country statute and regulator specifics as tenant-custom refinements.')
ON CONFLICT DO NOTHING;

INSERT INTO compliance_controls (tenant_id, framework_key, control_ref, parent_ref, title, weight, auto_signal, auto_config) VALUES
  (NULL,'sovereign_data_protection','DPP','', 'Data Protection Principles', 1,'','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.1','DPP','Accountability',                          2,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.2','DPP','Lawfulness of processing and consent',    2,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.3','DPP','Specification of purpose',                 1,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.4','DPP','Compatibility of further processing',      1,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.5','DPP','Quality of information',                   1,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.6','DPP','Openness and transparency',                1,'manual','{}'::jsonb),
  -- MANUAL (reviewer flag): data-security safeguards is an officer-assessed control, NOT auto-asserted "Met".
  -- platform_capability would auto-assert Met, over-claiming to an auditor while production KMS is deferred to
  -- go-live (the vault exists but full key management is not yet in place). Officer attests actual state.
  (NULL,'sovereign_data_protection','DPP.7','DPP','Data security safeguards',                 3,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.8','DPP','Data subject participation and rights',    2,'manual','{}'::jsonb),
  (NULL,'sovereign_data_protection','DPP.9','DPP','Personal data breach response',           2,'incident_response','{}'::jsonb)
ON CONFLICT DO NOTHING;
