-- Hardening (audit fixes) + real detection engine.

-- ---------------------------------------------------------------------------
-- [B/P1] Index login lookups. auth_find_user_by_email filters by email alone;
-- the composite UNIQUE(tenant_id, email) can't serve it. Add a case-insensitive
-- email index and make the lookup case-insensitive.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS users_lower_email ON users (lower(email));

CREATE OR REPLACE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, password_hash text, role text, status text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, password_hash, role, status
    FROM users WHERE lower(email) = lower(p_email) LIMIT 1
$$;

-- ---------------------------------------------------------------------------
-- [A/P1] Alert idempotency: one alert per (event, rule). Add detection linkage.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detection_id uuid;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedupe_key text;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre text[] NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX IF NOT EXISTS alerts_tenant_dedupe
  ON alerts (tenant_id, dedupe_key) WHERE dedupe_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- [B/P2] Enum integrity — reject invalid severities/statuses/stages/roles.
-- ---------------------------------------------------------------------------
ALTER TABLE events    ADD CONSTRAINT events_severity_chk    CHECK (severity IN ('informational','low','medium','high','critical'));
ALTER TABLE alerts    ADD CONSTRAINT alerts_severity_chk    CHECK (severity IN ('informational','low','medium','high','critical'));
ALTER TABLE alerts    ADD CONSTRAINT alerts_status_chk      CHECK (status   IN ('new','assigned','closed','promoted'));
ALTER TABLE incidents ADD CONSTRAINT incidents_severity_chk CHECK (severity IN ('informational','low','medium','high','critical'));
ALTER TABLE incidents ADD CONSTRAINT incidents_stage_chk    CHECK (stage    IN ('new','triage','investigating','contained','closed'));
ALTER TABLE tenants   ADD CONSTRAINT tenants_isolation_chk  CHECK (isolation_tier IN ('pooled','dedicated','sovereign'));
ALTER TABLE tenants   ADD CONSTRAINT tenants_tier_chk       CHECK (service_tier   IN ('essential','standard','advanced','critical','enterprise'));
ALTER TABLE tenants   ADD CONSTRAINT tenants_status_chk     CHECK (status   IN ('onboarding','active','suspended'));
ALTER TABLE users     ADD CONSTRAINT users_role_chk         CHECK (role IN ('platform_admin','soc_manager','analyst_t1','analyst_t2','analyst_t3','detection_engineer','customer_admin','customer_viewer'));
ALTER TABLE users     ADD CONSTRAINT users_status_chk       CHECK (status IN ('active','disabled'));

-- ---------------------------------------------------------------------------
-- Detection rules (SRS §6.6). Global rules (tenant_id NULL) apply to all tenants;
-- tenants may add their own. Seed BEFORE forcing RLS so the global rows insert.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
  id          uuid PRIMARY KEY,
  tenant_id   uuid,                       -- NULL = global
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  severity    text NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
  confidence  int  NOT NULL DEFAULT 50,
  mitre       text[] NOT NULL DEFAULT '{}',
  condition   jsonb NOT NULL DEFAULT '{}',
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS detection_rules_enabled ON detection_rules (enabled);

GRANT SELECT, INSERT, UPDATE, DELETE ON detection_rules TO nirvet_app;

-- Seed the initial global detection catalogue (doc 04 §6).
INSERT INTO detection_rules (id, tenant_id, name, description, severity, confidence, mitre, condition) VALUES
 (gen_random_uuid(), NULL, 'Ransomware behaviour',
  'Encryption/rename activity indicative of ransomware.', 'critical', 90, ARRAY['T1486'],
  '{"any":[{"field":"action","op":"eq","value":"file_encrypt"},{"field":"activity_name","op":"contains","value":"ransom"},{"field":"class_name","op":"contains","value":"ransom"}]}'),
 (gen_random_uuid(), NULL, 'Malware detected',
  'Endpoint/EDR malware detection.', 'high', 80, ARRAY['TA0002'],
  '{"all":[{"field":"class_name","op":"contains","value":"malware"}]}'),
 (gen_random_uuid(), NULL, 'Compromised identity / credential access',
  'Credential theft, impossible travel, or MFA anomaly.', 'high', 75, ARRAY['TA0006'],
  '{"any":[{"field":"class_name","op":"contains","value":"credential"},{"field":"class_name","op":"contains","value":"identity"},{"field":"activity_name","op":"contains","value":"mfa"},{"field":"activity_name","op":"contains","value":"impossible"}]}'),
 (gen_random_uuid(), NULL, 'Suspicious mailbox forwarding',
  'Mailbox forwarding rule to external address (BEC).', 'high', 70, ARRAY['TA0009'],
  '{"any":[{"field":"action","op":"contains","value":"forward"},{"field":"class_name","op":"contains","value":"forwarding"}]}'),
 (gen_random_uuid(), NULL, 'Malicious outbound connection',
  'Connection to a known-bad IP/domain (C2).', 'medium', 65, ARRAY['TA0011'],
  '{"any":[{"field":"outcome","op":"eq","value":"malicious"},{"field":"action","op":"contains","value":"c2"},{"field":"class_name","op":"contains","value":"command and control"}]}')
ON CONFLICT DO NOTHING;

-- Now enforce RLS: tenants read global + own; may write only their own.
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON detection_rules;
CREATE POLICY tenant_isolation ON detection_rules
  USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)
  WITH CHECK (tenant_id = app_current_tenant());
