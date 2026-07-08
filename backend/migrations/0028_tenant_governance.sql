-- Tenant profile & governance (SRS §6.1: TEN-004 status lifecycle, TEN-006 org profile /
-- escalation matrix / business hours / authority-to-act policy, TEN-010 change history).
--
-- Owner rule: NO hardcoding — every policy is an admin-configurable row with a SEEDED
-- DEFAULT (the default lives in data, overridable via the admin API), never a code constant.
-- These config tables are tenant-scoped (RLS FORCE): a customer_admin manages their own
-- tenant's config; a platform_admin manages any tenant via the tenant context. The tenants
-- registry itself stays platform-level.

-- TEN-004: widen the status lifecycle vocabulary (was onboarding/active/suspended).
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_status_chk;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_chk
  CHECK (status IN ('prospect','onboarding','active','suspended','churned','archived','legal_hold'));

-- TEN-006: per-tenant org profile (1 row/tenant). Timezone + business hours + legal/regulatory
-- profile + critical-asset notes. business_hours is JSONB so the weekly schedule is fully
-- admin-configurable; the column DEFAULT is the seeded default (data, not code).
CREATE TABLE IF NOT EXISTS tenant_profiles (
  tenant_id       uuid PRIMARY KEY DEFAULT app_current_tenant(),
  timezone        text  NOT NULL DEFAULT 'UTC',
  business_hours  jsonb NOT NULL DEFAULT
    '{"mon":["09:00","17:00"],"tue":["09:00","17:00"],"wed":["09:00","17:00"],"thu":["09:00","17:00"],"fri":["09:00","17:00"]}',
  legal_regulatory jsonb NOT NULL DEFAULT '{}',   -- { jurisdiction, frameworks[], data_residency }
  critical_assets_notes text NOT NULL DEFAULT '',
  updated_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_profiles;
CREATE POLICY tenant_isolation ON tenant_profiles
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_profiles TO nirvet_app;

-- TEN-006: escalation matrix — ordered contacts that fire at/above a severity, over a channel.
-- §6.16 notification routing consumes this (later slice).
CREATE TABLE IF NOT EXISTS escalation_contacts (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  name         text NOT NULL,
  role         text NOT NULL DEFAULT '',
  min_severity text NOT NULL DEFAULT 'high' CHECK (min_severity IN ('informational','low','medium','high','critical')),
  order_index  int  NOT NULL DEFAULT 0,       -- escalation order (0 first)
  channel      text NOT NULL DEFAULT 'email'  CHECK (channel IN ('email','sms','webhook','teams','slack')),
  address      text NOT NULL,                 -- email / phone / url per channel
  active       boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS escalation_contacts_tenant ON escalation_contacts (tenant_id, min_severity, order_index);
ALTER TABLE escalation_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_contacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON escalation_contacts;
CREATE POLICY tenant_isolation ON escalation_contacts
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON escalation_contacts TO nirvet_app;

-- TEN-006 / SOAR-003: authority-to-act policy. Per action-type (or '*' catch-all), the mode
-- decides whether a response action may run and whether it needs approval. §6.11 SOAR consumes
-- this (later slice). The SEEDED DEFAULT is FAIL-CLOSED ('*' => approval), so an unconfigured
-- tenant can never auto-execute a high-impact action (NFR-009).
CREATE TABLE IF NOT EXISTS authority_policies (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL DEFAULT app_current_tenant(),
  action_type        text NOT NULL DEFAULT '*',  -- '*' = catch-all; else e.g. isolate_endpoint, disable_user
  mode               text NOT NULL DEFAULT 'approval'
                       CHECK (mode IN ('observe','approval','pre_authorized','emergency')),
  approver_role      text NOT NULL DEFAULT '',   -- '' = any senior approver
  business_hours_only boolean NOT NULL DEFAULT false,
  active             boolean NOT NULL DEFAULT true,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, action_type)
);
ALTER TABLE authority_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON authority_policies;
CREATE POLICY tenant_isolation ON authority_policies
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON authority_policies TO nirvet_app;

-- TEN-010: append-only tenant change history for material settings changes. Insert-only
-- (mirrors audit_log 0017/0024): UPDATE/DELETE raise, so history cannot be rewritten.
CREATE TABLE IF NOT EXISTS tenant_change_history (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  actor_id     uuid,
  actor_email  text NOT NULL DEFAULT '',
  entity       text NOT NULL,               -- profile | status | escalation | authority
  field        text NOT NULL DEFAULT '',
  old_value    text NOT NULL DEFAULT '',
  new_value    text NOT NULL DEFAULT '',
  at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenant_change_history_tenant ON tenant_change_history (tenant_id, at DESC);
ALTER TABLE tenant_change_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_change_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_change_history;
CREATE POLICY tenant_isolation ON tenant_change_history
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON tenant_change_history TO nirvet_app;   -- no UPDATE/DELETE grant

CREATE OR REPLACE FUNCTION tenant_change_history_no_mutate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'tenant_change_history is append-only (TEN-010)';
END; $$;
DROP TRIGGER IF EXISTS tenant_change_history_immutable ON tenant_change_history;
CREATE TRIGGER tenant_change_history_immutable
  BEFORE UPDATE OR DELETE ON tenant_change_history
  FOR EACH ROW EXECUTE FUNCTION tenant_change_history_no_mutate();

-- Seed defaults for EXISTING tenants (runs as the migration superuser, bypassing RLS): every
-- tenant gets a profile row and the fail-closed catch-all authority policy. New tenants get
-- these seeded in tenant.Create's transaction.
INSERT INTO tenant_profiles (tenant_id)
  SELECT id FROM tenants ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO authority_policies (id, tenant_id, action_type, mode)
  SELECT gen_random_uuid(), id, '*', 'approval' FROM tenants
  ON CONFLICT (tenant_id, action_type) DO NOTHING;
