-- Split the detection_rules RLS policy per command (R3 global-rule RLS).
--
-- The original single policy (0002) had no FOR clause, so its
--   USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)
-- applied to EVERY command — including the row-selection side of UPDATE and DELETE.
-- That made the shared GLOBAL catalogue (tenant_id IS NULL) targetable by a tenant:
--   * DELETE: a tenant could delete a global rule for everyone (no WITH CHECK on DELETE).
--   * UPDATE: a tenant could re-home a global rule into its own tenant (USING allowed the
--     NULL row as a target; WITH CHECK passed once tenant_id was set to their own),
--     silently removing it from the global catalogue for all other tenants.
-- Reads legitimately need global + own; writes must be own-tenant only. Per-command
-- policies express exactly that. (Only nirvet_app is constrained — migrations run as the
-- superuser owner, which bypasses RLS, so the seeded global rows are unaffected.)

ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation          ON detection_rules;
DROP POLICY IF EXISTS detection_rules_select     ON detection_rules;
DROP POLICY IF EXISTS detection_rules_insert     ON detection_rules;
DROP POLICY IF EXISTS detection_rules_update     ON detection_rules;
DROP POLICY IF EXISTS detection_rules_delete     ON detection_rules;

-- Read: the global catalogue (tenant_id IS NULL) plus the tenant's own rules.
CREATE POLICY detection_rules_select ON detection_rules
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);

-- Insert: own-tenant rows only. The app role can never create a global rule (those are
-- seeded by migrations); WITH CHECK rejects a NULL or foreign tenant_id.
CREATE POLICY detection_rules_insert ON detection_rules
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());

-- Update: own rows only, and cannot be re-homed. Global rows are invisible as targets
-- (USING excludes NULL), so a tenant cannot steal or alter the shared catalogue.
CREATE POLICY detection_rules_update ON detection_rules
  FOR UPDATE USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

-- Delete: own rows only — the global catalogue cannot be deleted by a tenant.
CREATE POLICY detection_rules_delete ON detection_rules
  FOR DELETE USING (tenant_id = app_current_tenant());
