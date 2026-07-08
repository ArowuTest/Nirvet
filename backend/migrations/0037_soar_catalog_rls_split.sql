-- Round-4 L1: split the soar_action_catalog RLS policy per command (same fix as 0026 for
-- detection_rules). Migration 0036 shipped a single policy
--   USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)
-- with a blanket WITH CHECK, so its USING applied to the row-selection side of UPDATE and DELETE —
-- making the shared GLOBAL catalogue (tenant_id IS NULL) targetable by a tenant:
--   * DELETE: a tenant could delete a global action row for everyone.
--   * UPDATE: a tenant could re-home a global row into its own tenant (USING allowed the NULL row
--     as a target; WITH CHECK passed once tenant_id was set to their own).
-- Reads legitimately need global + own; writes must be own-tenant only. (Latent today — no handler
-- issues a raw DELETE/rehome and catalog-absence fails closed to business_critical — but closed now.)

ALTER TABLE soar_action_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_action_catalog FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation           ON soar_action_catalog;
DROP POLICY IF EXISTS soar_action_catalog_select  ON soar_action_catalog;
DROP POLICY IF EXISTS soar_action_catalog_insert  ON soar_action_catalog;
DROP POLICY IF EXISTS soar_action_catalog_update  ON soar_action_catalog;
DROP POLICY IF EXISTS soar_action_catalog_delete  ON soar_action_catalog;

-- Read: the global default catalogue (tenant_id IS NULL) plus the tenant's own overrides.
CREATE POLICY soar_action_catalog_select ON soar_action_catalog
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);

-- Insert/Update/Delete: own-tenant rows only. Global rows are seeded by migrations (run as the
-- superuser owner, which bypasses RLS) and are invisible as write targets to the app role, so a
-- tenant can neither create a global row, nor re-home/alter/delete the shared catalogue.
CREATE POLICY soar_action_catalog_insert ON soar_action_catalog
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY soar_action_catalog_update ON soar_action_catalog
  FOR UPDATE USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY soar_action_catalog_delete ON soar_action_catalog
  FOR DELETE USING (tenant_id = app_current_tenant());

-- Round-4 L2: normalise any correlation policy that was set below the corroboration floor (>= 2) so
-- the service-level floor (SetCorrelationPolicy) is consistent with stored data. Seeded default is
-- already 2; this only heals a tenant that had lowered it to 1 before the floor was enforced.
UPDATE correlation_policies SET min_alerts_for_promotion = 2 WHERE min_alerts_for_promotion < 2;
