-- §6.12 #117 A-4 fix — permit a platform admin (system context, app_current_tenant() IS NULL) to write the GLOBAL
-- ai_provider row (tenant_id NULL). The 0067 insert/update WITH CHECK (tenant_id = app_current_tenant()) rejects a
-- NULL-tenant row because `NULL = NULL` evaluates to NULL (not true), so WithSystem — which sets NO tenant GUC and
-- does NOT bypass RLS (nirvet_app is non-BYPASSRLS) — cannot insert/update the global default. Widen the write
-- policy to also allow the global row ONLY when the caller is in system context (app_current_tenant() IS NULL).
--
-- This is safe: a tenant request always runs under WithTenant, so app_current_tenant() = that tenant (never NULL),
-- and the added disjunct `tenant_id IS NULL AND app_current_tenant() IS NULL` can never be true for it — a tenant
-- still can only write its own row and can never write or forge the global row. Only platform-admin handlers reach
-- WithSystem (padmin RBAC), which is where the global default is set.

DROP POLICY IF EXISTS ai_provider_insert ON ai_provider;
DROP POLICY IF EXISTS ai_provider_update ON ai_provider;

CREATE POLICY ai_provider_insert ON ai_provider
  FOR INSERT WITH CHECK (
    tenant_id = app_current_tenant()
    OR (tenant_id IS NULL AND app_current_tenant() IS NULL)
  );

CREATE POLICY ai_provider_update ON ai_provider
  FOR UPDATE
  USING (
    tenant_id = app_current_tenant()
    OR (tenant_id IS NULL AND app_current_tenant() IS NULL)
  )
  WITH CHECK (
    tenant_id = app_current_tenant()
    OR (tenant_id IS NULL AND app_current_tenant() IS NULL)
  );
