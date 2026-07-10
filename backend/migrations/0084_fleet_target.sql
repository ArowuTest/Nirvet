-- 0084_fleet_target.sql — operator WRITE path (MA-2/3): bounded target-tenant resolution.
--
-- The write path is the highest-consequence surface in the reframe: a wrong target = a containment/SOAR action
-- fired on the WRONG government agency. fleet_alert_tenant() is its foundation — it resolves the TARGET tenant
-- of a fleet write from the RESOURCE (the alert's own tenant_id) AND enforces the operator's fleet-scope bound
-- in ONE fail-closed step:
--   * TARGET-FROM-RESOURCE (reviewer #1): the returned tenant is the ALERT ROW's tenant_id — never p.TenantID,
--     never a client-supplied id. A forged/mismatched body id cannot redirect the write to another tenant,
--     because the tenant is read from the row keyed by the alert id.
--   * FLEET-SCOPE CHECK (reviewer #2): it returns the tenant ONLY IF that tenant is inside the caller's
--     resolved fleet scope; otherwise NULL (→ the Go layer refuses the write). Fail-closed on empty/NULL scope
--     (a non-provider's empty scope → NULL for every alert → NO write path at all).
-- Same SD-fn discipline as fleet_alerts (mig 0083): superuser definer → RLS inert → `tenant_id = ANY($set)` is
-- the only guard; bound uuid[]; minimal; SET search_path; REVOKE PUBLIC + GRANT nirvet_app.

CREATE OR REPLACE FUNCTION fleet_alert_tenant(p_alert_id uuid, p_tenant_ids uuid[])
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT a.tenant_id
    FROM alerts a
   WHERE a.id = p_alert_id
     AND cardinality(coalesce(p_tenant_ids, ARRAY[]::uuid[])) > 0  -- fail-closed: empty/NULL scope -> no target
     AND a.tenant_id = ANY(p_tenant_ids);                          -- the ONLY scope guard; target FROM the row
$$;

REVOKE ALL ON FUNCTION fleet_alert_tenant(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_alert_tenant(uuid, uuid[]) TO nirvet_app;
