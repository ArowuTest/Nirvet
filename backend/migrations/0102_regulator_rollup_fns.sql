-- 0102_regulator_rollup_fns.sql
-- Customer read-model Slice A: the REGULATOR audience's metadata-only cross-tenant read path. Mirrors the MA4-2
-- tenant_posture_fleet pattern (0085): a dedicated SECURITY DEFINER function, bound to an explicit tenant-id
-- array, fail-closed on empty/NULL scope, REVOKE PUBLIC + GRANT nirvet_app. Read under WithSystem so the ONLY
-- way to reach cross-tenant rows is through this fail-closed function.
--
-- CRITICAL (reviewer invariant 5): these functions return ONLY low-cardinality metadata columns — category /
-- severity / stage / status and computed SLA-breach booleans. They NEVER return a title, note, actor, or any
-- content/PII column. The regulator physically cannot receive incident content, because the query does not
-- select a content column. Breach is computed here to match internal/incident/sla.go computeBreach exactly.

CREATE OR REPLACE FUNCTION incident_meta_for_tenants(p_tenant_ids uuid[])
RETURNS TABLE (category text, severity text, stage text, ack_breached boolean, resolve_breached boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    category,
    severity,
    stage,
    (ack_due_at IS NOT NULL
       AND ((acknowledged_at IS NOT NULL AND acknowledged_at > ack_due_at)
            OR (acknowledged_at IS NULL AND now() > ack_due_at)))                        AS ack_breached,
    (resolve_due_at IS NOT NULL
       AND ((closed_at IS NOT NULL AND closed_at > resolve_due_at)
            OR (closed_at IS NULL AND now() > resolve_due_at)))                          AS resolve_breached
  FROM incidents
  WHERE cardinality(coalesce(p_tenant_ids, ARRAY[]::uuid[])) > 0   -- fail-closed: empty/NULL scope -> 0 rows
    AND tenant_id = ANY(p_tenant_ids)                              -- the ONLY tenant guard
  LIMIT 100000;
$$;
REVOKE ALL ON FUNCTION incident_meta_for_tenants(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION incident_meta_for_tenants(uuid[]) TO nirvet_app;

CREATE OR REPLACE FUNCTION alert_meta_for_tenants(p_tenant_ids uuid[])
RETURNS TABLE (severity text, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT severity, status
  FROM alerts
  WHERE cardinality(coalesce(p_tenant_ids, ARRAY[]::uuid[])) > 0   -- fail-closed: empty/NULL scope -> 0 rows
    AND tenant_id = ANY(p_tenant_ids)
  LIMIT 500000;
$$;
REVOKE ALL ON FUNCTION alert_meta_for_tenants(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION alert_meta_for_tenants(uuid[]) TO nirvet_app;
