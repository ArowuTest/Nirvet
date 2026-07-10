-- 0083_fleet_read.sql — Ghana operator seam #1: the bounded cross-tenant fleet READ primitive (MA-1).
--
-- fleet_alerts() is the operator fleet console's cross-tenant read of the alert queue, and the SINGLE
-- highest-consequence function in the operator reframe: a bug that returns rows outside the requested
-- tenant-set is a full cross-tenant breach.
--
-- WHY THE PREDICATE IS THE ONLY GUARD (the FORCE/BYPASSRLS interaction, stated and true):
--   `alerts` is ENABLE + FORCE ROW LEVEL SECURITY (RLS applies even to the table owner). This function is
--   SECURITY DEFINER and is created here by the migration role `postgres`, so it EXECUTES AS postgres.
--   postgres is a SUPERUSER, and superusers BYPASS RLS unconditionally — FORCE does not apply to a superuser.
--   Therefore RLS provides ZERO protection inside this function, and `tenant_id = ANY(p_tenant_ids)` is the
--   ONLY tenant guard. The MA-1 contract this function MUST hold:
--     * FAIL CLOSED — an empty or NULL tenant-set returns ZERO rows, never all tenants. (belt: explicit
--       cardinality guard; suspenders: `x = ANY('{}')` is FALSE and `x = ANY(NULL)` is NULL — both exclude.)
--     * BOUND ARRAY — p_tenant_ids is a uuid[] BIND parameter, never string-interpolated.
--     * MINIMAL — NO business logic in the definer boundary: only the scoped SELECT + a hard row cap.
--     * REVOKE PUBLIC + GRANT nirvet_app (CI-guarded by scripts/check-security-definer-revoke.sh).
--   The tenant-set is resolved from the AUTHENTICATED PRINCIPAL in Go (the scope-resolver), never from client
--   input; this function only enforces the bound.

CREATE OR REPLACE FUNCTION fleet_alerts(p_tenant_ids uuid[], p_status text, p_limit int)
RETURNS SETOF alerts
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT *
    FROM alerts
   WHERE cardinality(coalesce(p_tenant_ids, ARRAY[]::uuid[])) > 0   -- MA-1 fail-closed: empty/NULL scope -> 0 rows
     AND tenant_id = ANY(p_tenant_ids)                              -- MA-1 the ONLY tenant guard
     AND (p_status = '' OR status = p_status)
   ORDER BY created_at DESC
   LIMIT least(greatest(coalesce(p_limit, 100), 1), 500);          -- MA-1 hard cap (bounded read)
$$;

REVOKE ALL ON FUNCTION fleet_alerts(uuid[], text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_alerts(uuid[], text, int) TO nirvet_app;
