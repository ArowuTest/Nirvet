-- §6.18 #122 H-1 (reviewer landing High) — the irreversible total-tenant purge was gated WEAKER than the lesser
-- action beside it (clearing legal hold has senior+four-eyes; offboard had a single padmin + reason). The four-eyes
-- envelope is added in the service; THIS migration adds the state-machine + retention gate as DEFENSE IN DEPTH inside
-- the SECURITY DEFINER purge function itself — so a purge is un-bypassable even by a direct DB call (same posture as
-- the existing legal_hold check). A tenant may only be purged from the 'exported' state, and only after its retention
-- window (per-tenant, admin-configurable, seeded default) has elapsed — never straight from 'active'/'suspended'.

-- Offboard-grace state: when a tenant's data was exported (retention clock starts) and the per-tenant grace window
-- before destruction (a contract term — admin-settable, seeded default; NOT a code constant).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS exported_at timestamptz;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS offboard_retention_days int NOT NULL DEFAULT 30;

-- Record the export step in the append-only offboarding evidence trail.
ALTER TABLE tenant_offboarding DROP CONSTRAINT IF EXISTS tenant_offboarding_action_chk;
ALTER TABLE tenant_offboarding ADD CONSTRAINT tenant_offboarding_action_chk
  CHECK (action IN ('legal_hold_set','legal_hold_clear','export','delete'));

-- Re-create the purge with the state+retention gate BEFORE the legal_hold gate stays first (evidence preservation is
-- the most important refusal). Order: legal_hold → exported-state → retention-elapsed → purge.
CREATE OR REPLACE FUNCTION tenant_offboard_purge(p_tenant uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r record;
  n int := 0;
  t_status    text;
  t_held      boolean;
  t_exported  timestamptz;
  t_retention int;
BEGIN
  SELECT status, legal_hold, exported_at, offboard_retention_days
    INTO t_status, t_held, t_exported, t_retention
    FROM tenants WHERE id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant % not found; purge refused', p_tenant;
  END IF;
  IF t_held IS TRUE THEN
    RAISE EXCEPTION 'tenant % is on legal hold; purge refused', p_tenant;
  END IF;
  IF t_status IS DISTINCT FROM 'exported' THEN
    RAISE EXCEPTION 'tenant % is not in the exported state (status=%); purge refused', p_tenant, t_status;
  END IF;
  IF t_exported IS NULL OR (t_exported + make_interval(days => t_retention)) > now() THEN
    RAISE EXCEPTION 'tenant % retention window has not elapsed; purge refused', p_tenant;
  END IF;
  SET LOCAL session_replication_role = 'replica';  -- FK-order independent purge
  FOR r IN
    SELECT table_name FROM information_schema.columns
     WHERE column_name = 'tenant_id' AND table_schema = 'public'
       AND table_name NOT IN ('tenants', 'tenant_offboarding')  -- retain the tenant row + the destruction evidence trail
  LOOP
    EXECUTE format('DELETE FROM %I WHERE tenant_id = $1', r.table_name) USING p_tenant;
    n := n + 1;
  END LOOP;
  RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION tenant_offboard_purge(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_offboard_purge(uuid) TO nirvet_app;
