-- §6.18 #122 P-3 — tenant lifecycle + UNIFORM offboarding (ADMIN-005 / TEN-009). legal_hold is an orthogonal
-- boolean (a tenant can be active AND on hold — it is an evidence-preservation flag, not a lifecycle state), and
-- deletion is ONE uniform routine that dynamically enumerates every tenant-scoped table (not per-table FK cascade —
-- for a retention/compliance SOC that is the wrong posture). Dynamic enumeration means the routine can never silently
-- miss a new tenant-scoped table as the schema grows.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS legal_hold boolean NOT NULL DEFAULT false;
-- Extend the status set with the offboarding terminal states (exported, deleted).
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_status_chk;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_chk
  CHECK (status IN ('onboarding','active','suspended','exported','deleted'));

-- Offboarding evidence trail — append-only (certificate of destruction, hold set/clear). Immutable like the config
-- audit: a purge/hold record is evidence and must not be rewritten.
CREATE TABLE IF NOT EXISTS tenant_offboarding (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL,
  action        text NOT NULL,              -- legal_hold_set | legal_hold_clear | delete
  tables_purged int  NOT NULL DEFAULT 0,
  cert_sha256   text NOT NULL DEFAULT '',   -- certificate of destruction (delete action)
  actor_id      uuid,
  reason        text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_offboarding_action_chk CHECK (action IN ('legal_hold_set','legal_hold_clear','delete'))
);
REVOKE UPDATE, DELETE, TRUNCATE ON tenant_offboarding FROM nirvet_app;
CREATE OR REPLACE FUNCTION tenant_offboarding_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'tenant_offboarding is append-only (immutable); % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS tenant_offboarding_no_mutate ON tenant_offboarding;
CREATE TRIGGER tenant_offboarding_no_mutate
  BEFORE UPDATE OR DELETE ON tenant_offboarding
  FOR EACH ROW EXECUTE FUNCTION tenant_offboarding_immutable();
GRANT SELECT, INSERT ON tenant_offboarding TO nirvet_app;

-- The uniform offboarding purge (SECURITY DEFINER — must bypass RLS to delete a tenant's rows across all tables).
-- REFUSES if the tenant is on legal_hold (an evidence-preservation control). Dynamically enumerates every table with
-- a tenant_id column (except tenants itself, which is retained + marked deleted) and deletes the target's rows.
-- session_replication_role=replica (owner is superuser) disables FK triggers so purge order is irrelevant.
CREATE OR REPLACE FUNCTION tenant_offboard_purge(p_tenant uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r record;
  n int := 0;
  held boolean;
BEGIN
  SELECT legal_hold INTO held FROM tenants WHERE id = p_tenant;
  IF held IS TRUE THEN
    RAISE EXCEPTION 'tenant % is on legal hold; purge refused', p_tenant;
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
