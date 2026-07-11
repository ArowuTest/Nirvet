-- 0093_session_generation.sql — platform session revocation (§6.2, HEAVY).
-- A monotonic session GENERATION per user and per tenant. A JWT is stamped with the generation it was minted at;
-- the per-request check (iam.CheckSession) rejects a token whose generation is behind current. Bumping the
-- generation (on password change/reset, break-glass revoke, offboard) immediately invalidates all older tokens —
-- closing the "nothing kills a live stateless-JWT session" gap. Absent row = generation 0 (in-flight tokens at
-- deploy stamp gen 0 and stay valid until the first bump — backward compatible).

-- Per-user generation (user boundary): bumped on that user's password change/reset, break-glass revoke, disable.
CREATE TABLE IF NOT EXISTS user_session_state (
  tenant_id  uuid   NOT NULL DEFAULT app_current_tenant(),
  user_id    uuid   NOT NULL,
  generation bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
ALTER TABLE user_session_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_session_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON user_session_state;
CREATE POLICY tenant_isolation ON user_session_state
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON user_session_state TO nirvet_app;

-- Per-tenant generation (tenant boundary): one O(1) atomic bump kills EVERY session in the tenant (offboard).
-- Avoids per-user enumeration (O(users)) and its race with a user created mid-offboard.
CREATE TABLE IF NOT EXISTS tenant_session_state (
  tenant_id  uuid   PRIMARY KEY DEFAULT app_current_tenant(),
  generation bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_session_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_session_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_session_state;
CREATE POLICY tenant_isolation ON tenant_session_state
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_session_state TO nirvet_app;

-- Revocation-latency SLA as seeded config (no-hardcoding): the check cache TTL. A sovereign can tighten it.
-- The auditor number: terminated/compromised users are revoked IMMEDIATELY (cache-bust on disable/break-glass/
-- offboard); routine credential changes propagate within cache_ttl_seconds.
CREATE TABLE IF NOT EXISTS session_revocation_config (
  scope             text PRIMARY KEY DEFAULT 'global',
  cache_ttl_seconds int  NOT NULL DEFAULT 30,
  updated_at        timestamptz NOT NULL DEFAULT now()
);
INSERT INTO session_revocation_config (scope) VALUES ('global') ON CONFLICT (scope) DO NOTHING;
GRANT SELECT, UPDATE ON session_revocation_config TO nirvet_app;

-- TOMBSTONE INVARIANT: generation rows must SURVIVE a purge — otherwise the purge (which reads the current
-- generation as absent→0) would REVIVE tokens that were correctly revoked (e.g. an offboarded tenant's token with
-- tgen 5 < 6 would pass 5 ≥ 0). The uniform tenant-offboard purge (mig 0073) dynamically enumerates every table
-- with a tenant_id column, so it WOULD delete user_session_state + tenant_session_state. Re-define it to EXCLUDE
-- both generation tables (they are tiny — (id, bigint) — so retaining them permanently is the cheapest possible
-- guarantee that revoked-stays-revoked). The invariant is general: any future user-purge must likewise never
-- hard-delete a generation row while a pre-bump token could still be within its exp.
-- Preserves the full 0075 guard chain (not-found → legal_hold → exported-state → retention-elapsed) VERBATIM —
-- this replace ONLY widens the retain-list with the two generation tombstone tables. Do not drop a guard here.
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
       -- retain the tenant row + destruction evidence + the session-revocation TOMBSTONES (revoked-stays-revoked)
       AND table_name NOT IN ('tenants', 'tenant_offboarding', 'user_session_state', 'tenant_session_state')
  LOOP
    EXECUTE format('DELETE FROM %I WHERE tenant_id = $1', r.table_name) USING p_tenant;
    n := n + 1;
  END LOOP;
  RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION tenant_offboard_purge(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_offboard_purge(uuid) TO nirvet_app;
