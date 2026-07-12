-- §6.14 #188 HEAVY-3 — retention enforcement. The ONLY launch feature that DELETES customer telemetry, so it is
-- config-first + fail-safe toward KEEPING + safe-default (dry-run until a tenant explicitly enables live deletion).
--
--   * retention_policy — per-tenant (NULL=global default) switch. enabled DEFAULT false (dry-run/report-only).
--       window_days is an OPTIONAL, TIGHTEN-ONLY override: the effective window is min(window_days, entitlement
--       retention_days); the entitlement is the ceiling, a tenant may only ask to keep telemetry for LESS.
--   * retention_sweep_log — append-only record of EVERY sweep (incl. dry-runs), so a tenant sees what WOULD be
--       deleted before enabling.
--
-- Deletes ONLY raw telemetry: raw_events (+ its blob_uri payload blob in the object store — the raw payload else
-- lingers past retention; evidence-pack blobs are a DIFFERENT set and are preserved) and the normalized `events`
-- projection. It NEVER touches alerts/incidents/evidence/audit. ClickHouse ages out via its own PARTITION+TTL (#160)
-- — one owner per store (note: the global CH TTL is not per-tenant; a strict per-tenant window on CH is a
-- scale-phase item, called out in build/ARCHITECTURE_GATES.md).

CREATE TABLE IF NOT EXISTS retention_policy (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid,                                          -- NULL = global default
  enabled     boolean NOT NULL DEFAULT false,                -- false = dry-run/report-only (SAFE default)
  window_days int,                                           -- NULL = use the entitlement window; else TIGHTEN-ONLY
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT retention_window_chk CHECK (window_days IS NULL OR (window_days BETWEEN 1 AND 3650))
);
CREATE UNIQUE INDEX IF NOT EXISTS retention_policy_tenant_uq
  ON retention_policy (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

ALTER TABLE retention_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retention_policy_select ON retention_policy;
DROP POLICY IF EXISTS retention_policy_insert ON retention_policy;
DROP POLICY IF EXISTS retention_policy_update ON retention_policy;
CREATE POLICY retention_policy_select ON retention_policy
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY retention_policy_insert ON retention_policy
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY retention_policy_update ON retention_policy
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON retention_policy TO nirvet_app;

INSERT INTO retention_policy (tenant_id, enabled) VALUES (NULL, false) ON CONFLICT DO NOTHING;

-- Append-only sweep log (dry-run rows too).
CREATE TABLE IF NOT EXISTS retention_sweep_log (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL,
  store           text NOT NULL,                             -- raw_events | events
  cutoff          timestamptz NOT NULL,
  candidate_count bigint NOT NULL DEFAULT 0,
  deleted_count   bigint NOT NULL DEFAULT 0,
  dry_run         boolean NOT NULL,
  at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS retention_sweep_log_tenant_at ON retention_sweep_log (tenant_id, at DESC);

ALTER TABLE retention_sweep_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_sweep_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS retention_sweep_log_select ON retention_sweep_log;
DROP POLICY IF EXISTS retention_sweep_log_insert ON retention_sweep_log;
CREATE POLICY retention_sweep_log_select ON retention_sweep_log
  FOR SELECT USING (tenant_id = app_current_tenant());
CREATE POLICY retention_sweep_log_insert ON retention_sweep_log
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON retention_sweep_log TO nirvet_app;

-- Age `events` by collected_at (INGEST time — deterministic, not the source occurred/observed time). Index it so the
-- sweep is not a full scan (raw_events already has raw_events_tenant_received on received_at, mig 0053).
CREATE INDEX IF NOT EXISTS events_tenant_collected ON events (tenant_id, collected_at);

-- raw_events + events are APPEND-ONLY evidence: a BEFORE DELETE trigger (evidence_no_delete, mig 0024) blocks
-- deletion for EVERYONE (anti-tamper) and DELETE is REVOKEd from nirvet_app. Retention is a GOVERNED, audited,
-- policy-driven aging — a different thing from tampering — so it deletes through controlled SECURITY DEFINER
-- functions, exactly like the offboard purge (mig 0073): SET LOCAL session_replication_role='replica' disables the
-- immutability trigger for THIS path only, the function REFUSES on legal_hold (defense-in-depth over the Go check),
-- scopes strictly to the passed tenant + telemetry tables, and is REVOKE PUBLIC + GRANT nirvet_app (SD-revoke
-- fenced). The normal app path stays blocked — evidence immutability is intact for everything except this fenced
-- retention sweep.

CREATE OR REPLACE FUNCTION retention_delete_raw(p_tenant uuid, p_ids uuid[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n int; held boolean;
BEGIN
  SELECT legal_hold INTO held FROM tenants WHERE id = p_tenant;
  IF held IS TRUE THEN
    RAISE EXCEPTION 'tenant % is on legal hold; retention delete refused', p_tenant;
  END IF;
  SET LOCAL session_replication_role = 'replica';   -- bypass evidence_no_delete for the governed retention path
  DELETE FROM raw_events WHERE tenant_id = p_tenant AND id = ANY(p_ids);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END; $$;
REVOKE ALL ON FUNCTION retention_delete_raw(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION retention_delete_raw(uuid, uuid[]) TO nirvet_app;

CREATE OR REPLACE FUNCTION retention_delete_events(p_tenant uuid, p_cutoff timestamptz, p_limit int) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n int; held boolean;
BEGIN
  SELECT legal_hold INTO held FROM tenants WHERE id = p_tenant;
  IF held IS TRUE THEN
    RAISE EXCEPTION 'tenant % is on legal hold; retention delete refused', p_tenant;
  END IF;
  SET LOCAL session_replication_role = 'replica';
  DELETE FROM events
   WHERE tenant_id = p_tenant
     AND id IN (SELECT id FROM events WHERE tenant_id = p_tenant AND collected_at < p_cutoff ORDER BY collected_at LIMIT p_limit);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END; $$;
REVOKE ALL ON FUNCTION retention_delete_events(uuid, timestamp with time zone, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION retention_delete_events(uuid, timestamp with time zone, integer) TO nirvet_app;
