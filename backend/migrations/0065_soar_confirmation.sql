-- §6.11 SOAR completion reconciler (D-3): confirm a submitted containment ACTUALLY took effect. An async
-- MDE isolate is `executed` (accepted) the moment MDE returns a machineAction id; these columns carry whether
-- MDE later CONFIRMED it (terminal Succeeded). A Failed/Cancelled/TimeOut flips the row to `failed` (which
-- also drops it out of listReversibleExecutions — nothing to undo) and is alerted. SOAR-006/009.
ALTER TABLE soar_action_execution
  ADD COLUMN IF NOT EXISTS confirmed           boolean     NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS confirmation_status text        NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS confirmed_at         timestamptz;

-- Poll index: executed-but-unconfirmed rows.
CREATE INDEX IF NOT EXISTS soar_action_execution_unconfirmed
  ON soar_action_execution (status, claimed_at) WHERE NOT confirmed;

-- Operational thresholds (config-first, no-hardcoding; seeded defaults, platform-admin tunable): grace before
-- the first confirmation poll; stall = an action still non-terminal past this window is surfaced as stalled.
ALTER TABLE soar_platform
  ADD COLUMN IF NOT EXISTS confirmation_grace_secs int NOT NULL DEFAULT 60,
  ADD COLUMN IF NOT EXISTS confirmation_stall_secs int NOT NULL DEFAULT 900;

-- System-level list of executed, non-dry-run, unconfirmed, un-reversed connector actions WE CAUSED
-- (prior_state.changed = true — G-2; a foreign no-op is excluded), past the grace window. Mirrors
-- soar_stale_executions. Returns the BARE machineAction id from prior_state.action_id (G-1) — never the
-- display connector_ref — plus the age in seconds (DB clock is authoritative) for the stall check.
CREATE OR REPLACE FUNCTION soar_unconfirmed_executions(p_grace_secs int)
RETURNS TABLE (tenant_id uuid, id uuid, action_key text, connector_key text, target text, action_id text, age_secs int)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT tenant_id, id, action_key, connector_key, target,
         coalesce(prior_state->>'action_id', ''),
         extract(epoch FROM now() - claimed_at)::int
    FROM soar_action_execution
   WHERE status = 'executed' AND dry_run = false AND NOT confirmed AND NOT reversed
     AND connector_key <> ''
     AND (prior_state->>'changed')::boolean IS TRUE
     AND claimed_at < now() - make_interval(secs => p_grace_secs)
   ORDER BY claimed_at ASC
   LIMIT 500  -- bound each reconcile tick (oldest first); the remainder is picked up on the next tick
$$;
REVOKE ALL ON FUNCTION soar_unconfirmed_executions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION soar_unconfirmed_executions(int) TO nirvet_app;
