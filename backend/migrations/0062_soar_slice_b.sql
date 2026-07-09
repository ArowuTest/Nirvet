-- 0062_soar_slice_b.sql
-- §6.11 SOAR slice B: real containment executors. Durable two-phase execution (a connector step's
-- external effect cannot run inside the run's DB tx), a per-step supervisor cursor, per-tenant safety
-- config, and a global kill-switch. See build/ARCHITECTURE_GATES.md "§6.11 SOAR slice B DESIGN REVIEW".

-- Supervisor cursor: the run resumes from the last non-terminal step (MUST-2: step is the durable unit,
-- run is a supervisor). Default 0 keeps existing rows valid.
ALTER TABLE playbook_runs ADD COLUMN IF NOT EXISTS current_step int NOT NULL DEFAULT 0;

-- Durable record of one connector step's two-phase execution. The UNIQUE(run_id, step_index) is the
-- idempotency/claim key (MUST-1): Phase A inserts status='executing' exactly once; a crash re-drives at
-- Phase B (never re-runs Phase A). prior_state captures OBSERVED state in Phase B so reverse only undoes
-- what actually changed (MUST-3). run_id is a uuid so the composite is globally unique without tenant_id.
CREATE TABLE IF NOT EXISTS soar_action_execution (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL,
  run_id        uuid NOT NULL,
  step_index    int  NOT NULL,
  action_key    text NOT NULL,
  connector_key text NOT NULL DEFAULT '',
  target        text NOT NULL DEFAULT '',
  status        text NOT NULL CHECK (status IN ('executing','executed','failed','withheld')),
  reason        text NOT NULL DEFAULT '',      -- withhold/failure reason (MUST-4)
  params_hash   text NOT NULL DEFAULT '',
  prior_state   jsonb,                          -- observed state captured in Phase B (MUST-3)
  connector_ref text NOT NULL DEFAULT '',       -- vendor response reference
  dry_run       boolean NOT NULL DEFAULT false,
  reversed      boolean NOT NULL DEFAULT false,
  claimed_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, step_index)
);
CREATE INDEX IF NOT EXISTS soar_action_execution_stale ON soar_action_execution (status, claimed_at);
CREATE INDEX IF NOT EXISTS soar_action_execution_run   ON soar_action_execution (tenant_id, run_id);

ALTER TABLE soar_action_execution ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_action_execution FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_action_execution_rw ON soar_action_execution;
CREATE POLICY soar_action_execution_rw ON soar_action_execution
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON soar_action_execution TO nirvet_app;

-- SECURITY DEFINER reaper source: the supervisor runs at the system level (spans tenants) with no single
-- tenant GUC, so it reads stale 'executing' rows through this function (raw_events reconciler pattern).
CREATE OR REPLACE FUNCTION soar_stale_executions(p_visibility_secs int)
RETURNS TABLE (tenant_id uuid, run_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT DISTINCT tenant_id, run_id FROM soar_action_execution
  WHERE status = 'executing' AND claimed_at < now() - make_interval(secs => p_visibility_secs)
$$;
REVOKE ALL ON FUNCTION soar_stale_executions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION soar_stale_executions(int) TO nirvet_app;

-- Per-tenant destructive-action safety config (tighten-only; destructive OFF by default — a tenant opts
-- in). Rate limits bound the blast radius of a compromised/looping playbook.
CREATE TABLE IF NOT EXISTS soar_settings (
  tenant_id             uuid PRIMARY KEY,
  destructive_enabled   boolean NOT NULL DEFAULT false,
  dry_run               boolean NOT NULL DEFAULT false,
  max_class3_per_hour   int NOT NULL DEFAULT 10 CHECK (max_class3_per_hour >= 0),
  max_class4_per_hour   int NOT NULL DEFAULT 0  CHECK (max_class4_per_hour >= 0),
  updated_at            timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE soar_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_settings_rw ON soar_settings;
CREATE POLICY soar_settings_rw ON soar_settings
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON soar_settings TO nirvet_app;

-- Global platform kill-switch (single row). No tenant scope — platform_admin only (write gated in code);
-- the engine reads it at system level. When true, every connector executor is forced to simulate.
CREATE TABLE IF NOT EXISTS soar_platform (
  id          boolean PRIMARY KEY DEFAULT true CHECK (id),
  kill_switch boolean NOT NULL DEFAULT false,
  dry_run     boolean NOT NULL DEFAULT false,
  updated_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO soar_platform (id) VALUES (true) ON CONFLICT (id) DO NOTHING;
GRANT SELECT, UPDATE ON soar_platform TO nirvet_app;
