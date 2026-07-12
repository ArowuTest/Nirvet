-- 0106_detection_stateful.sql — DET-002 stateful detection primitives (LAUNCH #2).
-- The engine was single-event only (a predicate over ONE event). This adds threshold ("N matching events for one
-- entity within a window") and distinct ("N distinct values of a field for one entity within a window") rule
-- kinds, which is what MFA-fatigue and impossible-travel need. The window/threshold ARE the rule (detection-as-
-- code, admin-authored config); the windowed COUNT state lives in detection_windows, fire-once-per-(entity,window)
-- via a fired_at latch claimed with a conditional UPDATE (double-fire guard under concurrent workers).

-- Additive rule fields; kind defaults 'simple' so every existing rule is unchanged (back-compat).
ALTER TABLE detection_rules
  ADD COLUMN IF NOT EXISTS kind           text NOT NULL DEFAULT 'simple',
  ADD COLUMN IF NOT EXISTS window_seconds integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS threshold      integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS entity_field   text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS distinct_field text NOT NULL DEFAULT '';
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_kind_chk;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_kind_chk CHECK (kind IN ('simple', 'threshold', 'distinct'));

-- Per-(tenant,rule,entity,window) window header. window_start = the event time truncated to the window boundary,
-- so concurrent workers processing events in the same window converge on the SAME row. The count is derived
-- (COUNT(*) of member rows below) so it is IDEMPOTENT on event re-processing — a retried worker job cannot
-- double-count. fired_at is the fire-once latch.
CREATE TABLE IF NOT EXISTS detection_windows (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL DEFAULT app_current_tenant(),
  rule_id       uuid NOT NULL,
  entity_key    text NOT NULL,
  window_start  timestamptz NOT NULL,
  window_seconds integer NOT NULL,
  fired_at      timestamptz,                 -- latch: set once when the rule fires for this (entity,window)
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, rule_id, entity_key, window_start)
);
CREATE INDEX IF NOT EXISTS detection_windows_reap ON detection_windows (tenant_id, window_start);
ALTER TABLE detection_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_windows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON detection_windows;
CREATE POLICY tenant_isolation ON detection_windows
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON detection_windows TO nirvet_app;

-- Member set: one row per counted MEMBER of a window — for threshold rules the member is the contributing
-- EVENT's id (so an event counts at most once, even on retry); for distinct rules the member is the distinct
-- field value. The window's count = COUNT(*) of members. INSERT ... ON CONFLICT DO NOTHING makes recording a
-- member idempotent + concurrency-safe.
CREATE TABLE IF NOT EXISTS detection_window_values (
  tenant_id uuid NOT NULL DEFAULT app_current_tenant(),
  window_id uuid NOT NULL REFERENCES detection_windows(id) ON DELETE CASCADE,
  value     text NOT NULL,
  UNIQUE (tenant_id, window_id, value)
);
ALTER TABLE detection_window_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_window_values FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON detection_window_values;
CREATE POLICY tenant_isolation ON detection_window_values
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, DELETE ON detection_window_values TO nirvet_app;

-- Reaper (cross-tenant maintenance, no tenant context) — deletes windows past window_start + window + grace,
-- cascading their value rows. SECURITY DEFINER because RLS would block a no-tenant DELETE. REVOKE PUBLIC +
-- GRANT nirvet_app (CI-guarded by check-security-definer-revoke.sh). Returns the number deleted.
CREATE OR REPLACE FUNCTION detection_purge_expired_windows(p_grace interval)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  n bigint;
BEGIN
  DELETE FROM detection_windows
   WHERE window_start + make_interval(secs => window_seconds) + p_grace < now();
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION detection_purge_expired_windows(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION detection_purge_expired_windows(interval) TO nirvet_app;
