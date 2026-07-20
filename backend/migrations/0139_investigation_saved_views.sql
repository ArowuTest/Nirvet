-- 0139 — §6.9 Investigation slice B: saved views (INV — named, re-runnable hunt queries).
--
-- A saved view persists a bounded hunt query (the flat All/Any predicate lists) PLUS a RELATIVE time window
-- (lookback_seconds), so it stays re-runnable over time — on run the service recomputes From = now - lookback, To = now
-- and executes through the EXISTING allow-list-compiled RunHunt path. Critically, RunHunt RE-VALIDATES the query for the
-- RUNNING actor (field-visibility + cost ceiling + read-audit), so a saved view can never let a lower-role analyst run a
-- field/window they couldn't run directly — no privilege escalation via a stored query. Views are PRIVATE to the
-- creating analyst (user_id) within their tenant, exactly like notebooks (mig 0125).

CREATE TABLE IF NOT EXISTS investigation_saved_views (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid        NOT NULL DEFAULT app_current_tenant(),
  user_id          uuid        NOT NULL,                 -- owning analyst; views are private to their creator
  name             text        NOT NULL,
  description      text        NOT NULL DEFAULT '',
  query            jsonb       NOT NULL DEFAULT '{}',    -- {"all":[...],"any":[...]} — predicates only (no absolute time)
  lookback_seconds bigint      NOT NULL,                 -- relative window: From = now - lookback_seconds, To = now
  row_limit        int         NOT NULL DEFAULT 0,       -- 0 = use the configured default limit
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT investigation_saved_views_lookback_chk CHECK (lookback_seconds > 0)
);
CREATE INDEX IF NOT EXISTS idx_investigation_saved_views_owner
  ON investigation_saved_views (tenant_id, user_id, updated_at DESC);

ALTER TABLE investigation_saved_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_saved_views FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON investigation_saved_views;
CREATE POLICY tenant_isolation ON investigation_saved_views
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
-- owner_bypass (mig 0118 pattern / schemacheck guard #5): FORCE RLS also constrains the owner.
DROP POLICY IF EXISTS owner_bypass ON investigation_saved_views;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON investigation_saved_views USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_saved_views TO nirvet_app;
