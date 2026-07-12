-- §6.11 #188 HEAVY-2 (sub-commit 1) — single-use, run-bound approval link. Fixes the reviewer-confirmed replay
-- hole (notify.VerifyLink is stateless HMAC → replayable): a customer-approval link is a state transition, so a
-- replayable link is a replayable authorization. This table makes each approval link a ONE-SHOT capability bound
-- to a SPECIFIC run + tenant, consumed atomically.
--
-- The raw token is a high-entropy random string shown ONCE; only its SHA-256 hash is stored (a DB read cannot
-- recover a usable token). The customer presents the link WITHOUT a tenant session — the token IS the capability
-- and carries the tenant/run — so consumption runs through a SECURITY DEFINER function (RLS can't be satisfied
-- with no app_current_tenant), keyed by the unguessable hash, REVOKE PUBLIC + GRANT nirvet_app (SD-revoke fence).

CREATE TABLE IF NOT EXISTS approval_link (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL,
  run_id      uuid NOT NULL,                 -- bound to the SPECIFIC playbook run (not a coarse resource)
  token_hash  text NOT NULL UNIQUE,          -- SHA-256 hex of the raw token; raw token is never stored
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,                    -- NULL until consumed; single-use once set
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS approval_link_run_idx ON approval_link (tenant_id, run_id);

-- Tenant-scoped RLS for the analyst-facing reads/inserts (issue + list under the owning tenant). Consumption does
-- NOT go through these policies — it uses the SECURITY DEFINER function below (no tenant context at consume time).
ALTER TABLE approval_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS approval_link_select ON approval_link;
DROP POLICY IF EXISTS approval_link_insert ON approval_link;
CREATE POLICY approval_link_select ON approval_link
  FOR SELECT USING (tenant_id = app_current_tenant());
CREATE POLICY approval_link_insert ON approval_link
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON approval_link TO nirvet_app;

-- consume_approval_link atomically consumes a link by its token hash: it succeeds AT MOST ONCE (consumed_at set in
-- the same statement) and only for an unexpired, unconsumed link, returning the bound tenant + run. A replay (row
-- already consumed), an expired link, or an unknown hash returns zero rows. SECURITY DEFINER so it runs without a
-- tenant session (the hash is the capability); locked down to nirvet_app.
CREATE OR REPLACE FUNCTION consume_approval_link(p_hash text)
RETURNS TABLE (tenant_id uuid, run_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE approval_link
     SET consumed_at = now()
   WHERE token_hash = p_hash
     AND consumed_at IS NULL
     AND expires_at > now()
  RETURNING approval_link.tenant_id, approval_link.run_id;
$$;
REVOKE ALL ON FUNCTION consume_approval_link(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consume_approval_link(text) TO nirvet_app;
