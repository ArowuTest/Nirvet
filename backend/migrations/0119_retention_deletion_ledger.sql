-- Retention deletion-attempt ledger (external-audit Finding 1: observable, self-healing retention).
--
-- Retention deletes a raw_events row's payload blob BEFORE its metadata row so a blob is never retained
-- past its row (the compliance-safe ordering — never database-first). Object storage and Postgres cannot
-- share one transaction, so a crash between the two steps can transiently leave a row whose blob is already
-- gone (an orphaned reference, NOT an orphaned payload). blobstore.Store.Delete is contractually idempotent
-- on a missing object, so the next sweep re-selects that row, the blob delete "succeeds" (already gone), and
-- the row is finally deleted (self-heal).
--
-- This table makes that transient inconsistency OBSERVABLE and provably healing. A row that deletes cleanly
-- in a single pass is NOT recorded here (its aggregate lives in retention_sweep_log) — only anomalous
-- attempts are: a blob delete that failed, or a blob deleted whose metadata delete then failed. The entry is
-- marked completed once the row is finally removed. So a persistently non-empty pending set means a real
-- stuck deletion, not routine churn. Fields mirror the auditor's requested ledger.

CREATE TABLE IF NOT EXISTS retention_deletion_attempt (
  tenant_id        uuid        NOT NULL DEFAULT app_current_tenant(),
  raw_event_id     uuid        NOT NULL,
  blob_uri_hash    text        NOT NULL DEFAULT '',    -- sha256 hex of blob_uri (never the URI itself); '' if the row had no blob
  first_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_attempt_at  timestamptz NOT NULL DEFAULT now(),
  blob_deleted     boolean     NOT NULL DEFAULT false, -- payload blob confirmed gone (or the row had none)
  row_deleted      boolean     NOT NULL DEFAULT false, -- metadata row removed (terminal success)
  retry_count      integer     NOT NULL DEFAULT 1,
  completed_at     timestamptz,                        -- when the row was finally deleted (final completion time)
  PRIMARY KEY (tenant_id, raw_event_id)
);

-- Pending reconciliation lookups (oldest-pending / still-orphaned) hit only incomplete rows.
CREATE INDEX IF NOT EXISTS retention_deletion_attempt_pending
  ON retention_deletion_attempt (tenant_id, first_attempt_at)
  WHERE completed_at IS NULL;

ALTER TABLE retention_deletion_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_deletion_attempt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON retention_deletion_attempt;
CREATE POLICY tenant_isolation ON retention_deletion_attempt
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

-- owner_bypass: required for every RLS table so the non-superuser managed-DB owner (and its SECURITY
-- DEFINER functions) can act; asserted by schemacheck.TestOwnerBypassPolicy. Mirrors migration 0118.
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON retention_deletion_attempt USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON retention_deletion_attempt TO nirvet_app;

-- Cross-tenant reconciliation summary for operator metrics. SECURITY DEFINER so it runs as the owner and
-- aggregates every tenant's pending ledger without a tenant session (read-only; locked to nirvet_app).
CREATE OR REPLACE FUNCTION retention_pending_summary()
RETURNS TABLE (rows_with_missing_blob bigint, oldest_pending timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public STABLE AS $$
  SELECT count(*) FILTER (WHERE blob_deleted AND NOT row_deleted),
         min(first_attempt_at) FILTER (WHERE completed_at IS NULL)
    FROM retention_deletion_attempt
$$;
REVOKE ALL ON FUNCTION retention_pending_summary() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION retention_pending_summary() TO nirvet_app;

-- Prune long-completed ledger entries so the table stays bounded (the completion record is kept briefly as
-- healing evidence, then removed). Cross-tenant; SECURITY DEFINER (owner); returns the number pruned.
CREATE OR REPLACE FUNCTION retention_prune_completed_attempts(p_older_than interval)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n integer;
BEGIN
  DELETE FROM retention_deletion_attempt
   WHERE completed_at IS NOT NULL AND completed_at < now() - p_older_than;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION retention_prune_completed_attempts(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION retention_prune_completed_attempts(interval) TO nirvet_app;
