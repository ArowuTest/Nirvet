-- Ingestion durability (SEC Critical #4). Ingest performs three steps that are not
-- atomic: write the raw payload to the blob store, insert the raw_events row, and
-- enqueue a normalize job. A crash (or an enqueue failure) after the row is committed
-- but before the job is enqueued leaves an orphaned raw event that is never
-- normalized/detected — a silently lost security event.
--
-- Fix: mark each raw_events row once its normalize job is enqueued. A system-level
-- reconciler periodically re-enqueues rows still unmarked after a grace period. This
-- is at-least-once and backend-agnostic (works for both the Postgres and NATS queues):
-- the worker's event Append is idempotent on dedupe_key, so a duplicate re-enqueue of
-- an event that WAS processed is harmless.

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS enqueued_at timestamptz;

-- Rows that predate this column were processed under the old path; treat them as
-- already enqueued so the reconciler does not storm historical evidence.
UPDATE raw_events SET enqueued_at = received_at WHERE enqueued_at IS NULL;

-- The reconciler only ever scans the (normally empty) unenqueued set — a partial
-- index keeps that scan cheap regardless of table size.
CREATE INDEX IF NOT EXISTS raw_events_unenqueued_idx
  ON raw_events (received_at) WHERE enqueued_at IS NULL;

-- Cross-tenant lookup for the system-level reconciler. raw_events has RLS FORCEd, and
-- the reconciler runs without a tenant context (it spans tenants), so it reads through
-- this SECURITY DEFINER function — the single controlled hole, mirroring
-- auth_find_user_by_email. It returns only the fields needed to rebuild + re-enqueue a
-- normalize job (the payload itself is re-read from the blob store by its uri).
CREATE OR REPLACE FUNCTION ingest_unenqueued_raw(p_older_than timestamptz, p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, dedupe_key text, checksum text, blob_uri text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, dedupe_key, checksum, blob_uri
    FROM raw_events
   WHERE enqueued_at IS NULL
     AND received_at < p_older_than
   ORDER BY received_at
   LIMIT p_limit;
$$;

REVOKE ALL ON FUNCTION ingest_unenqueued_raw(timestamptz, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingest_unenqueued_raw(timestamptz, int) TO nirvet_app;
