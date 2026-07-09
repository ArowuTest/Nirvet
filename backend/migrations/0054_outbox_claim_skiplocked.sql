-- Round-6 (reliability): the outbox drain SELECTed status='pending' and only "claimed" a row by its
-- terminal update AFTER Dispatch sent it, so two worker instances both selected + sent the same row →
-- duplicate customer notifications. Fix: claim-before-send with FOR UPDATE SKIP LOCKED (the same pattern
-- the ingest queue uses), moving the row to a transient 'sending' state under the row lock so a second
-- instance skips it. A 'sending' row whose worker crashed is re-claimed after a visibility timeout.

ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS claimed_at timestamptz;

ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_status_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_status_check
  CHECK (status IN ('pending','sending','sent','failed'));

-- notification_outbox_claim atomically claims up to p_limit deliverable rows (pending, or 'sending' that
-- a crashed worker stranded past the visibility window), marks them 'sending' under FOR UPDATE SKIP
-- LOCKED, and returns them. Two concurrent drains never claim the same row → no double-send. SECURITY
-- DEFINER because the table is RLS-FORCEd and the dispatcher spans tenants.
DROP FUNCTION IF EXISTS notification_outbox_claim(int, int);
CREATE OR REPLACE FUNCTION notification_outbox_claim(p_limit int, p_visibility_secs int)
RETURNS TABLE (id uuid, tenant_id uuid, channel text, recipient text, subject text, body text, attempts int)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE notification_outbox o
     SET status = 'sending', claimed_at = now()
   WHERE o.id IN (
     SELECT c.id FROM notification_outbox c
      WHERE c.status = 'pending'
         OR (c.status = 'sending' AND c.claimed_at < now() - make_interval(secs => p_visibility_secs))
      ORDER BY c.created_at
      FOR UPDATE SKIP LOCKED
      LIMIT p_limit)
  RETURNING o.id, o.tenant_id, o.channel, o.recipient, o.subject, o.body, o.attempts;
$$;
REVOKE ALL ON FUNCTION notification_outbox_claim(int, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notification_outbox_claim(int, int) TO nirvet_app;
