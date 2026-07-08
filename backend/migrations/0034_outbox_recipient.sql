-- Notification recipient (Phase 0 escalation routing). The durable outbox previously carried
-- only channel+subject+body with no addressee, so notifications could not be routed to the
-- tenant's escalation matrix (escalation_contacts, TEN-006). Add a recipient so a breach can
-- fan out one outbox row per matching escalation contact (channel + address).

ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS recipient text NOT NULL DEFAULT '';

-- The SECURITY DEFINER drain must return the recipient too. Return-type change requires a
-- DROP first (CREATE OR REPLACE cannot alter a function's OUT columns).
DROP FUNCTION IF EXISTS notification_outbox_pending(int);
CREATE OR REPLACE FUNCTION notification_outbox_pending(p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, channel text, recipient text, subject text, body text, attempts int)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, channel, recipient, subject, body, attempts
    FROM notification_outbox
   WHERE status = 'pending'
   ORDER BY created_at
   LIMIT p_limit;
$$;
REVOKE ALL ON FUNCTION notification_outbox_pending(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notification_outbox_pending(int) TO nirvet_app;
