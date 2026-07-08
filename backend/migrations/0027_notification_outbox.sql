-- Durable notification outbox (SRS §6.8/§6.16; R3 reliability — SLA-notify delivery guarantee).
--
-- Previously SweepSLABreaches stamped the breach marker BEFORE notifying and discarded the
-- notifier error, so a transient delivery failure silently dropped the notification
-- (exactly-once-or-ZERO). This table lets a notification be enqueued transactionally in the
-- SAME tenant tx as the claim that produced it: the conditional marker still elects one
-- winner (exactly-once dedupe preserved), and the outbox row commits atomically with it. A
-- background dispatcher then delivers with retry — a failed send stays 'pending' and is
-- retried; only after maxAttempts does it dead-letter to 'failed' (observable), never lost.

CREATE TABLE IF NOT EXISTS notification_outbox (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  channel     text NOT NULL DEFAULT 'log',
  subject     text NOT NULL,
  body        text NOT NULL,
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
  attempts    int  NOT NULL DEFAULT 0,
  last_error  text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  sent_at     timestamptz
);
-- Partial index: the dispatcher only ever scans undelivered rows in insertion order.
CREATE INDEX IF NOT EXISTS notification_outbox_pending
  ON notification_outbox (created_at) WHERE status = 'pending';

ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON notification_outbox;
CREATE POLICY tenant_isolation ON notification_outbox
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_outbox TO nirvet_app;

-- Cross-tenant drain for the provider-side dispatcher. The table has RLS FORCEd and the
-- dispatcher spans tenants, so — exactly as incidents_sla_breaches does for the SLA sweep —
-- a SECURITY DEFINER function returns pending rows across tenants; the dispatcher then marks
-- each sent/failed back under that row's own tenant context (WithTenant), which RLS allows.
CREATE OR REPLACE FUNCTION notification_outbox_pending(p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, channel text, subject text, body text, attempts int)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, channel, subject, body, attempts
    FROM notification_outbox
   WHERE status = 'pending'
   ORDER BY created_at
   LIMIT p_limit;
$$;
REVOKE ALL ON FUNCTION notification_outbox_pending(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notification_outbox_pending(int) TO nirvet_app;
