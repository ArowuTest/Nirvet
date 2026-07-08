-- SLA breach alerting (SRS §6.8 follow-on). A background sweeper detects incidents
-- that have breached their ack or resolve deadline and notifies once. The notified
-- markers make the alert idempotent (fire exactly once per breach kind), so the sweep
-- is safe to run in multiple processes / on every tick.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ack_breach_notified_at     timestamptz;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolve_breach_notified_at timestamptz;

-- Cross-tenant scan for the provider-side sweeper (incidents has RLS FORCEd; the
-- sweeper spans tenants, mirroring ingest_unenqueued_raw). Returns one row per
-- un-notified breach: an ack breach (open, past ack_due, still unacknowledged) or a
-- resolve breach (open, past resolve_due).
CREATE OR REPLACE FUNCTION incidents_sla_breaches(p_now timestamptz, p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, title text, severity text, breach_kind text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, title, severity, 'ack'::text
    FROM incidents
   WHERE closed_at IS NULL
     AND ack_due_at IS NOT NULL AND acknowledged_at IS NULL
     AND ack_due_at < p_now
     AND ack_breach_notified_at IS NULL
  UNION ALL
  SELECT id, tenant_id, title, severity, 'resolve'::text
    FROM incidents
   WHERE closed_at IS NULL
     AND resolve_due_at IS NOT NULL
     AND resolve_due_at < p_now
     AND resolve_breach_notified_at IS NULL
  ORDER BY 1
  LIMIT p_limit;
$$;

REVOKE ALL ON FUNCTION incidents_sla_breaches(timestamptz, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION incidents_sla_breaches(timestamptz, int) TO nirvet_app;
