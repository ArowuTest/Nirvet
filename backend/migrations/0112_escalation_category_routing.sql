-- #188 LAUNCH #5 (MEDIUM) — category-scoped notification routing. Today an escalation contact routes purely by
-- severity threshold (min_severity). This adds an optional CATEGORY scope so an operator can route, e.g., identity
-- incidents to the identity on-call and network incidents to the network on-call. Additive + backward-compatible:
-- category defaults to '' (= no scope = the contact receives ALL categories, exactly as today).
--
-- Routing semantics (see tenant.ResolveEscalationFor):
--   a notification WITH a category  → general ('' ) contacts + contacts scoped to that category
--   a notification WITHOUT a category (category-agnostic, e.g. a cred-expiry reminder) → ALL contacts (broadcast)
-- so existing callers (ResolveEscalation == ResolveEscalationFor with category '') are unchanged.

ALTER TABLE escalation_contacts ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT '';

-- The SLA-breach sweeper needs the incident's category to route the breach. Recreate the SECURITY DEFINER reader
-- to also return category (a return-column change can't use CREATE OR REPLACE, so DROP first — which drops the
-- 0071 grants, so we RE-REVOKE PUBLIC + RE-GRANT nirvet_app here).
DROP FUNCTION IF EXISTS incidents_sla_breaches(timestamptz, integer);
CREATE FUNCTION incidents_sla_breaches(p_now timestamptz, p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, title text, severity text, category text, breach_kind text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, title, severity, category, 'ack'::text
    FROM incidents
   WHERE closed_at IS NULL
     AND ack_due_at IS NOT NULL AND acknowledged_at IS NULL
     AND ack_due_at < p_now
     AND ack_breach_notified_at IS NULL
  UNION ALL
  SELECT id, tenant_id, title, severity, category, 'resolve'::text
    FROM incidents
   WHERE closed_at IS NULL
     AND resolve_due_at IS NOT NULL
     AND resolve_due_at < p_now
     AND resolve_breach_notified_at IS NULL
  ORDER BY 1
  LIMIT p_limit;
$$;
REVOKE ALL ON FUNCTION incidents_sla_breaches(timestamp with time zone, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION incidents_sla_breaches(timestamp with time zone, integer) TO nirvet_app;
