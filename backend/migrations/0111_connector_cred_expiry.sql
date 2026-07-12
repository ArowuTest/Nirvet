-- #188 LAUNCH #5 (LIGHT) — connector credential expiry tracking + reminder. An OAuth client secret / API key on a
-- pull connector (Entra/Defender/M365) expires on a schedule the CUSTOMER controls in their IdP; when it lapses,
-- ingestion silently fails (blind monitoring). This lets an admin record the credential's expiry and have the
-- platform remind the tenant's escalation contacts BEFORE it lapses. Additive: both columns are nullable, so
-- existing connectors are unaffected and Create is unchanged.
--
-- cred_expiry_notified_at is the claim/dedupe marker (mirrors incidents' *_breach_notified_at): the sweeper
-- claims a connector by setting it, so exactly one sweeper reminds once per expiry. Setting a NEW expiry resets it
-- to NULL (in SetCredExpiry) so a renewed-then-re-expiring credential is reminded again.

ALTER TABLE connector_configs ADD COLUMN IF NOT EXISTS cred_expires_at         timestamptz;
ALTER TABLE connector_configs ADD COLUMN IF NOT EXISTS cred_expiry_notified_at timestamptz;

-- Partial index: the sweeper only cares about connectors with an expiry set and not yet reminded.
CREATE INDEX IF NOT EXISTS connector_configs_cred_expiry
  ON connector_configs (cred_expires_at)
  WHERE cred_expires_at IS NOT NULL AND cred_expiry_notified_at IS NULL;

-- connectors_expiring is the cross-tenant provider sweeper read. connector_configs is RLS FORCEd, so a plain
-- WithSystem SELECT returns nothing — this SECURITY DEFINER function (like incidents_sla_breaches) spans tenants.
-- p_before is the caller-computed cutoff (now + reminder window). Returns connectors whose credential is at/near
-- expiry and not yet reminded. REVOKE PUBLIC + GRANT nirvet_app per the SECURITY DEFINER hardening (#121 + CI fence).
CREATE OR REPLACE FUNCTION connectors_expiring(p_before timestamptz, p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, name text, kind text, cred_expires_at timestamptz)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, tenant_id, name, kind, cred_expires_at
    FROM connector_configs
   WHERE enabled = true
     AND cred_expires_at IS NOT NULL
     AND cred_expires_at <= p_before
     AND cred_expiry_notified_at IS NULL
   ORDER BY cred_expires_at
   LIMIT p_limit;
$$;
REVOKE ALL ON FUNCTION connectors_expiring(timestamp with time zone, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION connectors_expiring(timestamp with time zone, integer) TO nirvet_app;
