-- The poller (system worker) enumerates enabled pull-connectors across tenants
-- to fetch their telemetry. SECURITY DEFINER (controlled, read-only, minimal
-- columns) — like connector_find_for_webhook. Per-connector checkpoint/health
-- updates use the tenant context (no bypass), so no write function is needed.
CREATE OR REPLACE FUNCTION connector_list_pullers()
RETURNS TABLE (id uuid, tenant_id uuid, kind text, secret_ciphertext bytea, config jsonb)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, kind, secret_ciphertext, config
    FROM connector_configs
   WHERE enabled = true
     AND direction = 'read'
     AND kind IN ('microsoft-defender', 'defender', 'microsoft-365', 'entra-id')
$$;
GRANT EXECUTE ON FUNCTION connector_list_pullers() TO nirvet_app;
