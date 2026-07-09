-- §6.4 #118 H-3 — host-source silence detection (US-032). connector_configs is tenant-RLS'd, so the worker's
-- cross-tenant health sweeper reads silent host sources through a SECURITY DEFINER function (minimal, controlled),
-- mirroring connector_list_pullers / connector_find_for_webhook. Returns enabled host connectors that reported at
-- least once (last_success set) but not within p_within_secs, and are not already flagged 'silent' (so the sweeper
-- alerts once per silence episode).
CREATE OR REPLACE FUNCTION connector_silent_host_sources(p_within_secs double precision, p_limit int)
RETURNS TABLE (id uuid, tenant_id uuid, name text, kind text, last_success timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, name, kind, last_success
    FROM connector_configs
   WHERE enabled = true
     AND kind IN ('host_osquery','host_wazuh')
     AND last_success IS NOT NULL
     AND last_success < now() - make_interval(secs => p_within_secs)
     AND health <> 'silent'
   ORDER BY last_success ASC
   LIMIT p_limit
$$;
GRANT EXECUTE ON FUNCTION connector_silent_host_sources(double precision, int) TO nirvet_app;
