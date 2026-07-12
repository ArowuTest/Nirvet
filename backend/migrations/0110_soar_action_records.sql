-- #187 slice C — internal non-destructive SOAR executors. Until now the internal actions (enrich, create_note,
-- create_ticket, add_watchlist, collect_evidence) had no live executor and TRUTHFULLY SIMULATED. This gives them
-- a real, durable, tenant-scoped effect: each writes a typed record here inside the run's transaction. Kept as a
-- single self-contained SOAR-owned store (not a cross-domain write) so the executor stays non-destructive by
-- construction and introduces no import into incident/TI/evidence domains; domain-specific routing (add_watchlist
-- → STIX store, collect_evidence → evidence-pack, create_note → incident notes) is #181.
--
-- Safety shape (reviewer slice-C invariants): tenant_id defaults to app_current_tenant() and RLS ENABLE+FORCE
-- isolates every row to its tenant; writes happen inside the run's WithTenant tx + the per-step safeExecute panic
-- guard; the record is a plain tenant-owned row (no outbound, nothing destructive). nirvet_app gets SELECT+INSERT.

CREATE TABLE IF NOT EXISTS soar_action_records (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  incident_id uuid,
  action_key  text NOT NULL,
  kind        text NOT NULL,   -- note | ticket | watchlist | evidence | enrichment
  summary     text NOT NULL DEFAULT '',
  detail      jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS soar_action_records_tenant ON soar_action_records (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS soar_action_records_incident ON soar_action_records (tenant_id, incident_id) WHERE incident_id IS NOT NULL;

ALTER TABLE soar_action_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_action_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON soar_action_records;
CREATE POLICY tenant_isolation ON soar_action_records
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON soar_action_records TO nirvet_app;
