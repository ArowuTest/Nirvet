-- §6.7 correlation slice C: suppression / maintenance windows (COR-007) + alert-storm / incident-command
-- mode (COR-008). Over-correlation metrics (COR-010) are computed on read, no schema. Reaches §6.7 FULL.

-- Suppression / maintenance windows: while an active suppression matches a cluster (by entity or ATT&CK
-- technique), the cluster is still formed but AUTO-PROMOTION is withheld and the cluster is flagged
-- suppressed — so a planned maintenance window or known-noisy entity does not spawn incidents.
CREATE TABLE IF NOT EXISTS correlation_suppressions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  match_type  text NOT NULL,                -- entity | technique
  match_value text NOT NULL,                -- exact entity ref, or an ATT&CK technique id (e.g. T1110)
  reason      text NOT NULL DEFAULT '',
  starts_at   timestamptz NOT NULL DEFAULT now(),
  ends_at     timestamptz,                  -- NULL = indefinite until deleted
  created_by  uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT correlation_suppressions_type_chk CHECK (match_type IN ('entity','technique'))
);
CREATE INDEX IF NOT EXISTS correlation_suppressions_lookup ON correlation_suppressions (tenant_id, match_type, match_value);

ALTER TABLE correlation_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_suppressions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON correlation_suppressions;
CREATE POLICY tenant_isolation ON correlation_suppressions
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_suppressions TO nirvet_app;

-- Cluster suppression state.
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS suppressed         boolean NOT NULL DEFAULT false;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS suppression_reason text NOT NULL DEFAULT '';

-- Storm threshold: number of NEW clusters opened per hour above which the tenant is in "alert-storm"
-- mode, so the platform stops auto-opening an incident per cluster (incident-command aggregation).
-- Config, not a constant; floored to a sane minimum in the service.
ALTER TABLE correlation_policies ADD COLUMN IF NOT EXISTS storm_cluster_threshold int NOT NULL DEFAULT 25;
