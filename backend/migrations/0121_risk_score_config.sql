-- Per-tenant composite risk-score configuration (SRS §6.15 exposure posture / customer dashboard risk overview).
--
-- Owner rule (no-hardcoding): the score is computed from real signals (vuln exposure, compliance coverage,
-- incident/SLA posture), but every WEIGHT, BAND, and MODEL PARAMETER is an admin-configurable row with a SEEDED
-- DEFAULT in the column definition (data, not a code constant). One row per tenant; a tenant with no row inherits
-- the seeded column defaults (mirrored as a code fail-safe in riskscore.DefaultConfig). Tenant-scoped, RLS FORCE:
-- a customer_admin tunes their own tenant, a platform_admin any tenant via the tenant context.

CREATE TABLE IF NOT EXISTS risk_score_config (
  tenant_id          uuid PRIMARY KEY DEFAULT app_current_tenant(),
  -- Component weights (operator-facing policy). Composite = weighted mean over the components that have data.
  exposure_weight    numeric NOT NULL DEFAULT 0.40,
  compliance_weight  numeric NOT NULL DEFAULT 0.30,
  operational_weight numeric NOT NULL DEFAULT 0.30,
  -- Risk bands: ascending by max, covering 0..100. First band whose max >= composite wins.
  bands jsonb NOT NULL DEFAULT '[
    {"max":20,"label":"Low","tone":"ok"},
    {"max":40,"label":"Guarded","tone":"ok"},
    {"max":60,"label":"Moderate","tone":"warn"},
    {"max":80,"label":"Elevated","tone":"warn"},
    {"max":100,"label":"High","tone":"danger"}
  ]',
  -- Scoring-model internals (tunable but rarely touched): severity point-weights, penalties, saturation scales
  -- and operational weights. Kept in data so the model is not a code constant (owner no-hardcoding rule).
  model_params jsonb NOT NULL DEFAULT '{
    "sev_weights":{"critical":10,"high":6,"medium":3,"low":1},
    "exploited_penalty":8,
    "overdue_penalty":4,
    "exposure_scale":60,
    "open_incident_weight":5,
    "breach_weight":10,
    "late_weight":3,
    "operational_scale":40
  }',
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE risk_score_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_score_config FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON risk_score_config;
CREATE POLICY tenant_isolation ON risk_score_config
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON risk_score_config TO nirvet_app;
