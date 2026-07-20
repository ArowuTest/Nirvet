-- §6.17 #174 Billing slice C — operator cost model for margin. billing_cost_rate holds the operator's INTERNAL cost
-- per metric unit (what it costs to serve one unit), so margin = billed revenue − usage×cost. It is PLATFORM config
-- (global catalog, no RLS, like billing_package/billing_rate): written ONLY from the padmin route, every change
-- audited via billing_config_audit. All money is integer minor-units. No-hardcoding: rows are SEEDED (at 0) for
-- every metric, so a metric can never silently lack a cost row; the operator sets real costs via the admin API.
CREATE TABLE IF NOT EXISTS billing_cost_rate (
  metric     text PRIMARY KEY,
  cost_minor bigint NOT NULL DEFAULT 0 CHECK (cost_minor >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON billing_cost_rate TO nirvet_app;   -- writes only via the padmin route; no RLS (global catalog)

-- Seed a 0-cost row for every metering metric (billing/metering.go). 0 = "cost not yet configured": margin then
-- equals revenue AND the read model flags CostConfigured=false so the UI shows "operator cost not set" rather than a
-- misleading 100% margin. The operator replaces these with real costs.
INSERT INTO billing_cost_rate (metric) VALUES
  ('log_volume'), ('alert_count'), ('report_count'), ('playbook_actions'),
  ('connector_count'), ('asset_count'), ('api_usage'), ('storage')
ON CONFLICT (metric) DO NOTHING;
