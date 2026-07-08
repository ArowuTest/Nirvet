-- Config-ize two policy surfaces that were hardcoded as Go constants (Phase 0-D, owner
-- no-hardcoding rule): incident SLA per-severity targets (§6.8) and alert-correlation
-- window/thresholds (§6.7). Every value becomes an admin-configurable, tenant-scoped row
-- with a SEEDED DEFAULT (the default lives in data, overridable via the admin API), never a
-- code constant. Both tables are tenant-RLS FORCE (a customer_admin manages their own tenant;
-- a platform_admin any tenant via the tenant context). The Go code keeps the same literals as
-- fail-safe fallbacks only (used when a resolver is unwired or a tenant lacks a row).

-- §6.8 SLA targets: per (tenant, severity), the ack (time-to-acknowledge) and resolve
-- (time-to-close) deadlines, in SECONDS so any duration is expressible without a code change.
-- Seeded defaults mirror internal/incident/sla.go's slaTargets map.
CREATE TABLE IF NOT EXISTS sla_policies (
  tenant_id       uuid NOT NULL DEFAULT app_current_tenant(),
  severity        text NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
  ack_seconds     int  NOT NULL CHECK (ack_seconds > 0),
  resolve_seconds int  NOT NULL CHECK (resolve_seconds > 0),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, severity)
);
ALTER TABLE sla_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE sla_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON sla_policies;
CREATE POLICY tenant_isolation ON sla_policies
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON sla_policies TO nirvet_app;

-- §6.7 correlation policy: one row per tenant. window_seconds = how long a cluster stays open
-- to absorb related alerts; promote_threshold = aggregate risk at/above which a cluster warrants
-- an incident; min_alerts_for_promotion = corroboration required before auto-opening a case (>=2
-- so one crafted event cannot spawn an incident, R2 M-A). Defaults mirror
-- internal/correlation/correlation.go's Window / PromoteThreshold / MinAlertsForPromotion.
CREATE TABLE IF NOT EXISTS correlation_policies (
  tenant_id                uuid PRIMARY KEY DEFAULT app_current_tenant(),
  window_seconds           int NOT NULL DEFAULT 21600  CHECK (window_seconds > 0),          -- 6h
  promote_threshold        int NOT NULL DEFAULT 70     CHECK (promote_threshold BETWEEN 1 AND 100),
  min_alerts_for_promotion int NOT NULL DEFAULT 2      CHECK (min_alerts_for_promotion >= 1),
  updated_at               timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE correlation_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON correlation_policies;
CREATE POLICY tenant_isolation ON correlation_policies
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON correlation_policies TO nirvet_app;

-- Seed defaults for EXISTING tenants (runs as the migration superuser, bypassing RLS). New
-- tenants get these in tenant.Create's transaction (SeedGovernance). Values MUST stay in sync
-- with the Go seeded-default maps in internal/tenant/governance.go.
INSERT INTO sla_policies (tenant_id, severity, ack_seconds, resolve_seconds)
  SELECT t.id, s.severity, s.ack_seconds, s.resolve_seconds
    FROM tenants t
    CROSS JOIN (VALUES
      ('critical',        900,  14400),   -- 15m ack / 4h resolve
      ('high',           1800,  28800),   -- 30m ack / 8h resolve
      ('medium',         7200,  86400),   --  2h ack / 24h resolve
      ('low',           28800, 259200),   --  8h ack / 72h resolve
      ('informational', 86400, 432000)    -- 24h ack / 120h resolve
    ) AS s(severity, ack_seconds, resolve_seconds)
  ON CONFLICT (tenant_id, severity) DO NOTHING;

INSERT INTO correlation_policies (tenant_id)
  SELECT id FROM tenants ON CONFLICT (tenant_id) DO NOTHING;
