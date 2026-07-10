-- §6.17 #126 B-3 — pricing config (packages + per-metric rates) + tenant package assignment + config audit.
-- Pricing is PLATFORM config: a tenant can NEVER write it (no tenant route reaches these), only the padmin route.
-- All money is INTEGER MINOR-UNITS (kobo/cents) — there is no float column anywhere in a money path.

-- Commercial packages (global catalog). currency is ISO-4217; a package's rates are all in that currency.
CREATE TABLE IF NOT EXISTS billing_package (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL UNIQUE,
  currency   text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON billing_package TO nirvet_app;   -- writes only via the padmin route; no RLS (global catalog)

-- Per-metric rate for a package: included quantity + overage price per unit over, in integer minor-units.
CREATE TABLE IF NOT EXISTS billing_rate (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id    uuid NOT NULL REFERENCES billing_package(id),
  metric        text NOT NULL,
  included_qty  bigint NOT NULL DEFAULT 0,
  overage_minor bigint NOT NULL DEFAULT 0,           -- price per unit over, integer minor-units
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (package_id, metric),
  CONSTRAINT billing_rate_nonneg_chk CHECK (included_qty >= 0 AND overage_minor >= 0)
);
GRANT SELECT, INSERT, UPDATE ON billing_rate TO nirvet_app;

-- Tenant → package assignment + the tenant's CONTRACT currency (M-4). Tenant-scoped: a tenant may READ its own
-- assignment; only the padmin route WRITES it.
CREATE TABLE IF NOT EXISTS tenant_billing (
  tenant_id  uuid PRIMARY KEY DEFAULT app_current_tenant(),
  package_id uuid REFERENCES billing_package(id),
  currency   text NOT NULL DEFAULT 'NGN',
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_billing ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_billing FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_billing;
CREATE POLICY tenant_isolation ON tenant_billing
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_billing TO nirvet_app;

-- Append-only audit of every pricing/plan change (the §6.18 posture applied to money).
CREATE TABLE IF NOT EXISTS billing_config_audit (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id   uuid NOT NULL,
  action     text NOT NULL,          -- create_package | set_rate | assign_package
  target     text NOT NULL DEFAULT '',
  detail     jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE, TRUNCATE ON billing_config_audit FROM nirvet_app;
GRANT SELECT, INSERT ON billing_config_audit TO nirvet_app;
CREATE OR REPLACE FUNCTION billing_config_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'billing_config_audit is append-only; % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS billing_config_audit_no_mutate ON billing_config_audit;
CREATE TRIGGER billing_config_audit_no_mutate
  BEFORE UPDATE OR DELETE ON billing_config_audit
  FOR EACH ROW EXECUTE FUNCTION billing_config_audit_immutable();
