-- §6.17 slice B — umbrella billing: payer accounts + billing modes + billing suspension.
-- BILL-007 (downstream/umbrella billing) + BILL-006 (suspension). Pricing/mode/suspension are PLATFORM config: a
-- tenant has NO route to write any of it (the self-mark / re-parent fraud path is closed by route-gating + audit).

-- The payer / contract holder (e.g. the Federal Government) that covers many tenants. Global config (padmin-managed).
CREATE TABLE IF NOT EXISTS billing_account (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                 text NOT NULL UNIQUE,
  currency             text NOT NULL,
  contract_start       date,
  contract_end         date,
  contract_value_minor bigint NOT NULL DEFAULT 0,   -- agreed contract value, integer minor-units
  payment_status       text NOT NULL DEFAULT 'current',   -- current | overdue
  account_status       text NOT NULL DEFAULT 'active',    -- active | delinquent | suspended
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT billing_account_payment_chk CHECK (payment_status IN ('current','overdue')),
  CONSTRAINT billing_account_status_chk  CHECK (account_status IN ('active','delinquent','suspended')),
  CONSTRAINT billing_account_value_chk   CHECK (contract_value_minor >= 0)
);
GRANT SELECT, INSERT, UPDATE ON billing_account TO nirvet_app;   -- padmin-route writes only; global catalog (no RLS)

-- Billing mode + covering account on the tenant. Written ONLY from the padmin route (SetMode), audited — a tenant
-- cannot mark itself covered/comp (dodge payment) or re-parent itself to another account. billing_mode:
--   direct  — tenant pays its own invoice (slice A default)
--   covered — metered; charges attribute to billing_account_id; not directly invoiced
--   comp    — metered; zero-charge (sponsored/demo)
ALTER TABLE tenant_billing ADD COLUMN IF NOT EXISTS billing_mode text NOT NULL DEFAULT 'direct';
ALTER TABLE tenant_billing ADD COLUMN IF NOT EXISTS billing_account_id uuid REFERENCES billing_account(id);
ALTER TABLE tenant_billing DROP CONSTRAINT IF EXISTS tenant_billing_mode_chk;
ALTER TABLE tenant_billing ADD CONSTRAINT tenant_billing_mode_chk CHECK (billing_mode IN ('direct','covered','comp'));

-- Billing suspension = restrict ACCESS, NOT stop protecting (the safety decision). access_suspended gates the
-- authenticated API only; the ingest/detection/alert path never consults it. Distinct from tenants.status
-- (lifecycle) and fully reversible on payment.
ALTER TABLE tenant_billing ADD COLUMN IF NOT EXISTS access_suspended boolean NOT NULL DEFAULT false;
ALTER TABLE tenant_billing ADD COLUMN IF NOT EXISTS suspend_reason  text NOT NULL DEFAULT '';

-- An account-membership read for the account-level rollup (the ONE deliberate cross-tenant exception). SECURITY
-- DEFINER so it can read across the account's covered tenants, but it returns ONLY the tenants covered by the given
-- account — a payer sees its own umbrella, never all tenants, never another account's. REVOKE PUBLIC.
CREATE OR REPLACE FUNCTION billing_account_tenants(p_account uuid)
RETURNS TABLE (tenant_id uuid, currency text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT tenant_id, currency FROM tenant_billing
   WHERE billing_mode = 'covered' AND billing_account_id = p_account
$$;
REVOKE ALL ON FUNCTION billing_account_tenants(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION billing_account_tenants(uuid) TO nirvet_app;
