-- 0101_disclosure_policy.sql
-- Customer read-model Slice A: per-tenant disclosure policy (admin-config, no-hardcoding rule). Governs the
-- customer AUDIENCE only — which incident lifecycle stages become customer-visible (the row gate) and whether
-- the one sensitive closure field (root_cause) is disclosed. The projection STRUCTS (internal/readmodel) are the
-- hard security invariant — this policy can only WIDEN WITHIN THE SAFE ENVELOPE those structs define; it cannot
-- expose a provider-internal field, because the customer projection has no such field to populate.
--
-- Fail-closed by design: (1) a customer sees NO incident by default until it reaches an "engaged" stage;
-- (2) root_cause is NOT disclosed by default; (3) if a tenant has no row, readmodel.PolicyStore.Resolve returns
-- the same conservative default in Go (a missing row can never mass-disclose). Backfill direction is toward the
-- safe default, mirroring the CASE-004 visibility primitive (unset -> internal).

CREATE TABLE IF NOT EXISTS disclosure_policy (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL DEFAULT app_current_tenant(),
  -- The row-gate allowlist: a customer sees an incident only once it has reached one of these stages. Default =
  -- the "engaged" stages (provider has deliberately involved the customer); early internal stages
  -- (new/triage/assigned/investigating) are withheld. Kept in sync with readmodel.DefaultCustomerVisibleStages.
  customer_visible_stages text[]  NOT NULL DEFAULT ARRAY[
                            'waiting_customer','containment_pending','contained',
                            'eradication','recovery','monitoring','closed','post_incident_review']::text[],
  disclose_root_cause     boolean NOT NULL DEFAULT false,
  updated_at              timestamptz NOT NULL DEFAULT now(),
  updated_by              uuid,
  UNIQUE (tenant_id)
);

ALTER TABLE disclosure_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE disclosure_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON disclosure_policy;
CREATE POLICY tenant_isolation ON disclosure_policy
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON disclosure_policy TO nirvet_app;

-- Seed existing tenants with the conservative default row (so an admin has something to edit). New tenants use
-- the in-Go fail-closed default until an admin sets a row; both defaults are identical.
INSERT INTO disclosure_policy (id, tenant_id)
  SELECT gen_random_uuid(), id FROM tenants
  ON CONFLICT (tenant_id) DO NOTHING;
