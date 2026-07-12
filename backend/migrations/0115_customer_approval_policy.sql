-- §6.11 #188 HEAVY-2 (sub-commit 2/3) — customer-approval authority config + approval accumulation.
--
--   * customer_approval_policy — per-tenant (NULL=global default) authority routing for destructive SOAR actions:
--       platform_analyst (default = TODAY's behavior, no change) | customer_approver | both_required.
--       Seeded global default = platform_analyst, so every tenant is byte-for-byte unchanged until it opts in.
--   * run_approval — append-only record of each approval on a run (internal analyst OR customer), so the execution
--       gate can require the RIGHT set of DISTINCT principals before a destructive step fires (never customer-alone
--       for business_critical). Tenant-scoped: the customer path records under WithTenant once the link resolves
--       the tenant, so no cross-tenant/system write is needed.

-- ── customer_approval_policy ──────────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_approval_policy (
  id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                 uuid,                                -- NULL = global default
  authority                 text    NOT NULL DEFAULT 'platform_analyst',
  bc_customer_authorizable  boolean NOT NULL DEFAULT false,      -- may a business_critical step be authorized w/ a customer approval (still needs internal too)
  link_ttl_seconds          int     NOT NULL DEFAULT 10800,      -- approval-link lifetime (default 3h; containment auth is short-lived)
  customer_approver_ref     text    NOT NULL DEFAULT '',         -- informational: the designated customer approver identity (the link is the auth)
  updated_at                timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT customer_approval_authority_chk CHECK (authority IN ('platform_analyst','customer_approver','both_required')),
  CONSTRAINT customer_approval_ttl_chk       CHECK (link_ttl_seconds BETWEEN 300 AND 86400)
);
CREATE UNIQUE INDEX IF NOT EXISTS customer_approval_policy_tenant_uq
  ON customer_approval_policy (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

ALTER TABLE customer_approval_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_approval_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS customer_approval_policy_select ON customer_approval_policy;
DROP POLICY IF EXISTS customer_approval_policy_insert ON customer_approval_policy;
DROP POLICY IF EXISTS customer_approval_policy_update ON customer_approval_policy;
CREATE POLICY customer_approval_policy_select ON customer_approval_policy
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY customer_approval_policy_insert ON customer_approval_policy
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY customer_approval_policy_update ON customer_approval_policy
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON customer_approval_policy TO nirvet_app;

INSERT INTO customer_approval_policy (tenant_id, authority) VALUES (NULL, 'platform_analyst') ON CONFLICT DO NOTHING;

-- ── run_approval ──────────────────────────────────────────────────────────────────────────────────────────────
-- Append-only. principal_id is the platform user (internal); principal_ref is the human identity (email) used for
-- the dual-role guard (an internal approver and a customer approver must not be the same person). principal_role is
-- the internal approver's role at approval time, re-validated at execution.
CREATE TABLE IF NOT EXISTS run_approval (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  run_id         uuid NOT NULL,
  kind           text NOT NULL,                                 -- internal | customer
  principal_id   uuid,                                          -- platform user (internal); NULL for a customer
  principal_ref  text NOT NULL DEFAULT '',                      -- email/identity — dual-role guard compares this
  principal_role text NOT NULL DEFAULT '',                      -- internal approver role at approval time
  at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT run_approval_kind_chk CHECK (kind IN ('internal','customer'))
);
CREATE INDEX IF NOT EXISTS run_approval_run_idx ON run_approval (tenant_id, run_id);
-- At most one approval per (run, kind, principal_ref) so a double-submit doesn't inflate the count.
CREATE UNIQUE INDEX IF NOT EXISTS run_approval_dedup_uq ON run_approval (run_id, kind, principal_ref);

ALTER TABLE run_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE run_approval FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS run_approval_select ON run_approval;
DROP POLICY IF EXISTS run_approval_insert ON run_approval;
CREATE POLICY run_approval_select ON run_approval
  FOR SELECT USING (tenant_id = app_current_tenant());
CREATE POLICY run_approval_insert ON run_approval
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT ON run_approval TO nirvet_app;
