-- 0088_oversight_grants.sql — the oversight scope-resolver family's binding (Ghana operator seam).
--
-- A grant TABLE (owner+reviewer decision) — not a column on users — because the shape is many-to-one (a payer
-- covers many accounts; an org has many sub-admins), it is the CSA accreditation trail ("who can see across
-- tenants, granted by whom, when" = rows + granted_by + timestamps), and revocation is a clean DELETE. Each
-- grant carries a REAL FK to its scope (organisation / billing_account) with ON DELETE CASCADE, so a grant can
-- NEVER dangle to a deleted scope. Platform registries (padmin-managed, resolver-read via WithSystem keyed on
-- the authenticated principal) — like organisation/billing_account, NOT per-tenant-RLS'd.

CREATE TABLE IF NOT EXISTS org_admin_grant (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL,                                    -- the org-sub-admin user this grant scopes
  org_id       uuid NOT NULL REFERENCES organisation(id) ON DELETE CASCADE,
  granted_by   uuid,                                            -- the platform_admin who issued it (audit trail)
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS org_admin_grant_uniq ON org_admin_grant (principal_id, org_id);
CREATE INDEX IF NOT EXISTS org_admin_grant_principal_idx ON org_admin_grant (principal_id);

CREATE TABLE IF NOT EXISTS payer_account_grant (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL,                                    -- the payer/anchor user this grant scopes
  account_id   uuid NOT NULL REFERENCES billing_account(id) ON DELETE CASCADE,
  granted_by   uuid,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS payer_account_grant_uniq ON payer_account_grant (principal_id, account_id);
CREATE INDEX IF NOT EXISTS payer_account_grant_principal_idx ON payer_account_grant (principal_id);

GRANT SELECT, INSERT, DELETE ON org_admin_grant, payer_account_grant TO nirvet_app;
