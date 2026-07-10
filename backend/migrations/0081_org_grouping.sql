-- 0081_org_grouping.sql — Ghana operator seam #2: the `organisation` grouping (LAUNCH-LOCKED seam).
--
-- A first-class tenant-layer grouping, DISTINCT from the billing `account` (§6.17): it lets a scoped
-- org-sub-admin oversee a SET of tenants — e.g. a government cyber authority over its agencies, but not
-- private-sector tenants — via the §9 bounded-read primitive. This migration is ONLY the SEAM:
--   * the `organisation` registry table, and
--   * a NULLABLE `tenants.org_id` FK + index.
-- The scoped-read RESOLVER (organisation -> tenant-set) and the org-sub-admin ROLE are separate, GATED
-- work (fleet/write pre-code gate + its own slice) — NOT in this migration. Landing the seam now means the
-- grouping is never a retrofit (owner decision, 2026-07-10); nullable so existing/ungrouped tenants are
-- unaffected and padmin assigns org_id later. `organisation` is a platform-level registry (managed by
-- platform_admin, like `billing_account`) — no per-tenant RLS on the registry itself.

CREATE TABLE IF NOT EXISTS organisation (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  -- kind is config-first (not an enum-locked column): government | private | generic | ... . Seeded default
  -- keeps it non-null without constraining future kinds.
  kind        text NOT NULL DEFAULT 'generic',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Distinct org names keep padmin assignment unambiguous (case-insensitive).
CREATE UNIQUE INDEX IF NOT EXISTS organisation_name_key ON organisation (lower(name));

-- The seam: a tenant MAY belong to ONE organisation (nullable — ungrouped tenants unaffected).
-- ON DELETE SET NULL: removing an organisation ungroups its tenants rather than cascading a delete of them.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organisation(id) ON DELETE SET NULL;

-- The scoped-read resolver filters tenants by org_id — index it (also serves fleet/org rollups).
CREATE INDEX IF NOT EXISTS tenants_org_id_idx ON tenants (org_id);
