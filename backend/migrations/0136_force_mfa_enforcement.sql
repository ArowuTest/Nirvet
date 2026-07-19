-- 0136 — S1 Force-MFA server-side enforcement (go-live register B3).
--
-- The J5 lesson: `mfa.enforce` was a flag that DECLARED enforcement with no consumer — deleted because a control
-- that claims to enforce but nothing reads is false assurance. These columns/tables exist ONLY because a live
-- consumer at the MintSession chokepoint reads them (enforced by check-mfa-enforcement-consumed.sh + a
-- mutation-sensitive test). Two config layers, override-only-tightens:
--
--   * per-tenant policy (session_policies) — an admin may REQUIRE mfa for their tenant's roles.
--   * operator instance FLOOR (mfa_enforcement_floor) — a sovereign-operator minimum that tenant policy can only
--     ADD to, never weaken. Seeded to the compliance-correct default for gov: MFA mandatory for ALL roles.

-- 2a — per-tenant MFA policy (admin-set via PUT /admin/tenants/{id}/session-policy, already ssoAdmin-guarded).
ALTER TABLE session_policies
  ADD COLUMN IF NOT EXISTS require_mfa         boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS mfa_required_roles  text[]  NOT NULL DEFAULT '{}';

-- 2a — operator instance floor: a single global row (padmin-managed). The enforcement MECHANISM is fully armed;
-- the floor selects WHO it binds. The schema seed is OFF (require_all_roles=false, empty floor_roles) so the
-- default is backward-compatible and a mixed gov+commercial instance does not blanket-force MFA before the operator
-- decides. A GOV/sovereign operator sets require_all_roles=true at PROVISIONING (a documented go-live step, like
-- seed-cred rotation and KMS) — the compliance-correct all-users posture a gov auditor expects, reached by a single
-- auditable config flip, no code change (no-hardcoding rule; reversible-upward, per the S1 decision). A phased
-- rollout instead sets floor_roles={platform_admin,soc_manager,detection_engineer,customer_admin} first, then
-- tightens to require_all_roles=true. Per-tenant session_policies can only ADD on top — never drop a floor role.
CREATE TABLE IF NOT EXISTS mfa_enforcement_floor (
  id                smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- singleton
  require_all_roles boolean     NOT NULL DEFAULT false,
  floor_roles       text[]      NOT NULL DEFAULT '{}',
  updated_by        uuid,
  updated_at        timestamptz NOT NULL DEFAULT now()
);
INSERT INTO mfa_enforcement_floor (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

ALTER TABLE mfa_enforcement_floor ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_enforcement_floor FORCE ROW LEVEL SECURITY;
-- Read: any authenticated context may read the floor — it is the enforcement input at every login/mint, and the
-- role set is not sensitive. (FOR ALL below also covers SELECT for the system context; permissive policies OR.)
DROP POLICY IF EXISTS mfa_floor_read ON mfa_enforcement_floor;
CREATE POLICY mfa_floor_read ON mfa_enforcement_floor FOR SELECT USING (true);
-- Write: platform-admin (system) context ONLY — a tenant can never weaken the operator floor (structural, not just
-- handler-gated), the same isolation basis as platform_feature_flags.
DROP POLICY IF EXISTS mfa_floor_write ON mfa_enforcement_floor;
CREATE POLICY mfa_floor_write ON mfa_enforcement_floor FOR ALL
  USING (app_current_tenant() IS NULL) WITH CHECK (app_current_tenant() IS NULL);
GRANT SELECT, INSERT, UPDATE ON mfa_enforcement_floor TO nirvet_app;
