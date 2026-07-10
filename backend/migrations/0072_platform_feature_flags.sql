-- §6.18 #122 P-1 — platform feature flags (ADMIN-002) + immutable config-audit (ADMIN-004). safety_class is
-- CODE-OWNED (a Go registry), NOT a column — an admin must not be able to reclassify a protected flag to bypass the
-- guard. The DB stores flag state + scope; the resolver + guard enforce classification, fail-safe defaults, and
-- tighten-only. Immutable-class flags are resolved from code only (a planted row here is inert — Reinf-A).

CREATE TABLE IF NOT EXISTS platform_feature_flags (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key        text NOT NULL,
  scope      text NOT NULL DEFAULT 'global',   -- global | env | tenant | package | partner | region | beta
  scope_ref  text NOT NULL DEFAULT '',         -- tenant_id (as text) for scope='tenant'; '' for global
  enabled    boolean NOT NULL DEFAULT false,
  value      jsonb NOT NULL DEFAULT '{}',
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT platform_feature_flags_scope_chk CHECK (scope IN ('global','env','tenant','package','partner','region','beta'))
);
CREATE UNIQUE INDEX IF NOT EXISTS platform_feature_flags_key_scope_uq
  ON platform_feature_flags (key, scope, scope_ref);

ALTER TABLE platform_feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_feature_flags FORCE ROW LEVEL SECURITY;
-- Read: a tenant sees non-tenant-scoped flags (global/env/…) + its OWN tenant-scoped flags; system (padmin) sees all.
DROP POLICY IF EXISTS platform_feature_flags_read ON platform_feature_flags;
CREATE POLICY platform_feature_flags_read ON platform_feature_flags FOR SELECT
  USING (app_current_tenant() IS NULL OR scope <> 'tenant' OR scope_ref = app_current_tenant()::text);
-- Write: flags are PLATFORM-admin managed → system context only (app_current_tenant() IS NULL). A tenant can never
-- write a flag (there is no tenant-facing flag-write path); this makes that structural, not just handler-gated.
DROP POLICY IF EXISTS platform_feature_flags_insert ON platform_feature_flags;
DROP POLICY IF EXISTS platform_feature_flags_update ON platform_feature_flags;
DROP POLICY IF EXISTS platform_feature_flags_delete ON platform_feature_flags;
CREATE POLICY platform_feature_flags_insert ON platform_feature_flags FOR INSERT WITH CHECK (app_current_tenant() IS NULL);
CREATE POLICY platform_feature_flags_update ON platform_feature_flags FOR UPDATE USING (app_current_tenant() IS NULL) WITH CHECK (app_current_tenant() IS NULL);
CREATE POLICY platform_feature_flags_delete ON platform_feature_flags FOR DELETE USING (app_current_tenant() IS NULL);
GRANT SELECT, INSERT, UPDATE, DELETE ON platform_feature_flags TO nirvet_app;

-- ── platform_config_audit (ADMIN-004) — append-only, immutable ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_config_audit (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity      text NOT NULL,                   -- flag | config
  key         text NOT NULL,
  scope       text NOT NULL DEFAULT 'global',
  scope_ref   text NOT NULL DEFAULT '',
  old_value   jsonb,
  new_value   jsonb,
  safety_class text NOT NULL DEFAULT 'open',    -- point-in-time class as-enforced (denormalized, like soar risk_class)
  actor_id    uuid,
  reason      text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT platform_config_audit_entity_chk CHECK (entity IN ('flag','config'))
);
-- Append-only: the config-change history is an evidence spine — no UPDATE/DELETE, even by padmin (ADMIN-004).
REVOKE UPDATE, DELETE, TRUNCATE ON platform_config_audit FROM nirvet_app;
CREATE OR REPLACE FUNCTION platform_config_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'platform_config_audit is append-only (immutable); % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS platform_config_audit_no_mutate ON platform_config_audit;
CREATE TRIGGER platform_config_audit_no_mutate
  BEFORE UPDATE OR DELETE ON platform_config_audit
  FOR EACH ROW EXECUTE FUNCTION platform_config_audit_immutable();
GRANT SELECT, INSERT ON platform_config_audit TO nirvet_app;
