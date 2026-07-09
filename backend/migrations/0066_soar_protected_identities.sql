-- §6.11 D5 protected-identity guard (blast-radius containment). Identities/roles a destructive identity action
-- must NOT auto-affect; a protected target → withheld + human escalation, never a silent effect. Config-first
-- (seeded defaults, admin-tunable). L3 self-protection is code-derived from the connector identity, not here.

CREATE TABLE IF NOT EXISTS protected_identities (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NULL,                              -- NULL = global
  identity_ref text NOT NULL,                          -- objectId or UPN
  reason       text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now()
);
-- Expression uniqueness (COALESCE/lower) is not allowed in an inline table constraint → use a unique index.
CREATE UNIQUE INDEX IF NOT EXISTS protected_identities_tenant_ref_uq
  ON protected_identities (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(identity_ref));
ALTER TABLE protected_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_identities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS protected_identities_rw ON protected_identities;
CREATE POLICY protected_identities_rw ON protected_identities
  USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)   -- read own + global
  WITH CHECK (tenant_id = app_current_tenant());                  -- write own only (tighten-only)
GRANT SELECT, INSERT, DELETE ON protected_identities TO nirvet_app;

CREATE TABLE IF NOT EXISTS protected_directory_roles (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NULL,                                -- NULL = global default
  role_name  text NOT NULL,                            -- directory role displayName (matched case-insensitively)
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS protected_directory_roles_tenant_role_uq
  ON protected_directory_roles (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(role_name));
ALTER TABLE protected_directory_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_directory_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS protected_directory_roles_rw ON protected_directory_roles;
CREATE POLICY protected_directory_roles_rw ON protected_directory_roles
  USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, DELETE ON protected_directory_roles TO nirvet_app;

-- Seed the universally high-privilege roles (global; a tenant may add more, e.g. a custom admin role).
INSERT INTO protected_directory_roles (tenant_id, role_name) VALUES
  (NULL, 'Global Administrator'),
  (NULL, 'Privileged Role Administrator'),
  (NULL, 'Security Administrator'),
  (NULL, 'User Administrator')
ON CONFLICT DO NOTHING;
