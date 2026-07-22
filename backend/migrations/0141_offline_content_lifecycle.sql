-- Offline content lifecycle persistence. Imported content remains DATA; this schema
-- stores signed provenance and lifecycle state only. Activation is represented by
-- state transitions and never grants execution or response capabilities.

CREATE TABLE content_packages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NULL,
    publisher_id text NOT NULL,
    content_type text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    scope text NOT NULL CHECK (scope IN ('global','tenant')),
    state text NOT NULL CHECK (state IN ('quarantined','approved','staged','active','superseded','rolled_back','expired','rejected')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    content_sha256 text NOT NULL CHECK (length(content_sha256) = 64),
    manifest_bytes bytea NOT NULL,
    content_bytes bytea NOT NULL,
    signature bytea NOT NULL,
    imported_by text NOT NULL,
    approved_by text NULL,
    activated_by text NULL,
    imported_at timestamptz NOT NULL DEFAULT now(),
    approved_at timestamptz NULL,
    activated_at timestamptz NULL,
    prior_version bigint NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT content_packages_scope_tenant_ck CHECK (
        (scope = 'global' AND tenant_id IS NULL) OR
        (scope = 'tenant' AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT content_packages_version_uq UNIQUE NULLS NOT DISTINCT
        (tenant_id, publisher_id, content_type, version)
);

CREATE INDEX content_packages_tenant_idx ON content_packages (tenant_id);
CREATE INDEX content_packages_active_idx ON content_packages (tenant_id, content_type, state)
    WHERE state = 'active';

CREATE TABLE content_artifacts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NULL,
    package_id uuid NOT NULL REFERENCES content_packages(id) ON DELETE CASCADE,
    artifact_id text NOT NULL,
    artifact_kind text NOT NULL,
    artifact_data jsonb NOT NULL,
    publisher_id text NOT NULL,
    package_version bigint NOT NULL,
    content_sha256 text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT content_artifacts_package_artifact_uq UNIQUE (package_id, artifact_id)
);

CREATE INDEX content_artifacts_tenant_idx ON content_artifacts (tenant_id);
CREATE INDEX content_artifacts_package_idx ON content_artifacts (package_id);

CREATE TABLE content_lifecycle_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NULL,
    package_id uuid NULL REFERENCES content_packages(id) ON DELETE SET NULL,
    actor text NOT NULL,
    action text NOT NULL,
    result text NOT NULL,
    state text NOT NULL,
    publisher_id text NOT NULL,
    content_type text NOT NULL,
    version bigint NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX content_lifecycle_audit_tenant_idx ON content_lifecycle_audit (tenant_id);
CREATE INDEX content_lifecycle_audit_package_idx ON content_lifecycle_audit (package_id, occurred_at);

ALTER TABLE content_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE content_packages FORCE ROW LEVEL SECURITY;
ALTER TABLE content_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE content_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE content_lifecycle_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE content_lifecycle_audit FORCE ROW LEVEL SECURITY;

-- Tenant users may read global content plus their own tenant content, but may only
-- write tenant-scoped rows. Global publication is owner/padmin-only through owner_bypass.
CREATE POLICY tenant_isolation ON content_packages
    USING (tenant_id IS NULL OR tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY tenant_isolation ON content_artifacts
    USING (tenant_id IS NULL OR tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY tenant_isolation ON content_lifecycle_audit
    USING (tenant_id IS NULL OR tenant_id = app_current_tenant())
    WITH CHECK (tenant_id = app_current_tenant());

-- Managed Postgres owners are not superusers. Mirror migration 0118: owner_bypass
-- allows SECURITY DEFINER/padmin operations while runtime rejects owner connections.
DO $$
DECLARE
    r record;
    owner_name text;
BEGIN
    FOR r IN SELECT unnest(ARRAY['content_packages','content_artifacts','content_lifecycle_audit']) AS table_name
    LOOP
        SELECT pg_get_userbyid(c.relowner) INTO owner_name
        FROM pg_class c WHERE c.oid = r.table_name::regclass;
        EXECUTE format(
            'CREATE POLICY owner_bypass ON %I USING (current_user = %L) WITH CHECK (current_user = %L)',
            r.table_name, owner_name, owner_name
        );
    END LOOP;
END$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON content_packages TO nirvet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON content_artifacts TO nirvet_app;
GRANT SELECT, INSERT ON content_lifecycle_audit TO nirvet_app;
