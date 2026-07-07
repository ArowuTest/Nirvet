-- Nirvet initial schema (ADR-0001 multi-tenancy via RLS).
-- Run as a superuser/owner (see cmd/migrate). The application connects as the
-- non-owner, non-BYPASSRLS role nirvet_app, so FORCE ROW LEVEL SECURITY applies.

-- ---------------------------------------------------------------------------
-- Application role (created idempotently). Password is dev-only; rotate for prod.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nirvet_app') THEN
    CREATE ROLE nirvet_app LOGIN PASSWORD 'nirvet_app';
  END IF;
END$$;

GRANT USAGE ON SCHEMA public TO nirvet_app;

-- Helper: current tenant from the transaction-local GUC (NULL if unset).
CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------
-- Platform-level registries (NO RLS): tenants, ingest_jobs.
-- Access is restricted at the application layer (RBAC) / system worker.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id             uuid PRIMARY KEY,
  name           text NOT NULL,
  sector         text NOT NULL DEFAULT '',
  country        text NOT NULL DEFAULT '',
  service_tier   text NOT NULL DEFAULT 'standard',
  isolation_tier text NOT NULL DEFAULT 'pooled',
  status         text NOT NULL DEFAULT 'onboarding',
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ingest_jobs (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  kind        text NOT NULL,
  payload     bytea NOT NULL,
  state       text NOT NULL DEFAULT 'queued',   -- queued|running|done|dead
  attempts    int  NOT NULL DEFAULT 0,
  run_at      timestamptz NOT NULL DEFAULT now(),
  claimed_at  timestamptz,
  finished_at timestamptz,
  last_error  text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ingest_jobs_runnable ON ingest_jobs (state, run_at);

-- ---------------------------------------------------------------------------
-- Tenant-owned tables. tenant_id defaults from the GUC so inserts that omit it
-- still populate correctly; RLS scopes every row to the current tenant.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL DEFAULT app_current_tenant(),
  email         text NOT NULL,
  password_hash text NOT NULL,
  role          text NOT NULL,
  status        text NOT NULL DEFAULT 'active',
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  actor_id    uuid,
  actor_email text NOT NULL DEFAULT '',
  action      text NOT NULL,
  target      text NOT NULL DEFAULT '',
  metadata    jsonb NOT NULL DEFAULT '{}',
  request_id  text NOT NULL DEFAULT '',
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_tenant_at ON audit_log (tenant_id, at DESC);

CREATE TABLE IF NOT EXISTS raw_events (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  source      text NOT NULL,
  dedupe_key  text NOT NULL,
  checksum    text NOT NULL,
  payload     bytea NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS events (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL DEFAULT app_current_tenant(),
  dedupe_key    text NOT NULL,
  source        text NOT NULL,
  connector_id  uuid,
  collected_at  timestamptz NOT NULL DEFAULT now(),
  observed_at   timestamptz NOT NULL DEFAULT now(),
  class_name    text NOT NULL DEFAULT '',
  activity_name text NOT NULL DEFAULT '',
  severity      text NOT NULL DEFAULT 'informational',
  confidence    int  NOT NULL DEFAULT 0,
  actor_ref     text NOT NULL DEFAULT '',
  target_ref    text NOT NULL DEFAULT '',
  action        text NOT NULL DEFAULT '',
  outcome       text NOT NULL DEFAULT '',
  raw_pointer   text NOT NULL DEFAULT '',
  checksum      text NOT NULL DEFAULT '',
  data          jsonb NOT NULL DEFAULT '{}',
  UNIQUE (tenant_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS events_tenant_observed ON events (tenant_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  event_id    uuid,
  title       text NOT NULL,
  severity    text NOT NULL,
  confidence  int  NOT NULL DEFAULT 0,
  source      text NOT NULL DEFAULT '',
  status      text NOT NULL DEFAULT 'new',
  assignee_id uuid,
  actor_ref   text NOT NULL DEFAULT '',
  target_ref  text NOT NULL DEFAULT '',
  incident_id uuid,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_tenant_status ON alerts (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  title      text NOT NULL,
  severity   text NOT NULL,
  category   text NOT NULL DEFAULT 'uncategorised',
  stage      text NOT NULL DEFAULT 'new',
  owner_id   uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  closed_at  timestamptz
);
CREATE INDEX IF NOT EXISTS incidents_tenant_created ON incidents (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT app_current_tenant(),
  incident_id uuid NOT NULL,
  at          timestamptz NOT NULL DEFAULT now(),
  author      text NOT NULL DEFAULT '',
  kind        text NOT NULL DEFAULT 'note',
  note        text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS incident_timeline_incident ON incident_timeline (incident_id, at);

-- ---------------------------------------------------------------------------
-- Row-Level Security: enable + FORCE + tenant policy on every tenant-owned table.
-- FORCE ensures the policy applies even to the table owner; the app runs as a
-- separate non-owner role so isolation cannot be bypassed by app-layer bugs.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','audit_log','raw_events','events','alerts','incidents','incident_timeline']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$CREATE POLICY tenant_isolation ON %I
        USING (tenant_id = app_current_tenant())
        WITH CHECK (tenant_id = app_current_tenant())$f$, t);
  END LOOP;
END$$;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER auth lookup: the single controlled RLS hole, used only to
-- find a user by email during login (ADR-0001). Owned by the migrating superuser
-- so it bypasses RLS; returns minimal fields.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, password_hash text, role text, status text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, password_hash, role, status
    FROM users WHERE email = p_email LIMIT 1
$$;

-- ---------------------------------------------------------------------------
-- Grants to the application role.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
  tenants, ingest_jobs, users, audit_log, raw_events, events, alerts, incidents, incident_timeline
  TO nirvet_app;
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(text) TO nirvet_app;
GRANT EXECUTE ON FUNCTION app_current_tenant() TO nirvet_app;
