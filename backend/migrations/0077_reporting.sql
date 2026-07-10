-- §6.13 #125 reporting export. reports = tenant-scoped RLS report records; report_audit = append-only
-- generate/export/download trail (REP-008); report_limits = seeded global cost ceiling (no-hardcoding).
CREATE TABLE IF NOT EXISTS reports (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  type         text NOT NULL,
  format       text NOT NULL,
  params       jsonb NOT NULL DEFAULT '{}',
  status       text NOT NULL DEFAULT 'pending',
  artifact_uri text NOT NULL DEFAULT '',   -- blobstore URI (opaque UUID key)
  row_count    int  NOT NULL DEFAULT 0,
  byte_size    int  NOT NULL DEFAULT 0,
  error        text NOT NULL DEFAULT '',
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  ready_at     timestamptz,
  CONSTRAINT reports_status_chk CHECK (status IN ('pending','running','ready','failed')),
  CONSTRAINT reports_format_chk CHECK (format IN ('json','csv','xlsx'))
);
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON reports;
CREATE POLICY tenant_isolation ON reports
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON reports TO nirvet_app;
CREATE INDEX IF NOT EXISTS reports_tenant_created ON reports (tenant_id, created_at DESC);

-- REP-008: audit every report generation / export / download. Append-only + tenant-scoped.
CREATE TABLE IF NOT EXISTS report_audit (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  report_id  uuid,
  actor_id   uuid NOT NULL,
  action     text NOT NULL,
  format     text NOT NULL DEFAULT '',
  row_count  int  NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT report_audit_action_chk CHECK (action IN ('generate','export','download'))
);
ALTER TABLE report_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON report_audit;
CREATE POLICY tenant_isolation ON report_audit
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
REVOKE UPDATE, DELETE, TRUNCATE ON report_audit FROM nirvet_app;
GRANT SELECT, INSERT ON report_audit TO nirvet_app;
CREATE INDEX IF NOT EXISTS report_audit_tenant_created ON report_audit (tenant_id, created_at DESC);
CREATE OR REPLACE FUNCTION report_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'report_audit is append-only (immutable); % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS report_audit_no_mutate ON report_audit;
CREATE TRIGGER report_audit_no_mutate
  BEFORE UPDATE OR DELETE ON report_audit
  FOR EACH ROW EXECUTE FUNCTION report_audit_immutable();

-- Seeded global cost ceiling (no-hardcoding): the caps are policy, not code constants.
CREATE TABLE IF NOT EXISTS report_limits (
  scope      text PRIMARY KEY DEFAULT 'global',
  max_rows   int NOT NULL DEFAULT 50000,
  max_cells  int NOT NULL DEFAULT 500000,
  max_bytes  int NOT NULL DEFAULT 26214400,  -- 25 MiB
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO report_limits (scope) VALUES ('global') ON CONFLICT (scope) DO NOTHING;
GRANT SELECT ON report_limits TO nirvet_app;
