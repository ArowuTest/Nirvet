-- §6.9 #124 I-1/I-2 — investigation hunt-query read-path audit (INV-007) + the configurable cost ceiling.
--
-- INV-007 requires every query/export to be preserved in the audit log for sensitive cases. The mutation-audit
-- middleware only records writes; a hunt query READS customer data, so it is recorded here: who ran what query and how
-- many rows it returned (one row per execution — not per result row). Append-only + tenant-scoped + RLS-FORCEd, the
-- same posture as the other evidence trails.
CREATE TABLE IF NOT EXISTS investigation_query_audit (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  actor_id   uuid NOT NULL,
  kind       text NOT NULL,                       -- hunt_query | entity_read | raw_event | evidence_subset
  query      jsonb NOT NULL DEFAULT '{}',
  row_count  int  NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT investigation_query_audit_kind_chk CHECK (kind IN ('hunt_query','entity_read','raw_event','evidence_subset'))
);
ALTER TABLE investigation_query_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_query_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON investigation_query_audit;
CREATE POLICY tenant_isolation ON investigation_query_audit
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
REVOKE UPDATE, DELETE, TRUNCATE ON investigation_query_audit FROM nirvet_app;
GRANT SELECT, INSERT ON investigation_query_audit TO nirvet_app;
CREATE INDEX IF NOT EXISTS investigation_query_audit_tenant_created ON investigation_query_audit (tenant_id, created_at DESC);

CREATE OR REPLACE FUNCTION investigation_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'investigation_query_audit is append-only (immutable); % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS investigation_audit_no_mutate ON investigation_query_audit;
CREATE TRIGGER investigation_audit_no_mutate
  BEFORE UPDATE OR DELETE ON investigation_query_audit
  FOR EACH ROW EXECUTE FUNCTION investigation_audit_immutable();

-- Cost-ceiling config (no-hardcoding): a seeded GLOBAL default the query service reads; the caps are policy, not code
-- constants. Global platform config (no tenant_id) — read under WithSystem; per-tenant override deferred to slice B.
CREATE TABLE IF NOT EXISTS investigation_limits (
  scope              text PRIMARY KEY DEFAULT 'global',
  max_predicates     int NOT NULL DEFAULT 20,
  max_time_span_days int NOT NULL DEFAULT 90,
  default_limit      int NOT NULL DEFAULT 200,
  max_limit          int NOT NULL DEFAULT 1000,
  updated_at         timestamptz NOT NULL DEFAULT now()
);
INSERT INTO investigation_limits (scope) VALUES ('global') ON CONFLICT (scope) DO NOTHING;
GRANT SELECT ON investigation_limits TO nirvet_app;
