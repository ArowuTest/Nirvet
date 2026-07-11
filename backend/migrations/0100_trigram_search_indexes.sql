-- 0100_trigram_search_indexes.sql
-- G-M2 (perf): make the leading-wildcard ILIKE '%term%' search paths indexable with pg_trgm GIN.
--
-- 0055 deferred this: at the time the concern was that CREATE EXTENSION pg_trgm needs elevated privileges
-- that "are not guaranteed on every managed target". That caution no longer applies to our deployment model —
-- the sovereign / self-managed Postgres (and GCP Cloud SQL, which allow-lists pg_trgm) is under our control and
-- the migrate role runs as a superuser-equivalent. If a future target genuinely cannot enable pg_trgm, this
-- migration will fail LOUDLY at deploy (the operator enables the extension), rather than silently degrading.
--
-- Without these, both searches are a tenant-wide sequential scan filtered by the wildcard predicate. RLS still
-- bounds each scan to one tenant, and the planner BitmapOrs the per-column GIN indexes for the OR predicate.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- audit_log search (audit.go FindByActionContains + evidence-pack incident trail assembly):
--   WHERE action ILIKE '%'||$1||'%' OR target ILIKE '%'||$1||'%'
CREATE INDEX IF NOT EXISTS audit_log_action_trgm ON audit_log USING gin (action gin_trgm_ops);
CREATE INDEX IF NOT EXISTS audit_log_target_trgm ON audit_log USING gin (target gin_trgm_ops);

-- Postgres eventstore search (eventstore/postgres.go List):
--   WHERE ... class_name ILIKE '%'||$4||'%' OR action ILIKE ... OR actor_ref ILIKE ... OR target_ref ILIKE ...
-- (The ClickHouse backend is the V1 primary at scale; these cover the Postgres eventstore path.)
CREATE INDEX IF NOT EXISTS events_class_name_trgm ON events USING gin (class_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS events_action_trgm     ON events USING gin (action gin_trgm_ops);
CREATE INDEX IF NOT EXISTS events_actor_ref_trgm  ON events USING gin (actor_ref gin_trgm_ops);
CREATE INDEX IF NOT EXISTS events_target_ref_trgm ON events USING gin (target_ref gin_trgm_ops);
