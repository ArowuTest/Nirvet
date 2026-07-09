-- 0055_r6_lookup_indexes.sql
-- R6 (perf): add the missing lookup indexes behind hot per-incident/per-ref reads.
-- All plain btree so they apply on any managed Postgres with no extension dependency.

-- alerts.incident_id: alert.ListByIncident (WHERE incident_id=$1) and the evidence pack /
-- AI triage grounding both fan out from an incident to its alerts. Without this the read is
-- a tenant-wide scan filtered by incident_id. Tenant-composite so it composes with RLS.
CREATE INDEX IF NOT EXISTS alerts_tenant_incident ON alerts (tenant_id, incident_id);

-- alerts.actor_ref / target_ref: alert.ListByRef (WHERE actor_ref=$1 OR target_ref=$1).
-- Two single-column indexes so the planner can BitmapOr them for the OR predicate.
CREATE INDEX IF NOT EXISTS alerts_tenant_actor_ref  ON alerts (tenant_id, actor_ref);
CREATE INDEX IF NOT EXISTS alerts_tenant_target_ref ON alerts (tenant_id, target_ref);

-- assets.ref: asset.Get(byRef) (WHERE ref=$1) and asset.FindByRefs (WHERE ref = ANY($1)),
-- used by evidence-pack affected-asset resolution and AI triage enrichment. vulnerabilities
-- already has (tenant_id, ref) from 0025; assets had only (tenant_id, kind).
CREATE INDEX IF NOT EXISTS assets_tenant_ref ON assets (tenant_id, ref);

-- NOTE (deferred, not a plain-btree win): audit.FindByActionContains does a leading-wildcard
-- ILIKE '%incident%' over action/target to assemble an incident's audit trail for an evidence
-- pack. That is an on-demand export path (not a per-request hot path) and is already bounded to
-- the tenant by RLS + audit_log_tenant_at. A pg_trgm GIN index would make the wildcard match
-- indexable, but CREATE EXTENSION pg_trgm needs elevated privileges that are not guaranteed on
-- every managed target, so it is intentionally left out of this migration. The durable fix is to
-- promote incident_id to a real audit_log column and index it — tracked as a follow-up.
