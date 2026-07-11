-- 0087_syslog_sources.sql — Ghana operator L connector: the syslog-listener source registry (MA-SYS-2).
--
-- A syslog line arrives over mTLS with NO JWT; the listener attributes it to a tenant from the AUTHENTICATED
-- CHANNEL — the client cert's SHA-256 fingerprint → this registry's tenant_id — NEVER from the payload. This
-- is a platform registry (padmin-managed, listener-read via WithSystem): like `tenants`/`organisation` it is
-- NOT per-tenant-RLS'd (the listener has no tenant GUC at accept time; a FORCE-RLS table would return 0 rows
-- and break attribution). tenant_id FK CASCADE so offboarding a tenant removes its syslog sources.
--
-- SECURE DEFAULT: enabled=false — a registered source does not ingest until an operator explicitly enables it
-- (a tenant has no syslog ingress until a source credential is provisioned AND turned on).
CREATE TABLE IF NOT EXISTS syslog_sources (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name             text NOT NULL DEFAULT '',
  cert_fingerprint text NOT NULL,                 -- lowercase hex SHA-256 of the client leaf cert DER
  enabled          boolean NOT NULL DEFAULT false, -- secure default: off until explicitly enabled
  created_at       timestamptz NOT NULL DEFAULT now()
);

-- A fingerprint maps to exactly ONE source/tenant — the attribution key must be unambiguous. Expression/
-- uniqueness as a CREATE UNIQUE INDEX (from-zero-safe, IF NOT EXISTS keeps the apply idempotent).
CREATE UNIQUE INDEX IF NOT EXISTS syslog_sources_fingerprint_uniq ON syslog_sources (cert_fingerprint);
CREATE INDEX IF NOT EXISTS syslog_sources_tenant_idx ON syslog_sources (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON syslog_sources TO nirvet_app;
