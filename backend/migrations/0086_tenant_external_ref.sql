-- 0086_tenant_external_ref.sql — bulk onboarding factory (Ghana launch long-pole), ONB-2 idempotency key.
--
-- A batch onboarding row carries an operator-supplied external_ref (the MDA's id in the operator's records).
-- Idempotency is enforced at the DB layer, NOT app-level: a re-submitted batch (or a concurrent double-submit)
-- collides on this unique index and the duplicate row is skipped — race-safe, so a retried onboarding of ~200
-- MDAs converges to exactly one tenant per external_ref. Single-tenant create leaves external_ref NULL, and
-- NULLs do not collide (partial index), so it is unaffected.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS external_ref text;

-- Expression/partial uniqueness must be a CREATE UNIQUE INDEX (an inline UNIQUE(...) can't express the
-- WHERE), and IF NOT EXISTS keeps the migration idempotent on a fresh-from-zero apply.
CREATE UNIQUE INDEX IF NOT EXISTS tenants_external_ref_uniq
  ON tenants (external_ref) WHERE external_ref IS NOT NULL;
