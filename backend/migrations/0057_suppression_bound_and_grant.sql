-- 0057_suppression_bound_and_grant.sql
-- R6-verification carry-forward Low: make the correlation_suppression time-bound durable at the SCHEMA
-- level (was service-enforced only) and remove the hard-DELETE grant now that lift is a soft-delete
-- (deleted_at, 0051). Durability of the suppression record already rests on the immutable audit_log;
-- this closes the "a direct write could set an unbounded or backwards window / hard-delete the row" gap.

-- Schema-enforce the 90-day cap + forward window. Tolerates a legacy NULL ends_at (the service already
-- requires ends_at on create) so the constraint applies to any current + future row without a backfill.
ALTER TABLE correlation_suppressions DROP CONSTRAINT IF EXISTS correlation_suppressions_window_chk;
ALTER TABLE correlation_suppressions ADD CONSTRAINT correlation_suppressions_window_chk
  CHECK (ends_at IS NULL OR (ends_at > starts_at AND ends_at <= starts_at + interval '90 days'));

-- Lift is a soft-delete (UPDATE deleted_at); a hard DELETE would destroy the record the audit trail
-- references. Keep SELECT/INSERT/UPDATE, drop DELETE.
REVOKE DELETE ON correlation_suppressions FROM nirvet_app;
