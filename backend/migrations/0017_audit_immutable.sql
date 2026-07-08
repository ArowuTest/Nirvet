-- Audit-log immutability (SEC / NFR-003). The audit trail is the evidentiary spine
-- of the SOC; it must be append-only. Previously the app role held UPDATE/DELETE on
-- audit_log with no enforcement. This migration makes the table INSERT/SELECT-only
-- for the app AND blocks UPDATE/DELETE for EVERYONE (including the table owner) via
-- a trigger, so a bug, a compromised app role, or a careless migration cannot
-- rewrite history.

-- 1. App role can only append and read.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM nirvet_app;

-- 2. Hard stop at the database: no updates or deletes, ever.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only (immutable); % is not permitted', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS audit_log_no_mutate ON audit_log;
CREATE TRIGGER audit_log_no_mutate
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- Note: a tamper-evident hash-chain (prev_hash per row, computed on insert) is the
-- stronger control and is planned as a follow-on; this migration establishes the
-- append-only invariant that was previously unenforced.
