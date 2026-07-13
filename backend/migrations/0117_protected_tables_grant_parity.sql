-- Fix latent GRANT/RLS-policy mismatches on the SOAR protected-* tables.
--
-- These tables declared RLS policies for operations that were never GRANTed to the
-- application role nirvet_app. RLS policies decide WHICH ROWS are visible; the table
-- GRANT decides whether the role may touch the table AT ALL. With a policy but no
-- grant, nirvet_app hits "permission denied for table ..." at runtime. This was
-- masked in local/CI because migrations and most tests run as a SUPERUSER owner,
-- which bypasses both grants and RLS — the gap only appears when the app runs as the
-- non-owner nirvet_app (the production posture; see cmd/migrate FORCE-RLS handling).
--
-- Concrete impact: 0098 created protected_hosts with SELECT/INSERT/UPDATE/DELETE
-- policies but NO grant at all, and the SOAR containment guard
-- (internal/soar/sliceb_protected.go) does `SELECT ... FROM protected_hosts` on every
-- destructive-action authorization — it would have failed closed with a DB error.
-- 0066 granted protected_identities / protected_directory_roles SELECT,INSERT,DELETE
-- but omitted UPDATE, though both declare an UPDATE policy.
--
-- Aligns each grant to the table's declared policy surface. GRANT is idempotent, so
-- this is safe to re-run. A CI parity guard (schemacheck.TestPolicyGrantParity) now
-- prevents this class from recurring.

GRANT SELECT, INSERT, UPDATE, DELETE ON protected_hosts             TO nirvet_app;
GRANT UPDATE                        ON protected_identities         TO nirvet_app;
GRANT UPDATE                        ON protected_directory_roles    TO nirvet_app;
