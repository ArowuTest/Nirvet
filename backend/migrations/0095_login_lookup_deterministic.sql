-- F9 (builder pass, LOW-MED): make the SECURITY DEFINER login lookup DETERMINISTIC.
--
-- UNIQUE(tenant_id, email) permits the same email across tenants (realistic for an MSSP: one consultant
-- across several customer tenants). auth_find_user_by_email had `LIMIT 1` with NO `ORDER BY`, so for such
-- an email it returned an arbitrary row (physical order) — the legitimate user's login would flap between
-- tenants and could fail with "invalid credentials" against the wrong row's password. This is an
-- availability/determinism defect, NOT a cross-tenant compromise (tenant_id/role/password_hash all come
-- from the SAME returned row, so a caller only ever authenticates into the tenant whose password they hold).
--
-- Fix: order by (created_at, id) so the lookup is stable — the oldest matching account wins, every time.
-- (A fully tenant-explicit login — subdomain/tenant hint so a shared-email consultant can reach ANY of
-- their tenants — is the larger V2 change; this migration removes the non-determinism for launch.)
-- Return type is unchanged, so CREATE OR REPLACE is in-place; re-assert the REVOKE/GRANT so a from-zero
-- deploy reproduces the 0071 hardening.

CREATE OR REPLACE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, password_hash text, role text, status text,
               mfa_enabled boolean, mfa_secret bytea,
               failed_login_attempts int, locked_until timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, password_hash, role, status, mfa_enabled, mfa_secret,
         failed_login_attempts, locked_until
    FROM users WHERE lower(email) = lower(p_email)
   ORDER BY created_at, id
   LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_user_by_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(text) TO nirvet_app;
