-- Owner-bypass RLS policy on every RLS-enabled table.
--
-- WHY: The platform's SECURITY DEFINER functions — the auth lookups
-- (auth_find_user_by_email, auth_find_api_key_by_prefix, auth_find_invitation_by_hash,
-- auth_find_refresh_by_hash, auth_find_password_reset_by_hash, sso_/saml_ connection
-- lookups), the background reapers (notification_outbox_pending, soar_stale_executions,
-- ingest_unenqueued_raw, detection_purge_expired_windows, auth_purge_dead_refresh_tokens,
-- retention_delete_*, tenant_offboard_purge, …), and the cross-tenant fleet/read helpers
-- (fleet_alerts, tenant_posture_fleet, incident_meta_for_tenants, billing_account_tenants,
-- …) — are all owned by the DB owner and run with the owner's privileges. They MUST
-- bypass RLS: an auth lookup resolves the tenant from an email BEFORE any tenant context
-- exists; a reaper drains work across all tenants.
--
-- Locally the owner is a Postgres SUPERUSER, which bypasses RLS (including FORCE) natively,
-- so those functions "just worked". On managed Postgres (Render / Cloud SQL / RDS) you only
-- get a NON-superuser owner, and FORCE ROW LEVEL SECURITY binds it — so every one of those
-- SECURITY DEFINER functions silently returned zero rows: no login, no API-key auth, no SSO,
-- no refresh, and no async processing. (Discovered on the first managed deploy: login failed
-- with "invalid credentials" although the user existed and the password hash matched.)
--
-- FIX: a permissive policy that lets ONLY the owner bypass RLS. Inside a SECURITY DEFINER
-- function current_user is the DEFINER (the owner), not the caller, so the functions bypass;
-- the application role nirvet_app is NEVER the owner, so it stays fully tenant-isolated by the
-- existing tenant_isolation policies. This simply reproduces, for a non-superuser owner, the
-- RLS-exemption the superuser owner already has locally. FORCE stays set (schemacheck's
-- FORCE-RLS invariant is unchanged; owner-binding remains for any hypothetical third role).
--
-- The owner role name is captured from current_user at migration time (nirvet_owner on the
-- managed DB, the superuser locally) and baked into the policy literal. Idempotent.
-- A CI guard (schemacheck.TestOwnerBypassPolicy) asserts every RLS table carries this policy.

DO $$
DECLARE r record;
        owner_role text := current_user;   -- the migrating owner == the SECURITY DEFINER owner
BEGIN
  FOR r IN
    SELECT c.relname
    FROM pg_class c
    WHERE c.relkind = 'r'
      AND c.relnamespace = 'public'::regnamespace
      AND c.relrowsecurity
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS owner_bypass ON %I', r.relname);
    EXECUTE format(
      'CREATE POLICY owner_bypass ON %I USING (current_user = %L) WITH CHECK (current_user = %L)',
      r.relname, owner_role, owner_role);
  END LOOP;
END $$;
