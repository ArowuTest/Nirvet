-- Owner-bypass RLS policy for risk_score_config (and any other RLS table created since migration 0118).
--
-- Migration 0118 added the `owner_bypass` policy to every RLS-enabled table that existed AT THAT TIME. Tables
-- created afterwards (here: risk_score_config from 0121) do not carry it, which the schemacheck.TestOwnerBypassPolicy
-- CI guard flags — and on managed Postgres (non-superuser owner + FORCE RLS) any SECURITY DEFINER function owned by
-- the DB owner would silently return zero rows against them. This re-runs the exact 0118 loop: idempotent, and it
-- future-proofs every RLS table added since. See 0118 for the full rationale.

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
