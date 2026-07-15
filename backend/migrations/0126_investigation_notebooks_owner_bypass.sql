-- Owner-bypass RLS policy for the investigation_notebook* tables (and any other RLS table created since mig 0124).
--
-- Same rationale as 0118/0122/0124: on managed Postgres (non-superuser owner + FORCE RLS) a SECURITY DEFINER
-- function owned by the DB owner silently returns zero rows against any RLS table lacking an owner_bypass policy,
-- and schemacheck.TestOwnerBypassPolicy fails the build without it. The owner role name is only known at run time,
-- so it is applied via the idempotent DO-loop that captures current_user and formats it as a literal.

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
