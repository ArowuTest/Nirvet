-- Owner-bypass RLS policy for the ai_copilot_* tables (and any other RLS table created since migration 0122).
--
-- Same rationale as 0118/0122: on managed Postgres (non-superuser owner + FORCE RLS) a SECURITY DEFINER function
-- owned by the DB owner silently returns zero rows against any RLS table lacking an owner_bypass policy, and
-- schemacheck.TestOwnerBypassPolicy fails the build without it. The owner role name is only known at run time, so
-- it is applied here via the idempotent DO-loop that captures current_user and formats it as a literal — NOT
-- hand-written in 0123 (a `current_user = CURRENT_USER` literal would be a tautology and defeat tenant isolation).

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
