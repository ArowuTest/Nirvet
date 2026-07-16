-- Owner-bypass RLS policy for soar_protected_ack (and any other RLS table created since mig 0126).
--
-- Same rationale as 0118/0122/0124/0126: on managed Postgres the DB owner is NOT a superuser, so with FORCE ROW
-- LEVEL SECURITY a SECURITY DEFINER function owned by that role silently returns ZERO ROWS against any RLS table
-- without an owner_bypass policy. schemacheck.TestOwnerBypassPolicy fails the build without it — and it did,
-- which is the only reason this file exists rather than the bug shipping.
--
-- Worth naming the specific hazard for THIS table, because silent-zero here is not a cosmetic outage: the ack is
-- one of the two things that satisfies the D5 arm-gate. A silent zero would read as "this tenant never attested",
-- which fails SAFE (arming is refused, not permitted) — but it would refuse an operator who HAD decided, with a
-- message telling them to do the thing they already did. Fail-safe is the right direction and still the wrong
-- behaviour; the fence caught it before either could happen.
--
-- The owner role name is only known at run time, so it is applied via the same idempotent DO-loop that captures
-- current_user and formats it as a literal.

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
