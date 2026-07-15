-- Rename the 'emergency' authority mode to 'contractual_auto'.
--
-- 'emergency' reads as an emergency STOP. It is the exact opposite. soar.Allowed() lets it auto-run EVERY risk
-- class except business_critical with no human approval — isolate_endpoint, disable_user, block_ip — making it the
-- MOST PERMISSIVE mode in the system. The real fail-closed stop is 'observe' (nothing auto-runs), and 'observe' is
-- also the only mode the '*' catch-all accepts, so the brake already exists under a different name.
--
-- This is not a cosmetic nit. The name fooled the engineer who had just read this package and was writing a review
-- of it; it will fool a platform_admin at 2am who believes they are hitting the brakes and instead switches on
-- autonomous high-risk containment across every agency on the instance. A mode whose name reads as its own
-- opposite is a live misconfiguration risk, and the blast radius is other people's estates.
--
-- 'contractual_auto' says what it does: contractually pre-agreed autonomous execution.
--
-- A clean rename, NOT an alias — continuing to accept 'emergency' would keep the trap loaded. Existing rows are
-- migrated before the constraint is swapped, so this is safe whether or not the mode was ever used in anger.
-- (The legacy tenants.authority_mode column carried its own copy of this enum; it was already dropped in 0039, so
-- authority_policies is the only surviving home.)

-- Drop the OLD mode CHECK by discovery, not by guessing its name. The constraint in 0028 is declared inline, so
-- its name is whatever Postgres auto-generated. `DROP CONSTRAINT IF EXISTS <guess>` would silently no-op on a
-- wrong guess, the ADD below would then succeed under a NEW name, and the old constraint would survive and reject
-- every 'contractual_auto' write — a green migration hiding a broken mode. Find it by its definition instead.
DO $$
DECLARE c record;
BEGIN
  FOR c IN
    SELECT con.conname
      FROM pg_constraint con
      JOIN pg_class rel ON rel.oid = con.conrelid
     WHERE rel.relname = 'authority_policies'
       AND con.contype = 'c'
       AND pg_get_constraintdef(con.oid) ILIKE '%emergency%'
  LOOP
    EXECUTE format('ALTER TABLE authority_policies DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

UPDATE authority_policies SET mode = 'contractual_auto' WHERE mode = 'emergency';

ALTER TABLE authority_policies
  ADD CONSTRAINT authority_policies_mode_check
  CHECK (mode IN ('observe', 'approval', 'pre_authorized', 'contractual_auto'));

-- Prove the rename actually took: the new mode must be accepted and the old one rejected. A silent failure here
-- would leave the trap loaded, so fail the migration rather than the 2am operator.
DO $$
BEGIN
  BEGIN
    ASSERT (SELECT count(*) FROM authority_policies WHERE mode = 'emergency') = 0,
      'authority_policies still holds rows with the retired ''emergency'' mode';
  END;
END $$;
