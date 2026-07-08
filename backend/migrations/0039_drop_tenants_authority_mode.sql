-- Round-4 hygiene: drop the dead tenants.authority_mode column. Phase 0 reconciled SOAR onto the
-- per-action authority_policies store (the single source of truth); nothing in production reads or
-- writes this legacy tenant-wide column any more. Dropping it prevents future divergence between the
-- two mechanisms (the reviewer's explicit recommendation). Its CHECK constraint (0004) goes with it.
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_authority_chk;
ALTER TABLE tenants DROP COLUMN IF EXISTS authority_mode;
