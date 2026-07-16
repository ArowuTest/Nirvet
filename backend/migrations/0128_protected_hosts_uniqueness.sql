-- Give protected_hosts the uniqueness protected_identities has had since 0066.
--
-- 0098 created protected_hosts with policies and an index but no uniqueness constraint, so the same crown-jewel
-- pattern could be designated many times over. That was harmless while nothing could write to the table (which
-- was the real bug — see 0127-era work and the D5 reachability slice adding the designation API). Now that an
-- operator can actually add patterns, duplicates would be a live nuisance: the deny-list is what an analyst reads
-- at 2am to understand why a containment was withheld, and three identical 'dc01' rows with different notes make
-- that harder, not safer. The match itself is unaffected by duplicates — this is about the list staying legible
-- and a delete meaning what it looks like it means.
--
-- Expression uniqueness (COALESCE/lower) cannot be an inline table constraint — it needs a unique INDEX.
-- COALESCE folds the NULL tenant_id (global rows) into a sentinel so that NULL != NULL does not defeat the
-- constraint for instance-wide patterns.

-- Deduplicate first so the index can be built. This is a no-op on every existing database (nothing has ever
-- written to this table), but a CREATE UNIQUE INDEX that can fail on real data is not something to leave to
-- chance in a migration that must also run against future backfills.
DELETE FROM protected_hosts a
      USING protected_hosts b
      WHERE a.ctid < b.ctid
        AND COALESCE(a.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
          = COALESCE(b.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
        AND lower(a.pattern) = lower(b.pattern);

CREATE UNIQUE INDEX IF NOT EXISTS protected_hosts_tenant_pattern_uq
  ON protected_hosts (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(pattern));
