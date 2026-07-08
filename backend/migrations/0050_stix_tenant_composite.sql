-- Round-5 H3: stix_objects used a global `id`-only primary key, so a STIX id from a public feed
-- (deterministic/well-known) could only exist ONCE platform-wide. When tenant B imported an object whose
-- id already existed under tenant A, B either errored (versioned) or was silently skipped (unversioned)
-- → B gets incomplete intel = missed detections, and the shared id space is a cross-tenant existence
-- oracle / squat vector. Every sibling table keys uniqueness by (tenant_id, …); stix_objects must too.
--
-- Fix: a surrogate row_id PK + a composite unique on (tenant, id) with NULL-tenant coalesced to a fixed
-- sentinel so global rows stay unique among themselves too. Each tenant now holds its own copy of an id.

ALTER TABLE stix_objects ADD COLUMN IF NOT EXISTS row_id uuid NOT NULL DEFAULT gen_random_uuid();

-- Swap the primary key from id → row_id.
ALTER TABLE stix_objects DROP CONSTRAINT IF EXISTS stix_objects_pkey;
ALTER TABLE stix_objects ADD CONSTRAINT stix_objects_pkey PRIMARY KEY (row_id);

-- Composite uniqueness: a tenant may hold at most one copy of a STIX id; globals (tenant NULL) are made
-- unique among themselves via the zero-uuid sentinel. This is the ON CONFLICT target for UpsertStix.
DROP INDEX IF EXISTS stix_objects_tenant_id_uniq;
CREATE UNIQUE INDEX stix_objects_tenant_id_uniq
  ON stix_objects (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), id);
