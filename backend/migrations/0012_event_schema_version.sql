-- Canonical event schema versioning (ADR-0006). Every normalized event carries a
-- schema_version so the schema can evolve without a big-bang migration. Existing
-- rows default to '1.0' (the current version).
ALTER TABLE events ADD COLUMN IF NOT EXISTS schema_version text NOT NULL DEFAULT '1.0';
