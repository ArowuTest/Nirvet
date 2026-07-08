-- Canonical event schema v1.1 (ADR-0006): promote the hottest analytics fields
-- from the data JSON to first-class, indexable columns. mitre drives ATT&CK
-- coverage; vendor/product drive source analytics. Existing rows default empty.
ALTER TABLE events ADD COLUMN IF NOT EXISTS mitre   text[] NOT NULL DEFAULT '{}';
ALTER TABLE events ADD COLUMN IF NOT EXISTS vendor  text   NOT NULL DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS product text   NOT NULL DEFAULT '';

-- GIN index for fast "events with technique T…" lookups / coverage aggregation.
CREATE INDEX IF NOT EXISTS events_mitre ON events USING gin (mitre);
CREATE INDEX IF NOT EXISTS events_vendor ON events (tenant_id, vendor);
