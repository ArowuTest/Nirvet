-- 0060_drop_dead_stix_sightings.sql
-- Drop the dead stix_sightings stub. It was created in 0041 (slice A) but never wired: slice B stores
-- sightings as STIX objects in stix_objects (type='sighting') and reads them via sightingCounts, and no
-- Go code references stix_sightings. It also carried a latent cross-tenant defect — a bare PRIMARY KEY on
-- the caller-supplied text STIX id with no tenant_id (the R5-H3 class), surfaced by the new
-- tenant-composite schema guard. Removing the mis-designed, unused table is cleaner than composite-fixing
-- a table nothing writes to.
DROP TABLE IF EXISTS stix_sightings;
