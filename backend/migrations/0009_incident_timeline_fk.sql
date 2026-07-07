-- Harden the investigation timeline: every entry must belong to a real incident.
-- The column was NOT NULL, but the zero UUID ('00000000-…') is non-null, so a
-- code path that forgot to set incident_id could silently orphan a timeline entry
-- (caught by the Heartbeat_EndToEnd integration test). A foreign key closes that
-- class of bug at the database — an orphan insert now fails loudly.

-- Remove any pre-existing orphans so the constraint can be validated. Runs as the
-- migrating superuser, which bypasses RLS, so this sees rows across all tenants.
DELETE FROM incident_timeline t
 WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.id = t.incident_id);

ALTER TABLE incident_timeline DROP CONSTRAINT IF EXISTS incident_timeline_incident_fk;
ALTER TABLE incident_timeline
  ADD CONSTRAINT incident_timeline_incident_fk
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE;
