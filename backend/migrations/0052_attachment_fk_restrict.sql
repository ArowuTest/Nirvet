-- Round-5 observation: incident_attachments held ON DELETE CASCADE, which would let a future
-- incident-delete path erase chain-of-custody rows (contradicting the SELECT/INSERT-only grant that makes
-- them immutable). Switch to RESTRICT so an incident with evidence attachments cannot be deleted out from
-- under its custody records. (No incident hard-delete path exists today; this is defence-in-depth.)
ALTER TABLE incident_attachments DROP CONSTRAINT IF EXISTS incident_attachments_incident_id_fkey;
ALTER TABLE incident_attachments
  ADD CONSTRAINT incident_attachments_incident_id_fkey
  FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT;
