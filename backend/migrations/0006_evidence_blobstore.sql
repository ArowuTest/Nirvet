-- Cloud-portable evidence: raw event payloads move to the object store
-- (BlobStore: local FS now, GCS/S3 later — ADR-0002/0005). The row keeps the
-- URI + checksum; the payload column becomes optional (kept for back-compat).
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS blob_uri text;
ALTER TABLE raw_events ALTER COLUMN payload DROP NOT NULL;
