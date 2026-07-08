-- Evidence-table immutability (R2 H-Res). The Round-1 C1 fix locked audit_log only;
-- raw_events and events are equally evidentiary and still carried UPDATE/DELETE grants
-- from 0001. Extend the same append-only guarantee:
--   * events        — fully immutable (INSERT + SELECT only).
--   * raw_events     — immutable EXCEPT the enqueued_at durability marker (the ingestion
--                      reconciler legitimately needs that one column).
-- REVOKE covers the app role; triggers close the owner path too (mirrors audit_log 0017).

REVOKE DELETE ON events, raw_events FROM nirvet_app;
REVOKE UPDATE ON events FROM nirvet_app;

-- raw_events: reject any UPDATE that changes a column other than enqueued_at.
CREATE OR REPLACE FUNCTION raw_events_only_enqueued() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id          IS DISTINCT FROM OLD.id
     OR NEW.tenant_id   IS DISTINCT FROM OLD.tenant_id
     OR NEW.source      IS DISTINCT FROM OLD.source
     OR NEW.dedupe_key  IS DISTINCT FROM OLD.dedupe_key
     OR NEW.checksum    IS DISTINCT FROM OLD.checksum
     OR NEW.blob_uri    IS DISTINCT FROM OLD.blob_uri
     OR NEW.payload     IS DISTINCT FROM OLD.payload
     OR NEW.received_at IS DISTINCT FROM OLD.received_at THEN
    RAISE EXCEPTION 'raw_events is immutable (only enqueued_at may change)';
  END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS raw_events_immutable ON raw_events;
CREATE TRIGGER raw_events_immutable BEFORE UPDATE ON raw_events
  FOR EACH ROW EXECUTE FUNCTION raw_events_only_enqueued();

-- Block DELETE on both evidence tables for everyone (incl. the owner).
CREATE OR REPLACE FUNCTION evidence_no_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence table % is append-only; DELETE is not permitted', TG_TABLE_NAME;
END; $$;
DROP TRIGGER IF EXISTS raw_events_no_delete ON raw_events;
CREATE TRIGGER raw_events_no_delete BEFORE DELETE ON raw_events
  FOR EACH ROW EXECUTE FUNCTION evidence_no_delete();
DROP TRIGGER IF EXISTS events_no_delete ON events;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION evidence_no_delete();
