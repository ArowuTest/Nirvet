-- Round-5 M5: correlation suppression is a SOC-blinding control, so its lifecycle must be durable and
-- bounded. Soft-delete (deleted_at) keeps a permanent record that a suppression existed even after it is
-- lifted; the create/lift events are additionally written to the immutable audit_log with the
-- match_type/value/reason (service layer). ends_at is required + capped at the service layer so a
-- suppression can never silently blind detection forever.
ALTER TABLE correlation_suppressions ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
CREATE INDEX IF NOT EXISTS correlation_suppressions_live
  ON correlation_suppressions (tenant_id, match_type, match_value) WHERE deleted_at IS NULL;
