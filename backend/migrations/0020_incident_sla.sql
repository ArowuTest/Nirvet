-- Incident SLA timers (SRS §6.8). Track time-to-acknowledge and time-to-resolve
-- against per-severity targets so breaches are visible and reportable. Due-times are
-- computed at creation from the severity policy (in Go — see internal/incident/sla.go);
-- acknowledged_at is stamped on first ownership. Breach is derived on read, not stored.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ack_due_at      timestamptz;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolve_due_at  timestamptz;

-- Support "open incidents breaching / about to breach" scans without a full table scan.
CREATE INDEX IF NOT EXISTS incidents_resolve_due_open_idx
  ON incidents (resolve_due_at) WHERE closed_at IS NULL;
