-- §6.8 incident lifecycle depth, slice A (CASE-002/004/009). Widens the incident stage vocabulary to
-- the full CASE-002 chain, adds closure-criteria columns (CASE-009), and adds internal-vs-customer
-- note visibility (CASE-004).

-- CASE-002: widen the stage state machine (was new/triage/investigating/contained/closed). The
-- allowed TRANSITIONS between these are enforced in code (incident.stageTransitions); this CHECK just
-- constrains the stored value to the vocabulary.
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_stage_chk;
ALTER TABLE incidents ADD CONSTRAINT incidents_stage_chk CHECK (stage IN (
  'new','triage','assigned','investigating','waiting_customer','containment_pending',
  'contained','eradication','recovery','monitoring','closed','post_incident_review'));

-- CASE-009: closure criteria. Nullable/empty until the case is closed; the service REQUIRES
-- disposition + root_cause + impact + actions_taken to be non-empty on the transition to 'closed'.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS disposition      text    NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS root_cause       text    NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS impact           text    NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS actions_taken    text    NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS lessons_learned  text    NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS customer_ack     boolean NOT NULL DEFAULT false;

-- CASE-004: internal-only vs customer-visible timeline entries. Default 'internal' so nothing becomes
-- customer-visible by accident; a customer-facing timeline query returns only 'customer' entries.
ALTER TABLE incident_timeline ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'internal';
ALTER TABLE incident_timeline DROP CONSTRAINT IF EXISTS incident_timeline_visibility_chk;
ALTER TABLE incident_timeline ADD CONSTRAINT incident_timeline_visibility_chk
  CHECK (visibility IN ('internal','customer'));
