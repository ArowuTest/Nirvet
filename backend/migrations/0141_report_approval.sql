-- §6.13 #173 Reporting slice B — report-approval workflow. A generated report can require manager sign-off before it
-- is downloadable/deliverable (four-eyes on report release). This adds a review lifecycle to the existing report
-- record (no new tenant table, no new authz surface): review_status + reviewer attribution, an operator-level policy
-- of which report TYPES require review (no-hardcoding: config row + seed), and two new audit actions.

-- Review lifecycle on the existing (tenant-scoped, RLS-confined) reports row.
--   none            = the type does not require review → downloadable as today (backward-compatible).
--   pending_review  = ready artifact exists but is NOT releasable until a second, senior actor approves.
--   approved        = a senior actor (≠ creator) cleared it → releasable.
--   rejected        = a senior actor blocked it → TERMINAL, never releasable.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS review_status text NOT NULL DEFAULT 'none';
ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_by   uuid;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_at   timestamptz;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS review_note   text NOT NULL DEFAULT '';
DO $$ BEGIN
  ALTER TABLE reports ADD CONSTRAINT reports_review_status_chk
    CHECK (review_status IN ('none','pending_review','approved','rejected'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Operator-level policy: which report TYPES require sign-off before release. Keyed by report type; global (not
-- tenant-scoped) — this is an operator governance decision, like report_limits. GRANT SELECT only (padmin manages
-- the rows via WithSystem, mirroring report_limits). No-hardcoding: the seeds are policy, not code constants.
CREATE TABLE IF NOT EXISTS report_review_policy (
  type            text PRIMARY KEY,
  review_required boolean NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT now()
);
-- Seed the two generatable types. breach_report (regulatory) requires sign-off; service_review (routine ops KPI
-- export analysts self-serve) does not. Any UNSEEDED/unknown type defaults to REQUIRED at MarkReady (fail-closed
-- toward review — a new report type cannot silently skip sign-off), never stranded (approval is always available).
INSERT INTO report_review_policy (type, review_required) VALUES
  ('service_review', false),
  ('breach_report',  true)
ON CONFLICT (type) DO NOTHING;
GRANT SELECT ON report_review_policy TO nirvet_app;

-- Two new report_audit actions for the review transitions (append-only trail already enforced by the immutable
-- trigger from 0077). Rebuild the CHECK to add approve/reject alongside generate/export/download.
ALTER TABLE report_audit DROP CONSTRAINT IF EXISTS report_audit_action_chk;
ALTER TABLE report_audit ADD CONSTRAINT report_audit_action_chk
  CHECK (action IN ('generate','export','download','approve','reject'));

-- Queue lookup: ready reports awaiting review, per tenant.
CREATE INDEX IF NOT EXISTS reports_review_pending
  ON reports (tenant_id, created_at) WHERE review_status = 'pending_review';
