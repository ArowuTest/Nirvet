-- Privileged access management + break-glass (SRS §6.2 IAM-004/006). Time-bounded, justified,
-- approved (or emergency) role elevation. An active elevation lets its owner mint a short-lived
-- elevated token (stateless AssumeRole); the record is the governance/audit/expiry layer.

CREATE TABLE IF NOT EXISTS privileged_elevations (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL DEFAULT app_current_tenant(),
  user_id         uuid NOT NULL,                 -- who is elevated (the requester)
  user_email      text NOT NULL DEFAULT '',
  base_role       text NOT NULL,
  elevated_role   text NOT NULL,                 -- never platform_admin; same domain as base_role
  kind            text NOT NULL CHECK (kind IN ('pam','break_glass')),
  reason          text NOT NULL,                 -- justification (mandatory)
  duration_seconds int NOT NULL DEFAULT 3600 CHECK (duration_seconds BETWEEN 300 AND 28800),
  status          text NOT NULL DEFAULT 'requested'
                    CHECK (status IN ('requested','active','rejected','expired','revoked')),
  approver_id     uuid,
  approver_email  text NOT NULL DEFAULT '',
  granted_at      timestamptz,
  expires_at      timestamptz,
  review_required boolean NOT NULL DEFAULT false, -- break-glass must be reviewed after use
  reviewed_at     timestamptz,
  reviewed_by     text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS priv_elev_user   ON privileged_elevations (tenant_id, user_id, status);
CREATE INDEX IF NOT EXISTS priv_elev_review ON privileged_elevations (tenant_id, status, review_required);

ALTER TABLE privileged_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE privileged_elevations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON privileged_elevations;
CREATE POLICY tenant_isolation ON privileged_elevations
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON privileged_elevations TO nirvet_app;
