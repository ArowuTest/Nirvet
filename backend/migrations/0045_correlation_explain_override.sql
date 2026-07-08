-- §6.7 correlation slice B: risk explainability (COR-006) + analyst severity/risk override (COR-009).
-- max_confidence is persisted so the risk breakdown can be reconstructed on read; the override columns
-- let an analyst adjust a cluster's severity/risk with a recorded, audited reason. Effective values
-- (override-wins) are computed in the service.

ALTER TABLE correlations ADD COLUMN IF NOT EXISTS max_confidence     int  NOT NULL DEFAULT 0;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS severity_override  text;                 -- NULL = no override
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS risk_override      int;                  -- NULL = no override
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS override_reason    text NOT NULL DEFAULT '';
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS overridden_by      uuid;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS overridden_at      timestamptz;

ALTER TABLE correlations DROP CONSTRAINT IF EXISTS correlations_sev_override_chk;
ALTER TABLE correlations ADD CONSTRAINT correlations_sev_override_chk
  CHECK (severity_override IS NULL OR severity_override IN ('informational','low','medium','high','critical'));
ALTER TABLE correlations DROP CONSTRAINT IF EXISTS correlations_risk_override_chk;
ALTER TABLE correlations ADD CONSTRAINT correlations_risk_override_chk
  CHECK (risk_override IS NULL OR (risk_override BETWEEN 0 AND 100));
