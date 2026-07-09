-- 0063_soar_execution_risk_class.sql
-- §6.11 SOAR slice B chunk 4: record the action's §9.5 risk class ON the execution row, POINT-IN-TIME as
-- enforced at execution. This is deliberately DENORMALIZED, not a join back to soar_action_catalog: an
-- admin can re-classify an action later, and a catalog join would then retroactively mis-count the
-- per-class hourly rate cap AND mis-audit past executions. The class-as-enforced-then is the correct model
-- for both the rate limiter and the forensic record.
ALTER TABLE soar_action_execution ADD COLUMN IF NOT EXISTS risk_class text NOT NULL DEFAULT 'informational'
  CHECK (risk_class IN ('informational','low','medium','high','business_critical'));

-- The rate limiter counts recent executed rows by class; index the count path.
CREATE INDEX IF NOT EXISTS soar_action_execution_rate
  ON soar_action_execution (tenant_id, risk_class, status, claimed_at);
