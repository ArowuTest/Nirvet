-- 0137 — S2b i3: AI response proposals (§6.12 copilot investigation workspace, HEAVY security half).
--
-- The copilot may PROPOSE a response; it may never RUN one. A proposal is a DATA record. A HUMAN (senior/soc_manager)
-- ACCEPTS it, which creates a run through the EXISTING soar RunPendingApproval pipeline (Allowed(mode,risk) +
-- four-eyes + D5 + authority_policies). So there are TWO human/authority gates between AI-proposes and action-runs:
-- (a) the senior accepts, (b) the run's approval gate. The AI is strictly UPSTREAM; it removes no gate.
--   * recommended_action MUST be a catalog action_key (validated fail-closed at create — the AI cannot propose an
--     action the catalog + authority model doesn't already govern).
--   * proposed_by is constrained to 'ai' (first slice — the recommendation SOURCE); requested_by is the analyst who
--     initiated it (analyst-initiated only; auto-proposal is out-of-scope for this slice).
--   * status transitions pending -> accepted | rejected | superseded (accept is guarded by WHERE status='pending' in
--     code, so a proposal can never be promoted to a run twice).

CREATE TABLE IF NOT EXISTS ai_response_proposals (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL DEFAULT app_current_tenant(),
  incident_ref        uuid NOT NULL,                       -- the incident this proposal responds to
  proposed_by         text NOT NULL DEFAULT 'ai',          -- recommendation source (first slice: AI only)
  requested_by        uuid NOT NULL,                       -- the analyst who initiated the proposal
  recommended_action  text NOT NULL,                       -- a catalog action_key (validated at create)
  connector_key       text NOT NULL DEFAULT '',
  rationale           text NOT NULL DEFAULT '',
  evidence_citations  text[] NOT NULL DEFAULT '{}',        -- assembler citation ids the recommendation rests on
  risk_class          text NOT NULL,
  reversible          boolean NOT NULL DEFAULT false,
  expected_impact     text NOT NULL DEFAULT '',
  status              text NOT NULL DEFAULT 'pending',
  accepted_by         uuid,                                -- the senior who promoted it to a run
  accepted_run_id     uuid,                                -- the soar run created on accept
  decided_at          timestamptz,                         -- when accepted/rejected
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_prop_status_chk CHECK (status IN ('pending','accepted','rejected','superseded')),
  CONSTRAINT ai_prop_risk_chk   CHECK (risk_class IN ('informational','low','medium','high','business_critical')),
  CONSTRAINT ai_prop_source_chk CHECK (proposed_by IN ('ai'))
);

ALTER TABLE ai_response_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_response_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_response_proposals;
CREATE POLICY tenant_isolation ON ai_response_proposals
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

-- owner_bypass (mig 0118 pattern / schemacheck guard #5): FORCE RLS also constrains the table OWNER, so a
-- SECURITY DEFINER function running as the non-superuser managed-DB owner would silently read ZERO rows without this.
-- Restores the owner's exemption without weakening nirvet_app (never the owner). Every FORCE-RLS table needs it.
DROP POLICY IF EXISTS owner_bypass ON ai_response_proposals;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON ai_response_proposals USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;

-- A proposal is created (INSERT) and transitioned in place (UPDATE status/accepted_*); it is never deleted.
REVOKE DELETE, TRUNCATE ON ai_response_proposals FROM nirvet_app;
GRANT SELECT, INSERT, UPDATE ON ai_response_proposals TO nirvet_app;

CREATE INDEX IF NOT EXISTS ai_response_proposals_incident
  ON ai_response_proposals (tenant_id, incident_ref, created_at DESC);
