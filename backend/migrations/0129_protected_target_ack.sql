-- D5 arm-gate: the attestation that lets a tenant with NO designated crown jewels enable destructive SOAR.
--
-- The reviewer's invariant, and the reason this table exists:
--
--   A safety control must have a built-in floor that works with zero configuration — or must refuse to arm
--   until configured. An empty config table must never mean allow.
--
-- internal/ai/redaction.go takes the first branch and is the reference implementation in this repo: a built-in
-- compiled floor, always active, never disable-able, so masking works with zero DB config. The D5 protected-target
-- guard cannot take that branch — there is no universal crown jewel. Nirvet cannot guess that a given agency's
-- domain controller is dc01.mofep.gov.gh. So D5 must take the SECOND branch: refuse to arm until configured.
--
-- Why an attestation and not simply "require a non-empty list": requiring rows invites a dummy row. The dangerous
-- state was never "no protection" — it is "no protection that anybody decided on". So arming destructive response
-- requires EITHER at least one designated target OR this explicit, audited record that the tenant designates none.
-- Both are decisions; only one is a list.
--
-- Why its own table rather than columns on soar_settings: SetSettings upserts the whole settings struct in one
-- request. An ack field there could be set in the SAME call that flips destructive_enabled — a checkbox beside
-- the dangerous toggle, which is theatre, not a decision. A separate table forces a separate, separately-audited
-- act, which is the entire point.
--
-- confirmed_with is the honest part. The SOC cannot know whether the Ministry of Finance has a crown jewel; only
-- the agency can. Until the portal carries a real customer acknowledgement, this records WHO at the customer
-- confirmed it, as an attestation by a named operator. That is weaker than a customer click and stronger than a
-- silent default, and it is labelled as what it is rather than dressed up as consent.
CREATE TABLE IF NOT EXISTS soar_protected_ack (
  tenant_id      uuid PRIMARY KEY,
  acked_at       timestamptz NOT NULL DEFAULT now(),
  acked_by       uuid NOT NULL,               -- the platform admin who recorded the attestation
  acked_by_email text NOT NULL DEFAULT '',
  confirmed_with text NOT NULL,               -- who AT THE CUSTOMER confirmed there are no crown jewels
  note           text NOT NULL DEFAULT ''
);
ALTER TABLE soar_protected_ack ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_protected_ack FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_protected_ack_rw ON soar_protected_ack;
CREATE POLICY soar_protected_ack_rw ON soar_protected_ack
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());

-- Policy/grant parity: every cmd a policy permits needs the matching table grant, or the role hits "permission
-- denied" at runtime while local/CI (superuser-owner) sails through. That class shipped once already in 0066/0098
-- and was retired by 0117 plus a schemacheck fence — this table is written to satisfy that fence from birth.
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_protected_ack TO nirvet_app;
