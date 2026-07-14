-- AI copilot investigation workspace (SRS §6.12 AI-001, UI-depth Bucket B / B1). A persisted multi-turn analyst
-- copilot. Sessions are PRIVATE to the creating analyst (user_id) within their tenant; turns belong to a session.
-- Both tables are tenant-scoped with RLS FORCE + the owner_bypass policy (managed-PG SECURITY DEFINER + FORCE RLS
-- requirement, see mig 0118/0122). All LLM egress still flows through ai.Service.completeExternal (redaction
-- chokepoint, #188) — this migration only stores the conversation; it opens no new egress path.

CREATE TABLE IF NOT EXISTS ai_copilot_sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  user_id      uuid NOT NULL,              -- owning analyst; sessions are private to their creator
  title        text NOT NULL DEFAULT 'New investigation',
  incident_ref uuid,                        -- optional grounding: an incident the conversation is about
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_copilot_sessions_owner
  ON ai_copilot_sessions (tenant_id, user_id, updated_at DESC);

ALTER TABLE ai_copilot_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_copilot_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_copilot_sessions;
CREATE POLICY tenant_isolation ON ai_copilot_sessions
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
-- owner_bypass is added for both new tables by the follow-up loop in 0124 (same pattern as 0121→0122): the
-- migrating owner's role name is only known at run time, so it is applied via the DO-loop that captures
-- current_user, not hand-written here (a literal tautology would defeat tenant isolation).
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_copilot_sessions TO nirvet_app;

CREATE TABLE IF NOT EXISTS ai_copilot_turns (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  session_id uuid NOT NULL REFERENCES ai_copilot_sessions (id) ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('user', 'assistant')),
  content    text NOT NULL,
  model      text,                          -- provider model for assistant turns (NULL for user turns)
  redaction  jsonb,                         -- audit-only redaction counts for assistant turns (never cleartext)
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ai_copilot_turns_session
  ON ai_copilot_turns (session_id, created_at);

ALTER TABLE ai_copilot_turns ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_copilot_turns FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_copilot_turns;
CREATE POLICY tenant_isolation ON ai_copilot_turns
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
-- owner_bypass added by 0124's loop (see note above).
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_copilot_turns TO nirvet_app;
