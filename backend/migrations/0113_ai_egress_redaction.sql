-- §6.12 #188 HEAVY-1 — AI-egress redaction. Before any customer telemetry leaves the sovereign platform to a
-- third-party LLM (anthropic / openai_compatible), a mask-by-default Redactor replaces PII/secret tokens and
-- identifier fields with STABLE PER-CALL placeholders. Config-first (no-hardcoding): the on/off + mode is a
-- per-tenant DB record with a seeded global default (mask-by-default), and the pattern SET is config-extensible
-- so a jurisdiction-specific identifier (e.g. Ghana Card) is addable by config, not a code change.
--
-- Two tables, both mirroring the ai_provider (0067) pattern: tenant_id NULL = global default, COALESCE unique
-- index (single global row), RLS ENABLE+FORCE, read own+global / write own only.

-- ── ai_redaction_policy ───────────────────────────────────────────────────────────────────────────────────────
--   enabled : master switch (default TRUE = mask-by-default).
--   mode    : balanced (default) = mask email/IP/secret/phone tokens EVERYWHERE + wholesale-mask identifier ref
--             fields (actor/target/source/asset refs); strict = balanced + also wholesale-mask free-text fields
--             (title/incident); off = no masking (an explicit, audited tenant choice for a trusted self-hosted LLM).
CREATE TABLE IF NOT EXISTS ai_redaction_policy (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid,                                        -- NULL = global default (resolver falls back to it)
  enabled    boolean NOT NULL DEFAULT true,
  mode       text    NOT NULL DEFAULT 'balanced',
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_redaction_mode_chk CHECK (mode IN ('balanced','strict','off'))
);
-- One row per tenant + exactly one global row (COALESCE maps the global NULL to a fixed sentinel). Expression
-- index (not a table UNIQUE) so it carries tenant_id by construction (schemacheck guard #2, cf. ai_provider).
CREATE UNIQUE INDEX IF NOT EXISTS ai_redaction_policy_tenant_uq
  ON ai_redaction_policy (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

ALTER TABLE ai_redaction_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_redaction_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_redaction_policy_select ON ai_redaction_policy;
DROP POLICY IF EXISTS ai_redaction_policy_insert ON ai_redaction_policy;
DROP POLICY IF EXISTS ai_redaction_policy_update ON ai_redaction_policy;
DROP POLICY IF EXISTS ai_redaction_policy_delete ON ai_redaction_policy;
CREATE POLICY ai_redaction_policy_select ON ai_redaction_policy
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY ai_redaction_policy_insert ON ai_redaction_policy
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_redaction_policy_update ON ai_redaction_policy
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_redaction_policy_delete ON ai_redaction_policy
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_redaction_policy TO nirvet_app;

-- Seed the GLOBAL default: mask-by-default, balanced. Existing tenants inherit it until they set their own row.
INSERT INTO ai_redaction_policy (tenant_id, enabled, mode)
  VALUES (NULL, true, 'balanced')
  ON CONFLICT DO NOTHING;

-- ── ai_redaction_pattern ──────────────────────────────────────────────────────────────────────────────────────
-- ADDITIONAL, config-extensible masking patterns on top of the built-in compiled floor (email / IPv4 / IPv6 /
-- secret-entropy / phone — always active in Go, never disable-able). tenant_id NULL = a global pattern applied to
-- every tenant. Each row: a name, a Go/RE2 regex (validated + compiled at write time), and a placeholder prefix
-- (e.g. 'GHANA_NID' → GHANA_NID_1). This is how a jurisdiction identifier is added WITHOUT a code change.
CREATE TABLE IF NOT EXISTS ai_redaction_pattern (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid,                                      -- NULL = global (applies to all tenants)
  name         text NOT NULL,
  regex        text NOT NULL,
  placeholder  text NOT NULL,                             -- placeholder prefix, e.g. GHANA_NID
  enabled      boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_redaction_pattern_regex_len_chk CHECK (char_length(regex) BETWEEN 1 AND 512),
  CONSTRAINT ai_redaction_pattern_ph_chk        CHECK (placeholder ~ '^[A-Z][A-Z0-9_]{0,31}$')
);
-- A tenant sees its own patterns + the global ones. Writes are own-only (a tenant cannot create/alter a global
-- pattern; global patterns are seeded here or written by a platform admin in the system context).
CREATE INDEX IF NOT EXISTS ai_redaction_pattern_scope_idx
  ON ai_redaction_pattern (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

ALTER TABLE ai_redaction_pattern ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_redaction_pattern FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_redaction_pattern_select ON ai_redaction_pattern;
DROP POLICY IF EXISTS ai_redaction_pattern_insert ON ai_redaction_pattern;
DROP POLICY IF EXISTS ai_redaction_pattern_update ON ai_redaction_pattern;
DROP POLICY IF EXISTS ai_redaction_pattern_delete ON ai_redaction_pattern;
CREATE POLICY ai_redaction_pattern_select ON ai_redaction_pattern
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY ai_redaction_pattern_insert ON ai_redaction_pattern
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_redaction_pattern_update ON ai_redaction_pattern
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_redaction_pattern_delete ON ai_redaction_pattern
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_redaction_pattern TO nirvet_app;

-- Seed a GLOBAL Ghana Card (NID) pattern — proves the config-extensibility ships now and gives the Ghana operator
-- pilot immediate value. Format: GHA-NNNNNNNNN-N (9 digits + check digit). RE2-safe, anchored to the token shape.
INSERT INTO ai_redaction_pattern (tenant_id, name, regex, placeholder, enabled)
  VALUES (NULL, 'ghana_card', 'GHA-[0-9]{9}-[0-9]', 'GHANA_NID', true)
  ON CONFLICT DO NOTHING;
