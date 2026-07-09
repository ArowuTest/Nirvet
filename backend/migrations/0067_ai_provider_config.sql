-- §6.12 #117 A-1 — admin-configurable AI providers (SRS §1454/§1903/§3842 conformance debt). Config-first: the
-- LLM provider/endpoint/model becomes an admin-tunable DB record with a seeded default, replacing the hardcoded
-- api.anthropic.com gateway. Three tables:
--   * ai_provider                    — the resolved provider per (tenant, else global). tenant_id NULL = global default.
--   * ai_provider_allowed_endpoint   — platform-admin trust list of permitted model endpoints. This allowlist IS a
--                                      DATA-EGRESS / RESIDENCY control (§1903), not merely SSRF hardening: it is the
--                                      only set of hosts a tenant's data may be sent to. Global platform config (no
--                                      tenant dimension), like soar_platform.
--   * tenant_ai_policy               — per-tenant restriction (allowed provider kinds). Platform-admin-set; a tenant
--                                      may only TIGHTEN within it (enforced at the handler, same as SOAR/detection).
--
-- Load-bearing design note (see build/ARCHITECTURE_GATES.md "Admin-Configurable AI Providers"): the openai_compatible
-- endpoint is guarded by the ALLOWLIST, NOT by netsafe/IsInternalHost — a sovereign self-hosted model legitimately
-- lives on a private address. Internal ≠ malicious here; the platform-admin-curated allowlist is the trust boundary.

-- ── ai_provider ───────────────────────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_provider (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid,                                   -- NULL = global default (resolver falls back to it)
  provider_kind text NOT NULL,                          -- anthropic | openai_compatible | disabled
  base_url      text,                                   -- required iff openai_compatible; must match an allowlisted endpoint
  model         text NOT NULL DEFAULT '',               -- '' = provider's configured default
  api_key_ref   text,                                   -- vault ref; NULL = keyless (local model) OR anthropic-from-config default
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_provider_kind_chk CHECK (provider_kind IN ('anthropic','openai_compatible','disabled')),
  -- base_url present exactly when the kind is a generic HTTP endpoint we must point at a host.
  CONSTRAINT ai_provider_base_url_chk CHECK (
    (provider_kind =  'openai_compatible' AND base_url IS NOT NULL) OR
    (provider_kind <> 'openai_compatible' AND base_url IS NULL)
  )
);
-- One provider row per tenant, and exactly one global row. Expression index (COALESCE maps the global NULL to a
-- fixed sentinel) so only a single global row is allowed; this is an index, not a table UNIQUE constraint, so it
-- carries tenant_id by construction (schemacheck guard #2 is satisfied — cf. protected_identities in 0066).
CREATE UNIQUE INDEX IF NOT EXISTS ai_provider_tenant_uq
  ON ai_provider (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

ALTER TABLE ai_provider ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_provider FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_provider_select ON ai_provider;
DROP POLICY IF EXISTS ai_provider_insert ON ai_provider;
DROP POLICY IF EXISTS ai_provider_update ON ai_provider;
DROP POLICY IF EXISTS ai_provider_delete ON ai_provider;
-- Read own + global (resolver: tenant row wins, else global). Write own only (the global row is written by a
-- platform admin via the system context, like soar_platform); a tenant can never write/overwrite the global row.
CREATE POLICY ai_provider_select ON ai_provider
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY ai_provider_insert ON ai_provider
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_provider_update ON ai_provider
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY ai_provider_delete ON ai_provider
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_provider TO nirvet_app;

-- Seed the current default as the GLOBAL provider so existing tenants are byte-for-byte unchanged: anthropic,
-- api_key_ref NULL → the anthropicProvider uses the platform-configured Anthropic key (cfg.AnthropicAPIKey) exactly
-- as today, model '' → the gateway default. Idempotent.
INSERT INTO ai_provider (tenant_id, provider_kind, model, api_key_ref)
  VALUES (NULL, 'anthropic', '', NULL)
  ON CONFLICT DO NOTHING;

-- ── ai_provider_allowed_endpoint ──────────────────────────────────────────────────────────────────────────────
-- Platform-admin trust list. No tenant dimension: the allowlist is a platform-wide data-egress boundary (any tenant
-- pointing openai_compatible at a host must match one of these). http is permitted only for an explicitly-approved
-- on-prem endpoint (a cleartext-key warning is surfaced at save time — handler concern, A-4).
CREATE TABLE IF NOT EXISTS ai_provider_allowed_endpoint (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scheme     text NOT NULL,                             -- http | https
  host       text NOT NULL,                             -- lower-cased host
  port       int  NOT NULL DEFAULT 0,                   -- 0 = default port for the scheme
  note       text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_allowed_scheme_chk CHECK (scheme IN ('http','https')),
  CONSTRAINT ai_allowed_port_chk   CHECK (port >= 0 AND port <= 65535),
  UNIQUE (scheme, host, port)                            -- no tenant_id column → guard #2 N/A (platform-global config)
);
GRANT SELECT, INSERT, DELETE ON ai_provider_allowed_endpoint TO nirvet_app;

-- ── tenant_ai_policy ──────────────────────────────────────────────────────────────────────────────────────────
-- Per-tenant restriction on which provider kinds are permitted (§1903 data-routing restriction by tenant). Default
-- = all kinds allowed; a sovereign tenant is pinned to e.g. {openai_compatible,disabled}. Platform-admin-set; the
-- tenant handler may only choose a kind WITHIN allowed_kinds (tighten-only), never widen it.
CREATE TABLE IF NOT EXISTS tenant_ai_policy (
  tenant_id     uuid PRIMARY KEY,
  allowed_kinds text[] NOT NULL DEFAULT ARRAY['anthropic','openai_compatible','disabled'],
  updated_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_ai_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_ai_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_ai_policy_rw ON tenant_ai_policy;
CREATE POLICY tenant_ai_policy_rw ON tenant_ai_policy
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_ai_policy TO nirvet_app;
