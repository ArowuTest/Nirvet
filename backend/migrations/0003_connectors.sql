-- Connector configurations (SRS §6.4, §8; ADR-0004). Credentials are stored
-- vault-encrypted (secret_ciphertext); webhook connectors store a hashed source
-- key for authenticated ingestion.

CREATE TABLE IF NOT EXISTS connector_configs (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL DEFAULT app_current_tenant(),
  kind              text NOT NULL,             -- microsoft-365 | entra-id | defender | syslog | webhook
  name              text NOT NULL,
  direction         text NOT NULL DEFAULT 'read',
  enabled           boolean NOT NULL DEFAULT true,
  secret_ciphertext bytea,                     -- vault-sealed credential (never plaintext)
  key_hash          text,                      -- sha256 of the webhook source key
  config            jsonb NOT NULL DEFAULT '{}',
  health            text NOT NULL DEFAULT 'unknown',
  last_success      timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS connector_configs_tenant ON connector_configs (tenant_id, kind);

ALTER TABLE connector_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON connector_configs;
CREATE POLICY tenant_isolation ON connector_configs
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON connector_configs TO nirvet_app;

-- Unauthenticated webhook ingestion looks up a connector by id to verify the
-- source key. SECURITY DEFINER (controlled, minimal) — like the auth lookup.
CREATE OR REPLACE FUNCTION connector_find_for_webhook(p_id uuid)
RETURNS TABLE (tenant_id uuid, key_hash text, enabled boolean, kind text)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT tenant_id, key_hash, enabled, kind FROM connector_configs WHERE id = p_id
$$;
GRANT EXECUTE ON FUNCTION connector_find_for_webhook(uuid) TO nirvet_app;
