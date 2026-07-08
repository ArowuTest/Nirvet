-- §6.16 notification slice B: per-tenant sender config for real email (SMTP) and SMS channels
-- (COMM-001). The sender secret (SMTP password / SMS API key) is stored vault-encrypted (per-tenant
-- crypto.SecretCipher ciphertext) and is never returned by the API.

CREATE TABLE IF NOT EXISTS notification_senders (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL DEFAULT app_current_tenant(),
  channel           text NOT NULL,               -- email | sms
  from_address      text NOT NULL DEFAULT '',    -- email: From; sms: sender id / from number
  -- email (SMTP) config
  smtp_host         text NOT NULL DEFAULT '',
  smtp_port         int  NOT NULL DEFAULT 587,
  smtp_username     text NOT NULL DEFAULT '',
  -- sms config
  provider_url      text NOT NULL DEFAULT '',    -- SMS provider POST endpoint
  -- shared: vault-encrypted secret (SMTP password OR SMS API key)
  secret_ciphertext bytea,
  enabled           boolean NOT NULL DEFAULT true,
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, channel),
  CONSTRAINT notification_senders_channel_chk CHECK (channel IN ('email','sms')),
  CONSTRAINT notification_senders_port_chk CHECK (smtp_port BETWEEN 1 AND 65535)
);

ALTER TABLE notification_senders ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_senders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON notification_senders;
CREATE POLICY tenant_isolation ON notification_senders
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_senders TO nirvet_app;
