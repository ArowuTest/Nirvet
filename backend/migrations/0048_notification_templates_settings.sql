-- §6.16 notification slice C: templates + localization (COMM-007/008) and throttle/digest settings
-- (COMM-006). Secure expiring links (COMM-009) are stateless (HMAC), no schema.

-- Templates: global defaults + tenant-custom, per channel, per locale. {{var}} placeholders rendered at
-- send time. Locale selection: requested locale, else the tenant/global 'en' fallback.
CREATE TABLE IF NOT EXISTS notification_templates (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid,                          -- NULL = global template
  key        text NOT NULL,                 -- incident_opened | sla_breach | ...
  channel    text NOT NULL DEFAULT 'email', -- email | sms | log | webhook | slack | teams | any
  locale     text NOT NULL DEFAULT 'en',
  subject    text NOT NULL DEFAULT '',
  body       text NOT NULL DEFAULT '',
  enabled    boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, key, channel, locale)
);
CREATE INDEX IF NOT EXISTS notification_templates_lookup ON notification_templates (key, channel, locale);

ALTER TABLE notification_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_templates_select ON notification_templates;
DROP POLICY IF EXISTS notification_templates_insert ON notification_templates;
DROP POLICY IF EXISTS notification_templates_update ON notification_templates;
DROP POLICY IF EXISTS notification_templates_delete ON notification_templates;
CREATE POLICY notification_templates_select ON notification_templates
  FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY notification_templates_insert ON notification_templates
  FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY notification_templates_update ON notification_templates
  FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY notification_templates_delete ON notification_templates
  FOR DELETE USING (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_templates TO nirvet_app;

-- Per-tenant notification settings: throttle window (de-dupe repeated identical notifications) and a
-- default locale. throttle_window_seconds = 0 disables throttling.
CREATE TABLE IF NOT EXISTS notification_settings (
  tenant_id              uuid PRIMARY KEY DEFAULT app_current_tenant(),
  throttle_window_seconds int NOT NULL DEFAULT 0,
  default_locale         text NOT NULL DEFAULT 'en',
  updated_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT notification_settings_window_chk CHECK (throttle_window_seconds BETWEEN 0 AND 86400)
);
ALTER TABLE notification_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON notification_settings;
CREATE POLICY tenant_isolation ON notification_settings
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_settings TO nirvet_app;

-- Seed a few global default templates (en). Tenants override by inserting their own (key,channel,locale).
INSERT INTO notification_templates (tenant_id, key, channel, locale, subject, body) VALUES
  (NULL,'incident_opened','email','en','Incident opened: {{title}}',
   'A {{severity}} incident "{{title}}" was opened. Reference: {{incident_id}}.'),
  (NULL,'sla_breach','email','en','SLA breach ({{kind}}): {{title}}',
   'Incident {{incident_id}} ({{severity}}) has breached its {{kind}} SLA deadline.'),
  (NULL,'incident_opened','sms','en','','[{{severity}}] Incident opened: {{title}} ({{incident_id}})')
ON CONFLICT (tenant_id, key, channel, locale) DO NOTHING;
