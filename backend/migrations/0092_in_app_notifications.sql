-- 0092_in_app_notifications.sql — §6.16 in-app notification feed (launch-line, light).
-- A per-user inbox. RLS enforces the TENANT boundary; the USER boundary (recipient_id = the caller) is enforced
-- in the query layer (every read/update filters recipient_id = $caller) — a user sees ONLY their own notifications,
-- never another user's or another tenant's. No new egress: rows are written by in-process producers (NotifyInApp).

CREATE TABLE IF NOT EXISTS in_app_notifications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT app_current_tenant(),
  recipient_id uuid NOT NULL,               -- the user this notification is addressed to
  kind         text NOT NULL DEFAULT 'info',
  subject      text NOT NULL,
  body         text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  read_at      timestamptz                  -- NULL = unread
);
ALTER TABLE in_app_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE in_app_notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON in_app_notifications;
CREATE POLICY tenant_isolation ON in_app_notifications
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON in_app_notifications TO nirvet_app;
-- Serves the hot query "my inbox, unread first, newest first" without a scan.
CREATE INDEX IF NOT EXISTS in_app_notifications_recipient
  ON in_app_notifications (tenant_id, recipient_id, created_at DESC);

-- Basic per-user preference: a user may disable their own in-app feed. Scoped to (tenant, user) like the feed —
-- prefs never cross the user/tenant boundary. Default enabled (seeded implicitly by absence = enabled).
CREATE TABLE IF NOT EXISTS notification_user_prefs (
  tenant_id      uuid NOT NULL DEFAULT app_current_tenant(),
  user_id        uuid NOT NULL,
  in_app_enabled boolean NOT NULL DEFAULT true,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);
ALTER TABLE notification_user_prefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_user_prefs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON notification_user_prefs;
CREATE POLICY tenant_isolation ON notification_user_prefs
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON notification_user_prefs TO nirvet_app;
