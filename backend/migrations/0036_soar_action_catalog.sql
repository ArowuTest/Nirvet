-- SOAR action catalog (SRS §6.11 SOAR-002/004, §9.5 risk classes). The action catalog is the
-- config that turns each playbook step's action_key into (a) a §9.5 RISK CLASS and (b) an EXECUTOR
-- kind — admin-configurable data with a seeded default, so the risk class is no longer hardcoded in
-- every playbook step's JSON (owner no-hardcoding rule). A step whose action is absent from the
-- catalog fails closed to 'business_critical' (max approval) in code — never permissive.
--
-- risk_class is the five-level §9.5 scale (Class 0..4). executor is how the engine dispatches:
--   internal  = a Nirvet-native service (e.g. notify via the durable outbox) — some real today
--   connector = a source/EDR/IdP connector action (isolate, disable, block) — real once the live
--               Actioner registry exists; until then the engine records a truthful 'simulated'
--   manual    = a human/customer must act (request_customer_action) — recorded 'awaiting_customer'
-- Global rows (tenant_id NULL) ship the default catalog; a tenant may override an action's class or
-- executor with its own row (same RLS shape as playbooks).

CREATE TABLE IF NOT EXISTS soar_action_catalog (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid,                       -- NULL = global default; else tenant override
  action_key    text NOT NULL,
  title         text NOT NULL DEFAULT '',
  risk_class    text NOT NULL DEFAULT 'business_critical'
                  CHECK (risk_class IN ('informational','low','medium','high','business_critical')),
  executor      text NOT NULL DEFAULT 'connector'
                  CHECK (executor IN ('internal','connector','manual')),
  connector_key text NOT NULL DEFAULT '',   -- for executor='connector': which connector would run it
  enabled       boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);
-- One row per action_key per scope. tenant_id is NULLable and Postgres treats NULLs as distinct in
-- a UNIQUE, so use a COALESCE expression index to enforce "one global + one per tenant" per action.
CREATE UNIQUE INDEX IF NOT EXISTS soar_action_catalog_scope_key
  ON soar_action_catalog (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key);

ALTER TABLE soar_action_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_action_catalog FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON soar_action_catalog;
CREATE POLICY tenant_isolation ON soar_action_catalog
  USING (tenant_id = app_current_tenant() OR tenant_id IS NULL)   -- read global + own
  WITH CHECK (tenant_id = app_current_tenant());                  -- write only own (never global)
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_action_catalog TO nirvet_app;

-- Seed the global default catalog (SOAR-002 actions + §9.5 classes). Runs as the migration
-- superuser (bypasses RLS). Classes follow §9.5: Class0 informational, Class1 low, Class2 medium,
-- Class3 high (disable/revoke/isolate/block/quarantine), Class4 business_critical (no autonomy).
INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key) VALUES
  (NULL, 'enrich',                  'Enrich indicator / entity',      'informational', 'internal',  ''),
  (NULL, 'create_note',             'Add internal case note',         'informational', 'internal',  ''),
  (NULL, 'inspect_mailbox',         'Inspect mailbox rules / OAuth',  'low',           'connector', 'microsoft-365'),
  (NULL, 'notify_analyst',          'Notify internal analyst',        'low',           'internal',  ''),
  (NULL, 'create_ticket',           'Create ITSM ticket',             'low',           'internal',  ''),
  (NULL, 'add_watchlist',           'Add watchlist / IOC',            'low',           'internal',  ''),
  (NULL, 'collect_evidence',        'Collect evidence pack',          'low',           'internal',  ''),
  (NULL, 'generate_report',         'Generate report',               'low',           'internal',  ''),
  (NULL, 'notify_customer',         'Customer notification',          'medium',        'internal',  ''),
  (NULL, 'request_customer_action', 'Request customer action',        'medium',        'manual',    ''),
  (NULL, 'reset_password',          'Request password reset',         'medium',        'connector', 'entra-id'),
  (NULL, 'mark_email_review',       'Mark email for review',          'medium',        'connector', 'microsoft-365'),
  (NULL, 'disable_user',            'Disable user account',           'high',          'connector', 'entra-id'),
  (NULL, 'revoke_sessions',         'Revoke user sessions',           'high',          'connector', 'entra-id'),
  (NULL, 'isolate_endpoint',        'Isolate endpoint',               'high',          'connector', 'defender'),
  (NULL, 'block_ip',                'Block IP',                       'high',          'connector', 'defender'),
  (NULL, 'block_domain',            'Block domain',                   'high',          'connector', 'defender'),
  (NULL, 'block_hash',              'Block file hash',                'high',          'connector', 'defender'),
  (NULL, 'quarantine_email',        'Quarantine email',               'high',          'connector', 'microsoft-365'),
  (NULL, 'network_block_all',       'Network-wide block',             'business_critical', 'connector', ''),
  (NULL, 'mass_quarantine',         'Mass quarantine',                'business_critical', 'connector', ''),
  (NULL, 'cloud_lockdown',          'Cloud account lockdown',         'business_critical', 'connector', '')
ON CONFLICT DO NOTHING;
