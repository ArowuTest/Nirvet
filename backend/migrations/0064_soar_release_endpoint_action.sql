-- §6.11 SOAR slice C: seed the reverse of isolate_endpoint so a contained host can be released
-- (SOAR-010 business continuity; MUST-3 inverse of the Defender isolate Actioner). Class 3 high like
-- isolate — releasing a contained host prematurely re-exposes it, so it is itself a high-impact action.
-- Global row (tenant_id NULL), tenant-overridable tighten-only like the rest of the catalog.
INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key) VALUES
  (NULL, 'release_endpoint', 'Release endpoint from isolation', 'high', 'connector', 'defender')
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key) DO NOTHING;
