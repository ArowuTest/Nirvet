-- §6.11 G1 — Okta identity-containment action catalog rows (first non-Microsoft response vendor).
-- Action keys are vendor-prefixed (okta_*) because soar_action_catalog is keyed by action_key alone and its
-- connector_key column DRIVES routing: a bare 'revoke_sessions' already maps to entra-id (0036), so an Okta
-- session-revoke step would misroute. The unsuspend transition is the registered INVERSE (registry-only, invoked
-- by reverse) — like Entra's enable_user it is NOT a standalone catalog step action, so it is not seeded here.
-- suspend = high (§9.5, reversible identity containment); revoke_sessions = medium (non-destructive, idempotent).
-- Global rows (tenant_id NULL); a tenant may override class/executor with its own row (same RLS as playbooks).
INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key) VALUES
  (NULL, 'okta_suspend_user',    'Suspend Okta user account', 'high',   'connector', 'okta'),
  (NULL, 'okta_revoke_sessions', 'Revoke Okta user sessions', 'medium', 'connector', 'okta')
ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key) DO NOTHING;
