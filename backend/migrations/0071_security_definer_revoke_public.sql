-- #40 (reviewer Low from the #118 round) — defense-in-depth hardening. Every SECURITY DEFINER function bypasses RLS
-- (it runs as its owner), so it MUST NOT be executable by PUBLIC — only nirvet_app. The cohort from migration 0018
-- onward already REVOKEs PUBLIC + GRANTs nirvet_app, but the EARLY cohort (0003–0013: connector/sso/saml lookups,
-- and the auth_* lookups) never did, and 0070 regressed to that old pattern. Re-assert the invariant UNIFORMLY on
-- every SECURITY DEFINER function (idempotent — re-revoking an already-hardened one is a no-op). Not exploitable in a
-- single-nirvet_app-login deployment, but the right posture. A CI guard (scripts/check-security-definer-revoke.sh)
-- now prevents a new SECURITY DEFINER function from silently shipping without its REVOKE.

REVOKE ALL ON FUNCTION auth_find_api_key_by_prefix(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_api_key_by_prefix(text) TO nirvet_app;

REVOKE ALL ON FUNCTION auth_find_invitation_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_invitation_by_hash(text) TO nirvet_app;

REVOKE ALL ON FUNCTION auth_find_user_by_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(text) TO nirvet_app;

REVOKE ALL ON FUNCTION connector_find_for_webhook(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION connector_find_for_webhook(uuid) TO nirvet_app;

REVOKE ALL ON FUNCTION connector_list_pullers() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION connector_list_pullers() TO nirvet_app;

REVOKE ALL ON FUNCTION connector_silent_host_sources(double precision, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION connector_silent_host_sources(double precision, integer) TO nirvet_app;

REVOKE ALL ON FUNCTION incidents_sla_breaches(timestamp with time zone, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION incidents_sla_breaches(timestamp with time zone, integer) TO nirvet_app;

REVOKE ALL ON FUNCTION ingest_unenqueued_raw(timestamp with time zone, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingest_unenqueued_raw(timestamp with time zone, integer) TO nirvet_app;

REVOKE ALL ON FUNCTION notification_outbox_claim(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notification_outbox_claim(integer, integer) TO nirvet_app;

REVOKE ALL ON FUNCTION notification_outbox_pending(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION notification_outbox_pending(integer) TO nirvet_app;

REVOKE ALL ON FUNCTION saml_find_by_domain(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saml_find_by_domain(text) TO nirvet_app;

REVOKE ALL ON FUNCTION saml_get_connection(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saml_get_connection(uuid) TO nirvet_app;

REVOKE ALL ON FUNCTION soar_stale_executions(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION soar_stale_executions(integer) TO nirvet_app;

REVOKE ALL ON FUNCTION soar_unconfirmed_executions(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION soar_unconfirmed_executions(integer) TO nirvet_app;

REVOKE ALL ON FUNCTION sso_find_by_domain(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sso_find_by_domain(text) TO nirvet_app;

REVOKE ALL ON FUNCTION sso_get_connection(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sso_get_connection(uuid) TO nirvet_app;
