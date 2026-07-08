-- Login brute-force hardening (SEC). Per-IP rate limiting alone misses a distributed
-- attack (many source IPs against one account), and X-Forwarded-For is spoofable. This
-- adds a durable, instance-independent per-account control: after repeated failures the
-- account is locked for a cool-off window. Counter + lock live on the user row so the
-- control holds across API replicas and Redis outages.

ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts int NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until timestamptz;

-- Extend the SECURITY DEFINER login lookup to surface the lockout state (return-type
-- change requires a drop first — Postgres won't REPLACE it in place).
DROP FUNCTION IF EXISTS auth_find_user_by_email(text);
CREATE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, password_hash text, role text, status text,
               mfa_enabled boolean, mfa_secret bytea,
               failed_login_attempts int, locked_until timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, password_hash, role, status, mfa_enabled, mfa_secret,
         failed_login_attempts, locked_until
    FROM users WHERE lower(email) = lower(p_email) LIMIT 1
$$;
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(text) TO nirvet_app;
