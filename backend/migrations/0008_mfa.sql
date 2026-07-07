-- MFA (TOTP). The shared secret is stored vault-encrypted (bytea). The auth
-- lookup is extended to return the MFA fields so login can enforce it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret bytea;

-- Return-type change requires a drop first (Postgres won't REPLACE it in place).
DROP FUNCTION IF EXISTS auth_find_user_by_email(text);
CREATE FUNCTION auth_find_user_by_email(p_email text)
RETURNS TABLE (id uuid, tenant_id uuid, email text, password_hash text, role text, status text,
               mfa_enabled boolean, mfa_secret bytea)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, email, password_hash, role, status, mfa_enabled, mfa_secret
    FROM users WHERE lower(email) = lower(p_email) LIMIT 1
$$;
