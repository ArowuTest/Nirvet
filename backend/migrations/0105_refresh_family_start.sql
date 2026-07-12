-- 0105_refresh_family_start.sql — ADR-0007 absolute refresh-family lifetime cap (reviewer landing LOW #2).
-- expires_at is a SLIDING window (each rotation resets it), so a continuously-rotated chain — including one a
-- thief keeps alive by rotating faster than the victim — could live indefinitely. family_started_at records when
-- the family was first minted at login; it is carried UNCHANGED to every successor. RedeemRefresh enforces an
-- absolute cap (family_started_at + ABSOLUTE_TTL) so even an active chain forces a full re-login eventually.

ALTER TABLE refresh_tokens
  ADD COLUMN IF NOT EXISTS family_started_at timestamptz NOT NULL DEFAULT now();

-- Re-declare the pre-auth SD lookup to also return family_started_at (append-only to the row shape). CREATE OR
-- REPLACE cannot change a function's RETURNS TABLE shape, so DROP first.
DROP FUNCTION IF EXISTS auth_find_refresh_by_hash(text);
CREATE OR REPLACE FUNCTION auth_find_refresh_by_hash(p_hash text)
RETURNS TABLE (id uuid, tenant_id uuid, user_id uuid, family_id uuid, user_gen bigint, tenant_gen bigint,
               used_at timestamptz, revoked_at timestamptz, expires_at timestamptz, family_started_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, tenant_id, user_id, family_id, user_gen, tenant_gen, used_at, revoked_at, expires_at, family_started_at
    FROM refresh_tokens WHERE token_hash = p_hash LIMIT 1
$$;
REVOKE ALL ON FUNCTION auth_find_refresh_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_find_refresh_by_hash(text) TO nirvet_app;

-- Reaper (reviewer landing LOW #4): a background loop deletes refresh rows that can no longer be redeemed. This
-- is a cross-tenant maintenance sweep with no tenant/session context, so it runs as SECURITY DEFINER (RLS would
-- otherwise block a no-tenant DELETE). A row is purged once it is (a) past its own sliding expiry, OR (b) part of
-- a family older than the absolute cap — in both cases it is already un-redeemable, so deleting it removes no
-- live reuse-detection tripwire (a replay of an expired token is rejected on expiry anyway). p_absolute_cap is
-- passed from Go so the SQL cap stays in lockstep with absoluteRefreshFamilyTTL. Returns the number deleted.
CREATE OR REPLACE FUNCTION auth_purge_dead_refresh_tokens(p_absolute_cap interval)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  n bigint;
BEGIN
  DELETE FROM refresh_tokens
   WHERE expires_at < now()
      OR family_started_at < now() - p_absolute_cap;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION auth_purge_dead_refresh_tokens(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_purge_dead_refresh_tokens(interval) TO nirvet_app;
