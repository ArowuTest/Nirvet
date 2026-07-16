-- Index for the access-review last-login lookup (reviewer efficiency finding).
--
-- iam/accessreview.go runs a correlated subquery PER USER:
--   (SELECT max(at) FROM audit_log a WHERE a.actor_id = u.id AND a.action = 'auth.login')
-- The only audit_log indexes were (tenant_id, at DESC) and the action trigram — neither helps a
-- (actor_id, action) equality lookup, so each user's subquery scanned the tenant's audit_log slice. On a busy
-- tenant with a long-lived, append-only audit_log that is an N+1 over an ever-growing table: the access-review
-- page gets slower every day it runs.
--
-- (actor_id, action, at DESC) turns each subquery into an index-range read whose first row IS the max(at) — no
-- scan, no sort. Composite order matters: the two equality columns first, the ordered column last so max(at) is
-- the leading edge of the matched range. audit_log is append-only + immutable (0017), so an added index is pure
-- upside with no write-path correctness concern.
CREATE INDEX IF NOT EXISTS audit_log_actor_action_at
  ON audit_log (actor_id, action, at DESC);
