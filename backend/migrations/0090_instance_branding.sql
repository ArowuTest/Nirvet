-- 0090_instance_branding.sql — white-label branding (Ghana operator L). INSTANCE-level, not per-tenant.
--
-- On a dedicated single-operator instance the operator's branding is one thing for the whole instance — a
-- SINGLETON, not per-tenant data threaded through the isolation model (that would be a heavier, cross-tenant
-- surface). Public presentation only (name, logo, color, support email); padmin-managed. The `singleton`
-- boolean PK + CHECK guarantees at most one row (a well-known one-row-table idiom).
CREATE TABLE IF NOT EXISTS instance_branding (
  singleton     boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  operator_name text NOT NULL DEFAULT 'Nirvet',
  logo_url      text NOT NULL DEFAULT '',
  primary_color text NOT NULL DEFAULT '',
  support_email text NOT NULL DEFAULT '',
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Seed the single row so the public read always finds defaults (never unconfigured).
INSERT INTO instance_branding (singleton) VALUES (true) ON CONFLICT (singleton) DO NOTHING;

-- No per-tenant RLS: instance-level config, publicly readable, padmin-writable.
GRANT SELECT, INSERT, UPDATE ON instance_branding TO nirvet_app;
