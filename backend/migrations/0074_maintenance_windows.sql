-- §6.18 #122 P-4 — maintenance windows (ADMIN-008) + protected-flag time-box (Reinf-B). A maintenance window may
-- suppress NOTIFICATIONS and/or pause SLA timers, but ingestion/detection/correlation/incident-creation continue —
-- a window is never a detection blackout, and a CRITICAL (P1) breaks through suppression (M-2, enforced in code).

-- Reinf-B: a protected flag flipped less-secure is time-boxed; a sweep reverts it to its secure default at expiry so
-- a forgotten temporary loosening cannot persist indefinitely.
ALTER TABLE platform_feature_flags ADD COLUMN IF NOT EXISTS expires_at timestamptz;

CREATE TABLE IF NOT EXISTS maintenance_windows (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope                  text NOT NULL DEFAULT 'global',   -- global | tenant
  scope_ref              text NOT NULL DEFAULT '',         -- tenant_id (text) for scope='tenant'
  starts_at              timestamptz NOT NULL,
  ends_at                timestamptz NOT NULL,
  suppress_notifications boolean NOT NULL DEFAULT false,
  pause_sla              boolean NOT NULL DEFAULT false,
  banner                 text NOT NULL DEFAULT '',
  created_by             uuid,
  created_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT maintenance_windows_scope_chk CHECK (scope IN ('global','tenant')),
  CONSTRAINT maintenance_windows_time_chk  CHECK (ends_at > starts_at)
);
CREATE INDEX IF NOT EXISTS maintenance_windows_active ON maintenance_windows (scope, scope_ref, ends_at);
-- Platform/tenant ops config, consulted system-side by the notify/SLA path. No tenant RLS (no tenant_id column).
GRANT SELECT, INSERT, DELETE ON maintenance_windows TO nirvet_app;
