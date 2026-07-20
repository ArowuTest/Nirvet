-- 0138 — §6.14 B3: jurisdictional retention (gate build/GOLIVE_JURISDICTIONAL_RETENTION_GATE.md).
--
-- Adds a JURISDICTION axis to the retention window. A jurisdiction imposes a FLOOR (retain >= min_retain_days —
-- LENGTHENS retention, only preserves → safe, armed now) and/or a CEILING (delete after max_retain_days — SHORTENS
-- the window → the ONE direction that destroys evidence earlier → its destructive enforcement stays DORMANT behind
-- jurisdiction_delete_armed=false until the go-live arm). The effective window is computed by the SINGLE producer
-- retention.resolveWindow as:  max( floor, min(tenant_window, entitlement, ceiling) )  — floor is the OUTER max so a
-- contradiction (floor>ceiling) resolves toward RETENTION (the floor wins). legal_hold is ABOVE the formula (a held
-- tenant is never swept; the SD delete fns also refuse on hold, mig 0116). Unknown jurisdiction → no floor/ceiling
-- (fail toward retention, never invent a delete window). All still fails safe: dry-run default, tighten-only tenant.

-- ── jurisdiction_retention: operator (platform_admin) config, keyed by the tenant's country ───────────────────────
CREATE TABLE IF NOT EXISTS jurisdiction_retention (
  jurisdiction_key text        PRIMARY KEY,                 -- matches tenants.country
  name             text        NOT NULL DEFAULT '',
  min_retain_days  int,                                     -- FLOOR: retain >= this many days (NULL/0 = no floor)
  max_retain_days  int,                                     -- CEILING: delete after this many days (NULL = no ceiling)
  updated_by       uuid,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  -- Both may coexist even when floor>ceiling: resolveWindow resolves the contradiction toward the floor (retain
  -- longer). We do NOT reject it here — a mandated-retention floor must never be un-settable because a ceiling exists.
  CONSTRAINT jurisdiction_min_chk CHECK (min_retain_days IS NULL OR min_retain_days >= 0),
  CONSTRAINT jurisdiction_max_chk CHECK (max_retain_days IS NULL OR max_retain_days >= 1)
);
-- No rows seeded: an operator adds its sovereign regime as DATA. Unknown jurisdiction on a tenant → no clamp (retain).

ALTER TABLE jurisdiction_retention ENABLE ROW LEVEL SECURITY;
ALTER TABLE jurisdiction_retention FORCE ROW LEVEL SECURITY;
-- Read: any authenticated context may read it — it is a retention INPUT read at every sweep (which runs per-tenant),
-- and the windows are not sensitive. Write: platform-admin (system, app_current_tenant() IS NULL) ONLY — a sovereign
-- regime is operator-level, a tenant can never set its own jurisdiction windows (same isolation as mfa_enforcement_floor).
DROP POLICY IF EXISTS jurisdiction_retention_read ON jurisdiction_retention;
CREATE POLICY jurisdiction_retention_read ON jurisdiction_retention FOR SELECT USING (true);
DROP POLICY IF EXISTS jurisdiction_retention_write ON jurisdiction_retention;
CREATE POLICY jurisdiction_retention_write ON jurisdiction_retention FOR ALL
  USING (app_current_tenant() IS NULL) WITH CHECK (app_current_tenant() IS NULL);
DROP POLICY IF EXISTS owner_bypass ON jurisdiction_retention;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON jurisdiction_retention USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;
GRANT SELECT, INSERT, UPDATE ON jurisdiction_retention TO nirvet_app;

-- ── jurisdiction_delete_armed: the go-live arm for the CEILING's destructive enforcement (singleton, seeded false) ──
-- The floor + tighten-only tenant deletion are already safe/live. This flag gates ONLY the case where a jurisdiction
-- CEILING is the binding constraint that shortens the window BELOW what tenant/entitlement alone would give (i.e. the
-- ceiling deletes evidence earlier). Seeded false = dormant: the ceiling still participates in the window compute and
-- the DRY-RUN report (an operator SEES what it would delete), but performs no destructive delete until an operator
-- flips this at go-live (step D-arm-retention: after KMS + backup drill + retention soak). Reachable + dry-runnable,
-- not dead code (reachability invariant).
CREATE TABLE IF NOT EXISTS jurisdiction_delete_armed (
  id         smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- singleton
  armed      boolean     NOT NULL DEFAULT false,
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO jurisdiction_delete_armed (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

ALTER TABLE jurisdiction_delete_armed ENABLE ROW LEVEL SECURITY;
ALTER TABLE jurisdiction_delete_armed FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jurisdiction_delete_armed_read ON jurisdiction_delete_armed;
CREATE POLICY jurisdiction_delete_armed_read ON jurisdiction_delete_armed FOR SELECT USING (true);
DROP POLICY IF EXISTS jurisdiction_delete_armed_write ON jurisdiction_delete_armed;
CREATE POLICY jurisdiction_delete_armed_write ON jurisdiction_delete_armed FOR ALL
  USING (app_current_tenant() IS NULL) WITH CHECK (app_current_tenant() IS NULL);
DROP POLICY IF EXISTS owner_bypass ON jurisdiction_delete_armed;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON jurisdiction_delete_armed USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;
GRANT SELECT, INSERT, UPDATE ON jurisdiction_delete_armed TO nirvet_app;

-- ── retention_jurisdiction_ledger: attribution — every sweep where a jurisdiction rule participated records the
-- rule + the windows it produced, so a (wrongful, irreversible) jurisdictional delete is always attributable. Written
-- for dry-runs too, so the ceiling's dormant would-delete is on the record before it ever arms. Append-only.
CREATE TABLE IF NOT EXISTS retention_jurisdiction_ledger (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid        NOT NULL DEFAULT app_current_tenant(),
  jurisdiction_key text        NOT NULL,
  floor_days       int         NOT NULL DEFAULT 0,          -- 0 = none
  ceiling_days     int         NOT NULL DEFAULT 0,          -- 0 = none
  base_days        int         NOT NULL,                    -- window WITHOUT the ceiling (floor + tenant/entitlement)
  effective_days   int         NOT NULL,                    -- window used for the ACTUAL delete (armed? full : base)
  ceiling_binds    boolean     NOT NULL DEFAULT false,      -- the ceiling shortened the window below base
  armed            boolean     NOT NULL DEFAULT false,      -- was ceiling enforcement armed at this sweep
  store            text        NOT NULL,                    -- raw_events | events
  deleted_count    bigint      NOT NULL DEFAULT 0,
  dry_run          boolean     NOT NULL,
  at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS retention_jurisdiction_ledger_tenant_at ON retention_jurisdiction_ledger (tenant_id, at DESC);

ALTER TABLE retention_jurisdiction_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_jurisdiction_ledger FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON retention_jurisdiction_ledger;
CREATE POLICY tenant_isolation ON retention_jurisdiction_ledger
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
DROP POLICY IF EXISTS owner_bypass ON retention_jurisdiction_ledger;
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_bypass ON retention_jurisdiction_ledger USING (current_user = %L) WITH CHECK (current_user = %L)',
                 current_user, current_user);
END $$;
-- Append-only: no UPDATE/DELETE grant (attribution is immutable).
GRANT SELECT, INSERT ON retention_jurisdiction_ledger TO nirvet_app;
