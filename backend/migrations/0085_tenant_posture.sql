-- 0085_tenant_posture.sql — Ghana operator seam #4 (MA-4): the vendor POSTURE store.
--
-- The vendor retains STANDING health/posture oversight so it can spot a neglected major issue and
-- flag/escalate — but has NO standing content read. This table is the metadata-only projection that makes
-- that control accreditation-defensible: it holds COUNTS + AGES + STATUS, never incident bodies/titles/
-- telemetry/IOCs. Two structural guards make "no content" true by construction, not by test:
--   * MA4-5 (storage twin): this table has NO free-text/jsonb column — only int, timestamptz, uuid. A buggy
--     projector CANNOT store a title/description/category here; there is nowhere to put it.
--   * (companion) MA-4 no-import-path: internal/posture imports no content package (CI-guarded); content is
--     unreachable from the posture READ path in Go, just as it is unstorable here in SQL.
-- `category` (a free text column on incidents) is DELIBERATELY excluded (MA4-4): a CSA auditor asking "what
-- can the vendor see" would flag the vendor learning each agency's incident CLASS — beyond neglect-detection.

CREATE TABLE IF NOT EXISTS tenant_posture (
  tenant_id        uuid PRIMARY KEY DEFAULT app_current_tenant(),
  open_total       int NOT NULL DEFAULT 0,   -- open (not closed) incident count
  open_critical    int NOT NULL DEFAULT 0,   -- open counts by severity (severity is a controlled vocabulary,
  open_high        int NOT NULL DEFAULT 0,   -- not free text — a metadata enum, so counting it is safe)
  open_medium      int NOT NULL DEFAULT 0,
  open_low         int NOT NULL DEFAULT 0,
  oldest_open_at   timestamptz,              -- age of the oldest open incident (derived at read); NULL = none open
  unacked          int NOT NULL DEFAULT 0,   -- open AND not yet acknowledged
  ack_overdue      int NOT NULL DEFAULT 0,   -- open AND unacknowledged past ack_due_at
  sla_breached     int NOT NULL DEFAULT 0,   -- open AND past resolve_due_at
  sla_at_risk      int NOT NULL DEFAULT 0,   -- open AND resolve_due_at within the at-risk window
  escalated        int NOT NULL DEFAULT 0,   -- population deferred: escalation state lives in the notify domain
                                             --   (#78), joinable in a follow-on; column present so the store is ready
  last_activity_at timestamptz,              -- most recent incident activity (max created_at); NULL = none
  updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Per-tenant isolation for DIRECT reads (a tenant sees only its own posture row). The vendor's cross-tenant
-- oversight read does NOT use this path — it goes through the SECURITY DEFINER function below.
ALTER TABLE tenant_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_posture FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_posture;
CREATE POLICY tenant_isolation ON tenant_posture
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_posture TO nirvet_app;

-- MA4-2: the vendor's bounded cross-tenant posture read — a DEDICATED SECURITY DEFINER function that reads
-- ONLY tenant_posture (never the fleet_alerts() SD-fn, which reads the content `alerts` table). Same MA-1
-- discipline as fleet_alerts(): postgres-owned superuser definer ⇒ RLS is INERT inside ⇒ tenant_id = ANY(...)
-- is the ONLY guard; FAIL CLOSED on empty/NULL scope; bound uuid[] param; minimal; REVOKE PUBLIC + GRANT
-- nirvet_app (CI-guarded by scripts/check-security-definer-revoke.sh). Tenant-set is resolved from the
-- authenticated principal in Go (the posture scope-resolver), never from client input.
CREATE OR REPLACE FUNCTION tenant_posture_fleet(p_tenant_ids uuid[])
RETURNS SETOF tenant_posture
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT *
    FROM tenant_posture
   WHERE cardinality(coalesce(p_tenant_ids, ARRAY[]::uuid[])) > 0   -- MA-1 fail-closed: empty/NULL scope -> 0 rows
     AND tenant_id = ANY(p_tenant_ids)                             -- MA-1 the ONLY tenant guard
   ORDER BY tenant_id
   LIMIT 5000;                                                     -- hard cap (bounded read; whole-fleet posture)
$$;

REVOKE ALL ON FUNCTION tenant_posture_fleet(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_posture_fleet(uuid[]) TO nirvet_app;
