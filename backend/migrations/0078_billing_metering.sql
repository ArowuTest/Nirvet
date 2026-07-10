-- §6.17 #126 B-1/B-2 — the metering ledger + billing periods. The ledger is APPEND-ONLY point-deltas: the rollup is
-- always SUM(usage_events), never a mutable running counter (PIN-2), so the aggregate can never drift from the source
-- of truth (M-5 holds by construction). Idempotency is DB-enforced: a UNIQUE (tenant, metric, key) makes a retry a
-- no-op (no double-count) while a distinct key per real increment loses nothing.

-- Billing periods. A period is 'open' until invoiced ('closed'). A late event for a CLOSED period is recorded and
-- adjusted forward to the current open period (PIN-1 record-don't-drop) — never a silent mutation of the closed
-- invoice, never a discard.
CREATE TABLE IF NOT EXISTS billing_period (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL DEFAULT app_current_tenant(),
  period     text NOT NULL,          -- 'YYYY-MM'
  status     text NOT NULL DEFAULT 'open',
  opened_at  timestamptz NOT NULL DEFAULT now(),
  closed_at  timestamptz,
  UNIQUE (tenant_id, period),
  CONSTRAINT billing_period_status_chk CHECK (status IN ('open','closed'))
);
ALTER TABLE billing_period ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_period FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON billing_period;
CREATE POLICY tenant_isolation ON billing_period
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
GRANT SELECT, INSERT, UPDATE ON billing_period TO nirvet_app;

-- The append-only usage ledger.
CREATE TABLE IF NOT EXISTS usage_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT app_current_tenant(),
  metric          text NOT NULL,
  quantity        bigint NOT NULL,
  period          text NOT NULL,          -- the period this delta is BILLED to (adjusted forward if the event's own period is closed)
  event_period    text NOT NULL,          -- the period the event actually occurred in
  is_adjustment   boolean NOT NULL DEFAULT false,
  idempotency_key text NOT NULL,
  source          text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT usage_events_qty_chk CHECK (quantity >= 0),          -- M-3: no negative usage (fraud path)
  UNIQUE (tenant_id, metric, idempotency_key)                    -- PIN-2: DB-enforced idempotency
);
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON usage_events;
CREATE POLICY tenant_isolation ON usage_events
  USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
REVOKE UPDATE, DELETE, TRUNCATE ON usage_events FROM nirvet_app;   -- append-only
GRANT SELECT, INSERT ON usage_events TO nirvet_app;
CREATE INDEX IF NOT EXISTS usage_events_tenant_period_metric ON usage_events (tenant_id, period, metric);

CREATE OR REPLACE FUNCTION usage_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'usage_events is append-only (immutable); % is not permitted', TG_OP;
END;
$$;
DROP TRIGGER IF EXISTS usage_events_no_mutate ON usage_events;
CREATE TRIGGER usage_events_no_mutate
  BEFORE UPDATE OR DELETE ON usage_events
  FOR EACH ROW EXECUTE FUNCTION usage_events_immutable();
