-- M3 (builder pass, MEDIUM): give host isolation the D5 blast-radius net that identity actions already have.
--
-- The D5 protected-target design promises refusal for "a crown-jewel host" (a domain controller, the host
-- running the Nirvet collector, a life-critical server), but only the Entra IDENTITY guard was implemented —
-- Defender host isolate_endpoint hit a no-op guard. A tenant with destructive_enabled could auto-isolate a
-- critical host with no protected-target refusal (a self-sealing outage; NOT an authority bypass — isolate is
-- reversible, rate-capped, approval/emergency-gated — but the safety net was missing).
--
-- protected_hosts is the per-tenant config (no hardcoding): each row is a case-insensitive substring the SOAR
-- host guard matches against a resolved isolate target; a match → WITHHELD + human escalation, exactly like the
-- protected-identity deny-list. Empty by default (same posture as protected_identities — the tenant/operator
-- designates its crown jewels); global (tenant_id NULL) rows apply to every tenant on the instance.
CREATE TABLE IF NOT EXISTS protected_hosts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid REFERENCES tenants(id) ON DELETE CASCADE, -- NULL => a global (all-tenant) protected pattern
    pattern    text NOT NULL,                                 -- case-insensitive substring matched against the host ref
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- A tenant sees + manages its own rows and reads the shared globals; it can only write its own (globals are
-- seeded as superuser). Mirrors the protected_identities policy shape, incl. the L3 global-row DELETE guard.
ALTER TABLE protected_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY protected_hosts_read   ON protected_hosts FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY protected_hosts_insert ON protected_hosts FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_hosts_update ON protected_hosts FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_hosts_delete ON protected_hosts FOR DELETE USING (tenant_id = app_current_tenant());

CREATE INDEX IF NOT EXISTS idx_protected_hosts_tenant ON protected_hosts(tenant_id);
