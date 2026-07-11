-- L3 (builder pass, LOW/latent): stop a tenant from DELETE/UPDATE-ing platform-GLOBAL (tenant_id IS NULL)
-- rows on the three tables that mix per-tenant and shared-global content: playbooks, protected_identities,
-- protected_directory_roles.
--
-- Each had a SINGLE `ALL` policy: USING ((tenant_id = app_current_tenant()) OR (tenant_id IS NULL)) with
-- WITH CHECK (tenant_id = app_current_tenant()). Postgres evaluates ONLY `USING` for DELETE (and uses it to
-- select the target rows for UPDATE), so the `OR tenant_id IS NULL` arm let a tenant in RLS context DELETE
-- — or UPDATE-and-capture — the shared global playbooks / D5 protected-identity guardrails that every tenant
-- relies on. No reachable path today (no DELETE/UPDATE handler exists on these tables), but it is a latent
-- cross-tenant-integrity footgun to close BEFORE any such endpoint is built.
--
-- Fix: split the single policy into SELECT (may read own + global) vs INSERT/UPDATE/DELETE (own-tenant only).
-- INSERT semantics are unchanged (the old WITH CHECK already forced tenant_id = app_current_tenant(), so a
-- global row could never be inserted by the app anyway — globals are migration-seeded as superuser). This
-- only removes the `OR IS NULL` arm from the write paths, matching how detection_rules/ai_provider/stix_objects
-- already scope their writes.

-- playbooks
DROP POLICY IF EXISTS tenant_isolation ON playbooks;
CREATE POLICY playbooks_read   ON playbooks FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY playbooks_insert ON playbooks FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY playbooks_update ON playbooks FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY playbooks_delete ON playbooks FOR DELETE USING (tenant_id = app_current_tenant());

-- protected_identities
DROP POLICY IF EXISTS protected_identities_rw ON protected_identities;
CREATE POLICY protected_identities_read   ON protected_identities FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY protected_identities_insert ON protected_identities FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_identities_update ON protected_identities FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_identities_delete ON protected_identities FOR DELETE USING (tenant_id = app_current_tenant());

-- protected_directory_roles
DROP POLICY IF EXISTS protected_directory_roles_rw ON protected_directory_roles;
CREATE POLICY protected_directory_roles_read   ON protected_directory_roles FOR SELECT USING (tenant_id = app_current_tenant() OR tenant_id IS NULL);
CREATE POLICY protected_directory_roles_insert ON protected_directory_roles FOR INSERT WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_directory_roles_update ON protected_directory_roles FOR UPDATE USING (tenant_id = app_current_tenant()) WITH CHECK (tenant_id = app_current_tenant());
CREATE POLICY protected_directory_roles_delete ON protected_directory_roles FOR DELETE USING (tenant_id = app_current_tenant());
