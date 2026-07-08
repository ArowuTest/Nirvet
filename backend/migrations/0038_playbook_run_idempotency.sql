-- Round-4 M3: idempotency backstop for SOAR playbook runs. A retried or double-submitted
-- POST /playbooks/{id}/run must not re-dispatch permitted steps (duplicate notifications today;
-- double isolate/disable/block once a destructive connector executor lands). The service checks for
-- an existing active run per (playbook, incident) inside the run transaction and returns it instead
-- of creating a new one; this partial unique index makes that race-safe under concurrent submits:
-- at most ONE non-terminal (pending_approval|running) run per (tenant, playbook, incident).
--
-- Ad-hoc runs (incident_id IS NULL) are intentionally NOT deduped — an operator may legitimately run
-- the same playbook ad-hoc more than once; the destructive-in-context case is the incident-linked one.
CREATE UNIQUE INDEX IF NOT EXISTS playbook_runs_active_uniq
  ON playbook_runs (tenant_id, playbook_id, incident_id)
  WHERE status IN ('pending_approval', 'running') AND incident_id IS NOT NULL;
