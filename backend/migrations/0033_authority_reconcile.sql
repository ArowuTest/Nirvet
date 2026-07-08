-- Authority-to-act reconciliation (Phase 0). SOAR now resolves authority PER ACTION from
-- tenant.authority_policies (single source of truth) instead of the legacy tenants.authority_mode
-- column. Migration 0028 seeded the catch-all '*' policy as 'approval'; the genuinely
-- fail-closed default (and the platform's prior tenants.authority_mode default) is 'observe' —
-- NO response action auto-executes until an admin opts in. Bring the seeded catch-all rows into
-- line. (Pre-production: all '*' rows are still the seeded default; safe to normalize.)

UPDATE authority_policies SET mode = 'observe' WHERE action_type = '*' AND mode = 'approval';
