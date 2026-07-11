-- 0089_grant_organisation.sql — grant the app role write access to the `organisation` registry.
--
-- 0081 created `organisation` (the org grouping seam) but never granted nirvet_app access, so padmin
-- org-management (and the oversight resolver family that groups tenants by org) had no app write path —
-- like the peer `billing_account` registry, which IS granted. This closes that gap. organisation is a
-- platform registry (no per-tenant RLS); padmin manages it.
GRANT SELECT, INSERT, UPDATE, DELETE ON organisation TO nirvet_app;
