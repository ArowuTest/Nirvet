# Runbook — Upgrade (fail-closed, reversible)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2d. Upgrade reuses an **already-verified** control — the Helm
migration pre-install/pre-upgrade hook — so this runbook references that guarantee rather than re-proving it.

## Safety invariant (what a wrong upgrade destroys)
**A failed migration MUST fail the release — never a half-migrated serving pod.** The chart runs schema migration as a
Helm **pre-upgrade hook** (`deploy/helm/nirvet`, verified in `GATE_DEPLOYMENT_PACKAGING_SECURITY.md` + enforced by
`scripts/check-deploy-security.sh`): if the migration job fails, the hook fails, and the new app pods are **never
rolled out** against a partially-migrated DB. The old version keeps serving. This is the fail-closed guarantee.

## Pre-upgrade (every upgrade is a destructive-capable step → §2g)
1. **Take a restore point** — a pre-upgrade Postgres backup (BACKUP_RESTORE.md) + record the **current image digest**
   (the rollback target). Do NOT proceed without both.
2. Confirm migrations in the new release are **backward-safe for the rollback window** (additive; no destructive
   column drop that the old image needs). If a migration is NOT backward-safe, the runbook states the
   **point-of-no-return explicitly** and requires an acknowledged decision before proceeding.
3. Note the maintenance window; announce via the maintenance-list surface (platform-admin slice B).

## Upgrade procedure
1. `helm upgrade` with the new digest-pinned image (images are pinned by digest, verified by the deploy fence).
2. The **pre-upgrade migration hook runs first**. If it fails → the release fails, old pods still serve → go to
   Rollback. This is automatic, not a manual gate.
3. On hook success, new pods roll out. Verify `/readyz` (checks DB + dependencies) is green on the new version.
4. Smoke-test the value loop (ingest → detect → alert) on the new version before declaring success.

## Rollback (reversible — the §2g pair)
- **App-only regression** (migration was backward-safe): `helm rollback` to the prior digest; the old image runs
  against the already-migrated (backward-compatible) schema.
- **Schema regression** (migration not backward-safe, past the point-of-no-return): restore the pre-upgrade Postgres
  restore point (BACKUP_RESTORE.md — destructive-restore pre-snapshot + confirm applies), then `helm rollback` the
  image. This is why step 1's restore point is mandatory.

## Secrets
No upgrade step echoes/logs a secret (§2f). Image/DB credentials come from Kubernetes Secrets by reference
(existingSecretName), never pasted into the command.

## Accreditation mapping
Fail-closed migration + digest-pinned rollback + mandatory restore point satisfies the change-management / release
control; cross-references the verified deploy-security fence.
