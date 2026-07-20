# Runbook — Install (first sovereign deployment)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §1b. Bring up a fresh Nirvet instance from the verified Helm chart.
Install is non-destructive (greenfield), but it establishes the secret + KEK posture every later runbook depends on.

## Safety invariant
The instance must come up **fail-closed and secret-clean**: no default/blank secret, the KEK provider reachable before
first boot, and require-KMS mode ON for accredited deployments (so the local master-key path is unreachable). A wrong
install bakes in a weak KEK posture that no later runbook can retrofit safely.

## Prerequisites
1. **KEK provider** — a Vault (Transit) or HSM provisioned in-country, with a per-tenant transit key model. For
   accreditation, require-KMS mode: `NIRVET_CRYPTO_PROVIDER=vault` (or `pkcs11` in the `//go:build hsm` image) +
   `RequireKMS=true` so `localCipher` (master-key) is never reachable.
2. **Secrets** provisioned as Kubernetes Secrets by reference (`existingSecretName` in values) — DB password, Vault
   token/role, SSO client secrets. Never inline in values (enforced by `scripts/check-deploy-security.sh`).
3. **Datastores** — Postgres (RLS-capable, non-superuser `nirvet_app` role), ClickHouse, object store.
4. Pick the reference architecture (SOVEREIGN_ARCHITECTURE.md): single-site / dual-site / national-SOC.

## Procedure
1. `helm install` with `values-sovereign.yaml` (default-deny NetworkPolicy, non-root securityContext, digest-pinned
   images — all verified by the deploy fence).
2. The **pre-install migration hook** runs the schema from zero (validated fail-closed + from-zero in CI). If it
   fails, the release fails — no half-provisioned instance.
3. On success, verify `/readyz` green (DB + ClickHouse + object store + KEK reachable). A red `/readyz` on the KEK
   check means the crypto provider is not reachable — fix before proceeding (this is the same dependency the DR drill
   proves).
4. **Seed the first operator** — the seeded super-admin (rotated immediately by the owner per
   `project_uduxpass_seeded_admin_prelaunch` discipline; here the owner rotates on first login, MFA-gated).
5. Onboard the first tenant/agency via the onboarding wizard (tenant-create → profile → escalation → connectors →
   authority).
6. Take the **first backup** (BACKUP_RESTORE.md) and record the baseline — establishes the restore point every later
   upgrade/restore needs.

## Secrets
No install step echoes/logs a secret (§2f); all by-reference through Secrets/Vault.

## Accreditation mapping
Fail-closed provisioning + require-KMS + secret-by-reference + immediate seed-rotation satisfies the secure-baseline /
configuration-management control; cross-references the verified deploy-security fence and KMS require-mode.
