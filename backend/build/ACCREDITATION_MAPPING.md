# Accreditation Control Mapping (CSA / BCP-DR / best-in-class)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §3. This turns "we have the controls" into "we are accreditable":
each accreditation control is mapped to **both** its verified code-level control **and** its operational procedure, so
an accreditor sees the mechanism and the runbook that operates it safely. Every code control cited here is
reviewer-verified (source-verified, not relayed).

## The mapping

| Control area | Verified code control (mechanism) | Operational procedure (runbook) |
|---|---|---|
| **Data sovereignty / residency** | Per-tenant KEK (Vault transit key/tenant), per-tenant AES-GCM AAD, `TestEnvelope_ProviderConfusionRefused`; default-deny egress NetworkPolicy (`check-deploy-security.sh`); self-hostable LLM | SOVEREIGN_ARCHITECTURE.md (all data + keys in-country; blast-radius = one tenant) |
| **Tenant isolation / access control** | Postgres `FORCE ROW LEVEL SECURITY`, non-superuser `nirvet_app`, `WithTenant`; RBAC RoleRank; four-eyes (creator≠approver) | INSTALL.md (non-superuser role); INCIDENT_RECOVERY.md (four-eyes audit review) |
| **Cryptographic key management** | `envelopeCipher` (DEK + AES-256-GCM + zeroize), `keyWrapper` seam, `transitionCipher` dual-read no-orphan, `TestTransition_CrossProviderDualRead`, require-KMS mode | KEY_ROTATION.md (dual-read rotation); CERT_ROTATION.md (overlap validity); INSTALL.md (require-KMS) |
| **Backup / recoverability (BCP)** | Envelope layout = DB holds only wrapped DEKs (KEK held separately); crypto round-trip via real `crypto` pkg | **BACKUP_RESTORE.md — DRILLED** (KEK-separation trap + restore + RPO/RTO measured; B8 evidence) |
| **Disaster recovery (BCP-DR failover)** | KEK-reachability = decrypt precondition; Vault Transit provider (now real-Vault-validated) | **DR_FAILOVER.md — DRILLED** (decrypt-at-DR: KEK unreachable→fails closed, reachable→decrypts; no split-brain; failback) |
| **Change management / release** | Helm pre-upgrade migration hook fail-closed; digest-pinned images; from-zero migration CI validation | UPGRADE.md (fail-closed + digest rollback + pre-upgrade restore point) |
| **Incident response** | Session-generation kill at `MintSession`; append-only audit log (mig 0017); PAM/break-glass time-boxed + audited | INCIDENT_RECOVERY.md (session-kill + full rotation + audit re-verify, non-widening) |
| **Authentication assurance** | Server-side MFA floor at `MintSession` (S1 force-MFA), SSO OIDC/SAML signed-assertion, brute-force hardening | INSTALL.md (MFA-gated seed rotation); INCIDENT_RECOVERY.md (force re-auth) |
| **Audit / non-repudiation** | Append-only audit log; every privileged decision + four-eyes recorded in one tx | INCIDENT_RECOVERY.md (audit-integrity re-verify makes the investigation trustworthy) |
| **Secret handling** | Secrets by-reference (`existingSecretName`); no-secret-in-chart fence; no KEK ever printed (drills emit byte-counts only) | §2f across ALL runbooks — no step echoes/logs a secret |
| **Secure baseline / config mgmt** | Non-root securityContext, default-deny NetworkPolicy, digest-pinned, air-gap SHA256SUMS bundle — all fence-enforced | INSTALL.md (values-sovereign profile) |

## What makes this accreditation-grade (not a checklist)
- **Every recoverability claim is drilled, not asserted.** Backup/restore and DR-failover have captured evidence
  (`deploy/drills/evidence/`) with measured RPO/RTO — the reviewer bar was "the drill *happened*", met.
- **Every destructive procedure has a pre-backup + rollback** (§2g): restore (pre-snapshot+confirm), upgrade (restore
  point + digest rollback), failover (failback + fence), rotation (old key/cert retained until verified).
- **No procedure widens the blast radius or needs a standing god-path** — recovery works through existing audited,
  scoped chokepoints.
- **The sovereignty guarantee reduces to a crypto invariant**: a DB backup that leaves the country is wrapped
  ciphertext, useless without the in-country per-tenant KEK — provable, not policy.

## Out of scope (feeds separate workstreams)
The FIPS/CC HSM *certification* itself (procurement/lab), the full SOC-2/ISO evidence package (compliance workstream —
this mapping feeds it), and automated DR orchestration (first pass = documented + drilled manual procedures).
