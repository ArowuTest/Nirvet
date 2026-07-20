# Pre-code Gate — HA/DR + operational runbooks + Sovereign Architecture Guide (epic #6) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder/ops author → reviewer source-verifies against the safety invariants.
Origin: NIR-AUD-021 epic item #6 + go-live conditions B8 (backup/restore drill) and D3 (prod cutover). Pairs with the verified packaging chart (`GATE_DEPLOYMENT_PACKAGING_SECURITY.md`) — the chart is *how you deploy*, this is *how you operate it safely and get accredited*.
Scope: **the accreditation + operational-safety layer.** This is docs + drilled procedures, but it is NOT "just docs": a wrong backup/key-rotation/DR-failover step loses gov evidence or exposes keys. The reviewer bar here is the **safety invariant of each destructive procedure**, and that **B8 backup/restore is actually DRILLED, not just written.**

## 0. Why this is the best next step to best-in-class
The code is security-verified and the two hardest sovereign gaps (KMS, packaging) are closed. What now stands between the platform and the **first Ghana sovereign go-live** is **CSA accreditation + provable safe operation at 250-agency scale** — and the operational/DR documentation is the piece of that critical path with **zero build/env dependency**. A best-in-class sovereign SOCaaS is not just correct code; it is *operable and recoverable under failure*, with the runbooks an accreditor and a night-shift operator both trust.

## 1. Deliverables

### 1a. Sovereign Architecture Guide (reference architectures)
Document, with a trust-boundary + data-flow diagram each:
- **Single-site** (one customer/agency DC) — the minimal sovereign deployment.
- **Dual-site** (primary + DR) — sync/async replication posture for Postgres + ClickHouse + object store + the KMS/Vault; RPO/RTO targets.
- **National-SOC** (central operator → N agencies) — the multi-tenancy-at-scale model: how RLS tenancy maps to agencies, the per-agency KMS key separation (Vault transit key per tenant), and the blast-radius argument.
- **Data residency / sovereignty**: all data (and key material) stays in-country; no cross-border egress (ties the air-gap NetworkPolicy). State it explicitly for the accreditor.

### 1b. Operational runbooks (each with the safety invariant it must satisfy)
The auditor's set — Install · Upgrade · Backup · Restore · DR Failover · Key Rotation · Certificate Rotation · Incident Recovery. Each runbook is validated against its invariant below.

## 2. Safety invariants — LOCKED (the reviewer value; what a WRONG runbook destroys)

### 2a. Backup + Restore (B8 — must be DRILLED, not just written)
- **Completeness:** backup covers Postgres (RLS data), ClickHouse (events), object store (evidence packs), AND the migration state. **Key material handling is the subtle one:** the DB backup contains only KMS-**wrapped** DEKs (useless without the KEK), so the runbook must separately document backing up the **Vault/HSM KEK per its own procedure** — a data backup without the key backup restores *unreadable* data; a backup that dumps the raw KEK is a catastrophic leak. State both explicitly.
- **Restore drill actually run (B8):** the runbook is not accepted until a restore has been **performed end-to-end** and **RPO/RTO measured** — a restored instance boots, decrypts (KEK available), and passes a smoke test. "Backups exist" ≠ "restore works." Verify, don't relay.
- Restore is the destructive direction (over-writes) → runbook requires a pre-restore snapshot + an explicit confirm.

### 2b. Key Rotation (reuse the crypto machinery — never a big-bang)
Rotation MUST use the **`transitionCipher` dual-read** (write-new-provider/gen, read-old+new) proven in the KMS gate — the runbook re-wraps forward while old ciphertext stays readable, **no vault orphaned**. A "rotate = re-encrypt everything at once" procedure is rejected (a mid-rotation failure orphans data). Certificate rotation: overlap validity (new cert live before old expires) — no gap.

### 2c. DR Failover (the crypto-availability trap)
- **The KMS/Vault/HSM must be reachable from the DR site** — a DR replica that promotes but can't reach a KEK provider **cannot decrypt anything** (dead SOC at the worst moment). The runbook must provision KEK availability at DR (replicated Vault / HSM at DR / cross-site access) BEFORE failover is possible, and the drill proves decrypt-at-DR.
- **No split-brain:** promotion fences the old primary; a single-writer guarantee. Data consistency (accepted RPO) documented.
- Failover is destructive/irreversible-ish → explicit decision authority + a documented failback path.

### 2d. Upgrade (fail-closed, reversible)
Reuse the **migration pre-install/pre-upgrade hook** (verified in the packaging gate) — a failed migration fails the release, never a half-migrated serving pod. The runbook includes a **rollback** (prior image digest + a DB-restore point taken before upgrade). Migrations must be backward-safe for the rollback window (or the runbook states the point-of-no-return explicitly).

### 2e. Incident Recovery (platform self-compromise)
Recovery from a suspected platform compromise: rotate all seed credentials + the master/KEK (2b), **bump session generation to kill live JWTs** (reuse the session-revocation chokepoint), rotate connector/vault secrets, re-verify audit-log integrity (append-only, mig 0017). The runbook must not itself require standing god-access that would widen the blast radius.

### 2f. No secret in any runbook step
No runbook command echoes/logs/exports a secret (KEK, Vault token, DB password, JWT secret). Secrets are referenced by their Secret/HSM location, retrieved into the environment, never pasted into a doc or a shared terminal transcript. (Mirrors the packaging no-secret-in-chart rule at the ops layer.)

### 2g. Every destructive step: pre-backup + rollback
Any runbook step that overwrites/deletes/promotes (restore, failover, rotation, upgrade) is preceded by a capture of prior state and paired with a documented rollback/failback. No irreversible step without an explicit, acknowledged point-of-no-return.

## 3. Accreditation mapping (CSA + best-in-class)
Map each deliverable to the accreditation control it satisfies (BCP/DR, backup, incident response, access control, data sovereignty). Cross-reference the existing verified controls (RLS isolation, audit immutability, KMS per-tenant keys, MFA floor, four-eyes) so the accreditor sees the code-level control *and* its operational procedure. This mapping is what turns "we have the controls" into "we are accreditable."

## 4. GUARANTEE (how this gate is verified — proof, not prose)
Unlike a code gate, the teeth here are **evidence**:
- **B8 restore drill: a captured result** (restored instance booted + decrypted + smoke-passed + RPO/RTO numbers) — the reviewer verifies the drill *happened*, not that a doc describes it.
- **Key-rotation + DR-failover: a dry-run/tabletop or live drill** proving the dual-read and the decrypt-at-DR invariants actually hold.
- Each runbook reviewed against its §2 invariant; any destructive step missing a pre-backup/rollback → sent back.

## 5. Out of scope (follow-ons)
Vendor-specific HA tuning (Patroni/Citus params) beyond the reference posture · the FIPS/CC HSM certification itself (a procurement/lab activity) · automated DR orchestration (first pass = documented + drilled manual procedures) · full SOC-2/ISO evidence package (separate compliance workstream, though this feeds it).

---
### Reviewer sign-off (I verify against the invariants + the drill evidence)
- [ ] 1a — three reference architectures (single/dual/national-SOC) + data-residency, each with trust-boundary + KEK-separation shown.
- [ ] 2a — backup covers data + KEK handling (wrapped-in-DB + KEK-backed-separately, never raw); **restore DRILLED, RPO/RTO measured** (B8 evidence).
- [ ] 2b — key rotation uses dual-read (no orphan); cert rotation overlaps validity.
- [ ] 2c — DR failover proves **decrypt-at-DR** (KEK reachable) + no split-brain + failback path.
- [ ] 2d — upgrade fail-closed + rollback (image digest + pre-upgrade restore point).
- [ ] 2e — incident recovery rotates seeds/KEK + bumps session generation + re-verifies audit integrity.
- [ ] 2f/2g — no secret in any step; every destructive step has pre-backup + rollback.
- [ ] 3 — accreditation control mapping cross-referencing the verified code controls.
