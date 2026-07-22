# Pre-code Gate — Full-stack recovery validation (builder-2 item 5) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 22 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies + independently CI-confirms.
Origin: NIR-AUD-021 item 5 (the last of builder-2's sovereign-infra package). Items 1 (HSM `cff9eec`), 4 (offline content lifecycle `b839cd8`) are landed+verified; 2 (supply-chain signing/SBOM) and 3 (install-preflight+support-bundle) remain.
Scope: **disaster-recovery ASSURANCE.** A restore that returns bytes is not a recovery — it is an unproven claim. This item builds the mechanism that *proves* a restored Nirvet is correct, secure, tenant-isolated, and crypto-intact **before** it is allowed to serve traffic.

## 0. The governing principle
**A recovery is not "successful" when data comes back — it is successful only when the RESTORED stack is proven functionally correct, cryptographically intact, RLS-enforced, tenant-uncontaminated, audit-continuous, and staleness-safe. Until that proof passes, the restored system is treated as untrusted and MUST NOT serve production traffic.**
Falsification bar: *"what makes a recovery LOOK successful but actually be corrupt, incomplete, insecure, cross-tenant-contaminated, stale, or missing a secret — and what lets an unvalidated restore serve traffic anyway."*

## 1. Reconciliation with what already exists — DO NOT rebuild
Epic #6 / B8 already delivered and I verified (`e190ef4`, `0682e3c`):
- The **backup + restore mechanism** itself (Postgres + KEK separation, decrypt-at-restore, RTO≈2s on the drill sample).
- The HA/DR **runbooks**.
This item is **not** another backup/restore mechanism. It is the **validation layer on top of a completed restore** — the automated assertion suite + drill that proves the restored stack is trustworthy across every stateful component, not just the one sampled in B8. Reuse the B8 restore path as the setup; add the validation. Extending the B8 drill harness is the expected shape.

## 2. The stateful surface — enumerate the WHOLE stack (not just the DB)
Recovery validation must cover **every** component that holds state or the platform is not actually recoverable. The builder MUST enumerate and validate each; a component with no recovery story is a finding, not an omission:
- **Postgres** — all tenant + platform data, at a consistent point-in-time (no torn/partial restore).
- **KMS / crypto material** — KEK(s) (per provider: local/Vault/HSM), per-tenant DEK wrapping, provider reachability post-restore.
- **Object/blob storage** — evidence, attachments, report exports, air-gap bundles (whatever lives outside PG).
- **Queue / outbox / idempotency state** — in-flight SOAR runs, notification outbox, consumed idempotency keys.
- **Secrets / config** — every required secret and config value the app fail-closes without.
- **Content packs** — active/quarantined content-lifecycle state (ties `b839cd8`).
Deliverable includes a **recovery manifest**: each stateful component → how it is backed up, how it is restored, how its recovery is validated. "Reconstructible from X" is an acceptable story; "not covered" is not.

## 3. The validation dimensions (each an assertion in the harness)
### 3a. Data integrity + completeness
Restored data is point-in-time consistent: referential integrity holds, no torn write, no partial-table restore, row counts / checksums reconcile against the backup's recorded state. A silently-truncated restore is DETECTED, not served.
### 3b. Crypto continuity (extend B8 beyond the sample)
Every encrypted domain — not just the B8 drill sample — is **decryptable** post-restore with the restored/re-provisioned KEK; per-tenant DEKs unwrap; the KMS provider is reachable; if the KEK was rotated during recovery, re-wrap is proven and no ciphertext is orphaned (reuse the transition/dual-read cipher). A domain that cannot decrypt fails **closed** and is flagged — never silently served as empty/garbage.
### 3c. Security-invariant continuity — re-prove, don't assume
The invariants I've verified on the live system must be **re-asserted against the restored DB**, because a restore can silently drop them:
- **FORCE-RLS + owner_bypass present on every tenant-scoped table** post-restore (the schemacheck/`pg_class` assertion, run against the restored instance).
- **Runtime rejects the owner/superuser connection** (the non-owner app role still applies; restore didn't leave the app running as owner).
- MFA-floor, session-generation, authority-policy single-door, and every mutating-route-guard invariant still hold (the existing fences, re-run).
### 3d. Tenant-isolation NON-contamination (the top DR risk)
The catastrophic DR failure is a restore that **merges, mislabels, or cross-links tenant data**. Prove **zero cross-tenant leakage in the restored state**: re-run the two-tenant isolation proof (tenant A cannot read tenant B) against the restored DB; assert no row's `tenant_id` was rewritten/nulled by the restore; global vs tenant scoping intact. A restore that contaminates tenancy is the single most important thing this gate must catch.
### 3e. Audit continuity + tamper-evidence
The audit chain is **continuous across the recovery boundary** — no silent gap that could hide pre-failure tampering; the recovery event itself is audited (who restored what, from which backup, when); append-only invariants survive. If the audit log is hash-chained, the chain verifies across the restore seam.
### 3f. Staleness / replay safety (a restore is a snapshot in the past)
A restored snapshot must not **reactivate** state the platform had moved past:
- rolled-back or superseded content packs are NOT silently re-activated (ties content-lifecycle `b839cd8`);
- retention-deleted / legal-hold-purged / jurisdictionally-erased data is NOT resurrected (ties B3 retention-delete — a restore that brings back erased PII is a compliance breach);
- consumed idempotency keys / already-sent notifications / completed SOAR runs are NOT replayed to double-execution;
- session/refresh generation is advanced so pre-failure tokens are not silently revived.
### 3g. Config / secret completeness — fail-closed, never degraded
The restored app boots only if **every required secret/config is present**; a missing KMS credential, signing key, or DSN causes a **fail-closed boot** with a clear error, **never** a silent degraded/insecure mode (no "KMS unavailable → plaintext fallback", no "MFA config missing → MFA off"). The deploy-security self-check (`check-deploy-security.sh` posture) passes against the restored config.
### 3h. Functional recovery (the stack actually works)
App boots; health + security self-checks green; migrations at head; a **canonical end-to-end journey** passes against the restored system (e.g. login→incident→investigate→propose, exercising DB+crypto+RLS+audit together); connectors/agents re-establish **safely** (no auto-fire of queued destructive actions on reconnect — reconnection is not a trigger).

## 4. Fail-closed until certified (teeth)
- Recovery validation produces a **binary certification**: PASS = restored stack is trustworthy; FAIL = it is not.
- **An uncertified restore MUST NOT serve production traffic.** Enforce it structurally: a recovery-certification gate/flag the serving path checks — startup on a restored instance is blocked (or held in a maintenance/read-block mode) until validation passes. Prove the block with a test: an instance with a deliberately-broken restore (dropped RLS, missing key, contaminated tenant) is **refused**, not served.
- Any single dimension failing = overall FAIL. No "mostly recovered → good enough." No dimension may be skipped for speed.
- **No guard may be weakened to make validation pass.** The validation asserts the invariants; it never relaxes them. (Standing reviewer rule — a recovery that only passes because a check was loosened is a worse outcome than a failed recovery.)

## 5. The harness + drill (reviewer-verifiable, like B8)
- An **automated recovery-validation suite** that runs the full cycle against a real instance: **seed → backup → wipe/simulate-loss → restore → VALIDATE (all §3 dimensions) → assert certification**. Not a mock; a real Postgres (+ the other stateful components as available in CI) round-trip, extending the B8 drill.
- **Captured drill evidence** (a `build/REVIEW_EVIDENCE_*.md`, like B8): the cycle executed end-to-end, each dimension asserted, the certification result, and the recovery manifest (§2). Include a **negative drill**: at least one deliberately-corrupted restore that the harness correctly REFUSES (proves the validation isn't vacuous).
- The recovery manifest (§2) committed and current.

## 6. Falsification tests (each mutation-sensitive)
1. **Torn/partial restore** (drop rows / restore mid-transaction) → integrity check FAILS → not certified.
2. **Missing/wrong per-tenant key** → decrypt fails **closed** and is flagged; not silently served empty.
3. **RLS dropped on restore** (disable FORCE-RLS on a table in the restored DB) → §3c assertion catches it → FAIL.
4. **Cross-tenant contamination** (rewrite a `tenant_id` in the restore) → §3d isolation proof catches it → FAIL.
5. **Audit gap across the seam** (truncate audit around the boundary) → §3e continuity check FAILS.
6. **Stale reactivation** — a restored snapshot that would re-activate a rolled-back content pack OR resurrect retention-purged data → §3f catches it → FAIL.
7. **Missing secret** → fail-closed boot with clear error, NOT degraded/insecure mode (§3g).
8. **Uncertified-serving block** — an instance whose validation FAILED is refused production serving (§4); mutation: bypass the certification flag → the serving path still refuses (the gate is load-bearing, not advisory).

## 7. Out of scope (follow-ons)
Cross-region active/active failover automation · automated backup scheduling/retention policy (assume the B8 backup exists) · RTO/RPO SLA tuning beyond validating the recovered state · chaos-engineering fault injection beyond the negative drill · bare-metal/OS-image recovery (this is the Nirvet-stack layer).

## 8. Minimum CI gates + reviewer evidence (before "ready")
**CI gates (all blocking):**
- The recovery-validation cycle (seed→backup→wipe→restore→validate→certify) runs in CI against the postgres-backed lane (reuse `ci.yml`'s app+owner DSNs); **un-skippable** where DSNs are present (mirror the content-lifecycle / B8 pattern — a green result must mean it *ran*, not skipped).
- Each §3 dimension has a passing positive assertion **and** a negative-control test (§6) proving it catches the corresponding corruption.
- The §4 uncertified-serving block is tested (broken restore → refused).
- Any new tables/columns: schemacheck (FORCE-RLS + owner_bypass) + from-zero migration green.
- No guard weakened: the existing fences (`check-deploy-security.sh`, RLS/authz fences, route-authz coverage) stay green.

**Reviewer evidence (I verify at source + independently CI-confirm on GitHub):**
- The drill evidence doc (§5) — the cycle executed, dimensions asserted, certification result, **plus the negative drill**.
- The recovery manifest (§2) — every stateful component covered.
- The certification-gate code path (§4) + its bypass-mutation test.
- Independent CI-green confirmation of the recovery-validation lane on the PR head and on `main` after merge.

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2 — recovery manifest enumerates every stateful component; each has a validated recovery story.
- [ ] 3a/3b — integrity + crypto continuity across ALL encrypted domains (not just the B8 sample); decrypt fails-closed (tests #1, #2).
- [ ] 3c/3d — RLS/owner-bypass/non-owner + every security invariant re-asserted on the RESTORED DB; two-tenant no-contamination proof (tests #3, #4).
- [ ] 3e/3f — audit continuity across the seam; no stale reactivation of rolled-back/retention-purged/replayed state (tests #5, #6).
- [ ] 3g/3h — missing secret → fail-closed boot not degraded; functional E2E + safe connector re-establish (test #7).
- [ ] 4 — binary certification; uncertified restore CANNOT serve traffic; gate is load-bearing not advisory; no guard weakened (test #8).
- [ ] 5/8 — automated seed→backup→wipe→restore→validate drill + negative drill; un-skippable CI lane; evidence doc + manifest; independently CI-confirmed.
