# Runbook — DR Failover (promote the DR site)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2c. **DRILLED, not just written** — the decrypt-at-DR invariant
was proven end-to-end against a real Vault + a promoted DR replica (see *Drill evidence*).

## Safety invariant (what a wrong runbook destroys) — the crypto-availability trap
A promoted DR replica can decrypt tenant data **only if the KEK provider (Vault / HSM) is reachable from the DR site**.
The DB replica holds only KMS-**wrapped** ciphertext; without the KEK it decrypts **nothing** — a *dead SOC at the
worst possible moment*. Therefore **KEK reachability at DR MUST be provisioned BEFORE failover is possible** — a
replicated Vault (Raft/DR replication), an HSM reachable from DR, or cross-site KEK access. This is the #1 DR trap and
the one thing a "we replicated the database" plan silently misses.

## Pre-failover prerequisites (provision these FIRST)
1. **KEK at DR**: the Vault/HSM that wraps the DEKs is reachable and unsealed at the DR site (replicated Vault or
   cross-site network path). Verify with a decrypt probe BEFORE declaring DR ready.
2. Data replication current (Postgres streaming/async, ClickHouse, object store) — accepted RPO documented.
3. Decision authority + a documented failback path (below).

## Failover procedure (destructive/irreversible-ish → explicit decision + fence)
1. **Fence the old primary** (STONITH / network isolate / demote) so it can no longer accept writes — a single-writer
   guarantee, **no split-brain**. Record the decision authority.
2. Promote the DR replica to primary.
3. Point the app at DR (DSN + `NIRVET_VAULT_ADDR` → the DR-reachable KEK provider).
4. **Verify decrypt-at-DR**: the app boots and decrypts real ciphertext with the KEK. If it cannot, DO NOT cut over —
   the KEK is not reachable at DR (dead SOC). This is exactly the drill's PASS condition.
5. Redirect ingress; resume operations.

## Failback (the reverse, when the primary site returns)
Re-sync the recovered primary FROM the now-authoritative DR, then fail back with the same fence-promote-verify steps
(the old-primary is now the replica). Never bring the old primary back as a writer without re-sync (split-brain risk).

## Drill evidence (decrypt-at-DR — the drill actually happened)
Executed via `deploy/drills/dr_failover_drill.sh` — real Vault (Transit KEK), a primary + a restored DR replica, the
actual `crypto` Vault provider. Latest run:

```
[1] Vault up; transit KEK 'nirvet-dek' created (real Vault Transit provider)
[2] primary seeded with a Vault-wrapped secret (171 bytes wrapped; plaintext + KEK OUTSIDE the DB)
[3] DR replica restored from primary backup (RTO=2s)
[4] TRAP PASS: with the KEK provider unreachable, the DR replica CANNOT decrypt (fails closed = dead SOC)
[5] DECRYPT-AT-DR PASS: with the KEK reachable, the promoted DR replica decrypted the secret (SOC alive)
=== DR-FAILOVER DRILL RESULT: PASS ===
```
The drill also validated the **Vault Transit `keyWrapper` end-to-end against a REAL Vault** (previously only httptest-
faked in the KMS gate). Full result: `deploy/drills/evidence/dr_failover_result_20260720T233557.txt`. Re-runnable
(self-cleaning). Split-brain fencing is documented (procedure §1); this drill focuses on the untested crypto-
availability invariant.

## Secrets & rollback
No step echoes/logs a KEK, token, or DB password (§2f). Failover fences the old primary (rollback = failback with
re-sync); the promotion decision + authority are recorded (§2g).

## Accreditation mapping
Provable **decrypt-at-DR** + fenced promotion + failback path satisfy the BCP/DR failover control; cross-references
the verified KMS per-tenant key model and the drilled restore (BACKUP_RESTORE.md).
