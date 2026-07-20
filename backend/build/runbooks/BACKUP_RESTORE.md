# Runbook — Backup & Restore (B8)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2a. **This runbook is DRILLED, not just written** — a real
backup→wipe→restore→decrypt cycle has been executed and its result captured (see *Drill evidence* below).

## Safety invariant (what a wrong runbook destroys)
The database backup contains only **KMS/HSM-wrapped DEKs** — useless without the key-encrypting key (KEK). Therefore:
- **The KEK is backed up SEPARATELY**, on its own procedure (the Vault/HSM key export, or the `NIRVET_SECRET_MASTER_KEY`
  for the local-cipher pilot). A data backup **without** the key restores *unreadable* data; a backup that **dumps the
  raw KEK** is a catastrophic key leak. Both facts are stated here so an operator can never conflate the two backups.
- A restore is the **destructive direction** (it overwrites): take a pre-restore snapshot and require an explicit confirm.

## What is backed up (completeness)
| Component | What | How | Key handling |
|---|---|---|---|
| Postgres | tenant RLS data (incidents, alerts, config, audit, ledgers) | `pg_dump -Fc` (or continuous WAL archiving for low RPO) | holds only **wrapped** ciphertext |
| ClickHouse | raw/normalized events (ADR-0002) | native `BACKUP` / partition export to object store | events are not KEK-encrypted; residency applies |
| Object store | evidence packs, report artifacts | bucket replication / versioned snapshot | signed evidence (chain-of-custody preserved) |
| Migration state | schema version | included in the Postgres dump | — |
| **KEK** | Vault transit key / HSM key / master key | **its OWN backup procedure — NEVER in the DB dump** | the one thing that makes the rest readable |

## Backup procedure
1. Snapshot the KEK per its provider's key-backup procedure (Vault `vault operator raft snapshot` / HSM key-wrap
   escrow / the sealed master key). Store it in a **separate** secured location from the data backup. Never log it.
2. `pg_dump -Fc` Postgres; `BACKUP` ClickHouse; snapshot the object store. Record the backup timestamp (the RPO anchor).
3. Verify the data backup contains **no plaintext secret and no raw KEK** (the drill asserts this automatically).

## Restore procedure (destructive — pre-snapshot + confirm)
1. **Pre-restore snapshot** of the current target (rollback point), then require an explicit operator confirm.
2. Restore Postgres (`pg_restore` into a fresh DB), ClickHouse, and the object store from the backup set.
3. Provision the **KEK at the restore site** (restored Vault snapshot / HSM reachable / master key from its escrow).
4. **Verify: boot + decrypt + smoke.** The restored instance must decrypt real ciphertext with the KEK. If it cannot,
   the restore is NOT usable — do not cut over. (This is exactly what the drill's `verify` step proves.)

## Drill evidence (B8 — the drill actually happened)
Executed via `deploy/drills/b8_backup_restore.sh` (real Postgres 17 container, real crypto, full cycle). Latest run:

```
[4] backup taken: pg_dump custom-format, 490239 bytes, 1s
[5] TRAP (a) PASS: neither the plaintext nor the KEK appears in the backup — DB holds only wrapped ciphertext
[6] restore completed into a fresh DB: RTO=2s
[7] TRAP (b) PASS: restored instance decrypted the secret with the separately-backed-up KEK (smoke pass)
[7] NEGATIVE-CONTROL PASS: with a wrong/absent KEK the restored DB is UNREADABLE
=== B8 DRILL RESULT: PASS ===   RTO=2s   RPO=0 (immediate backup; production RPO = the scheduled backup interval)
```
Full captured result: `deploy/drills/evidence/b8_result_20260720T213046.txt`. Re-run any time with the script above
(the drill is self-cleaning; it can also be wired into CI, where the runner has Docker).

## RPO / RTO
- **RTO** (measured, this hardware): **2s** for the drill dataset; scales with data volume — the runbook records the
  measured RTO per environment at go-live.
- **RPO**: 0 in the drill (backup taken immediately after the last write). **Production RPO = the scheduled backup
  interval**; for near-zero RPO, enable Postgres WAL archiving / ClickHouse incremental backup (documented per site).

## Accreditation mapping (CSA / BCP-DR)
Backup completeness + a **drilled, evidenced** restore + the KEK-separation invariant satisfy the BCP/DR and
data-recoverability controls; cross-references the verified code controls (audit immutability mig 0017, KMS per-tenant
keys, RLS isolation) so the accreditor sees the control *and* its operational procedure.
