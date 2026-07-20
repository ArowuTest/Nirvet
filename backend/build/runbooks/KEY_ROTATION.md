# Runbook — Key Rotation (KEK / provider / generation)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2b. Rotation is **tabletop-validated against an already-verified
code invariant** (the gate allows tabletop for rotation): the dual-read primitive this runbook depends on is proven
by the green unit test `internal/platform/crypto/provider_test.go::TestTransition_CrossProviderDualRead` (reviewer-
verified in the KMS-provider gate).

## Safety invariant (what a wrong runbook destroys)
**Rotation MUST use the `transitionCipher` dual-read — NEVER a big-bang "re-encrypt everything at once".** The cipher
writes forward under the NEW provider/generation while it can still READ the old one; old ciphertext stays readable
throughout, so a failure mid-rotation orphans nothing. A procedure that re-encrypts the whole vault in one shot is
**rejected** — a crash halfway leaves data wrapped by a key that is no longer the write key and may be discarded.

## How the code already guarantees it (reference, not re-drilled)
- Every envelope ciphertext is stamped with `[providerTag][keyGen]` (KMS gate 2c). `transitionCipher.Decrypt`
  dispatches a blob to the reader whose (tag,gen) matches; the writer emits the NEW (tag,gen).
- `TestTransition_CrossProviderDualRead` proves: after switching to a new provider/gen, **old-provider ciphertext
  still decrypts** through the transition (write-new / read-both), and a **single-reader** transition (writer only)
  **cannot** read the old blob — i.e. the dual-read is load-bearing, not decorative. This is the exact rotation
  invariant, already green in CI.
- Cross-provider/gen confusion is refused loudly (`TestEnvelope_ProviderConfusionRefused`) — a blob is never
  mis-unwrapped by the wrong key.

## Procedure (dry-run / operator)
1. **Stand up the new key** (new Vault transit key version / new HSM key / new generation) alongside the current one.
   Do NOT retire the old key yet.
2. **Configure the transition**: the writer = new provider/gen; keep the old provider/gen as a legacy READER. New
   writes are wrapped by the new key; all existing ciphertext keeps decrypting via the old reader.
3. **Re-wrap forward, lazily/gradually**: on each read-then-write (or a bounded background sweep), re-encrypt under
   the new key. There is no window where data is unreadable — old and new coexist.
4. **Retire the old key ONLY after** a verification pass confirms no ciphertext remains under it (the old reader can
   be removed once its blob count reaches zero). Retiring early would orphan any un-migrated data.
5. **Rollback**: because the old key is retained until step 4, rollback = keep writing under the old key; nothing was
   destroyed. This is the reversibility the gate requires.

## Certificate rotation (overlap validity — no gap)
Bring the **new certificate live before the old one expires** (overlapping validity windows); flip traffic to the new
cert, then let the old expire. Never a window with no valid cert. (cert-manager renewal or operator-supplied.)

## Secrets
No rotation step echoes/logs/exports a key or token (§2f). Keys are referenced by their Vault/HSM location; the old
key is destroyed via its provider's own audited procedure, never printed.

## Accreditation mapping
Key lifecycle with **no-orphan dual-read + retained-until-verified retirement** satisfies the key-management control;
cross-references the verified `transitionCipher` invariant so the accreditor sees the code guarantee behind the procedure.
