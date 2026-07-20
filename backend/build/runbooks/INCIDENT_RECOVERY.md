# Runbook — Incident Recovery (suspected platform self-compromise)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2e. Recovery from a suspected compromise of the SOC platform
*itself*. Every step reuses a **verified code chokepoint** — this runbook sequences them, it does not invent new
mechanism.

## Safety invariant (what a wrong recovery destroys)
Recovery must **shrink the blast radius, not widen it.** The procedure MUST NOT require standing god-access or a
break-glass that itself becomes a new compromise vector. Every credential/key that could have been observed by the
attacker is rotated; every live session the attacker may hold is killed; the audit trail is confirmed intact so the
investigation itself is trustworthy.

## Recovery procedure (order matters)
1. **Kill live sessions** — bump the **session generation**; this invalidates every live JWT at the `MintSession`
   chokepoint (verified `project_nirvet_session_revocation`). An attacker holding a stolen token is out immediately —
   no waiting for token expiry.
2. **Rotate seed + platform credentials** — the seeded super-admin credential, service-account keys, API keys. Force
   re-auth (now MFA-gated, `S1 force-MFA`).
3. **Rotate the KEK** — follow KEY_ROTATION.md (dual-read, no orphan). If the KEK may be compromised, this is
   mandatory: new writes wrap under the new key; old ciphertext stays readable until re-wrapped. The attacker's
   knowledge of the old key becomes worthless as re-wrap progresses.
4. **Rotate connector / Vault secrets** — every outbound integration secret (ticketing, vendor actioners, SMTP) is
   rotated by its own provider procedure; referenced by location, never printed (§2f).
5. **Re-verify audit-log integrity** — confirm the audit log (append-only, mig 0017) has not been tampered with; the
   append-only guarantee means the attacker cannot have deleted their own tracks. This makes the post-incident
   investigation trustworthy. If integrity fails, escalate — the DB itself is suspect (go to restore from a
   known-good pre-compromise backup, BACKUP_RESTORE.md).
6. **Review four-eyes / privileged-action audit** for the compromise window — every destructive/privileged action is
   creator≠approver recorded; enumerate what the attacker did.

## Non-widening guarantee
None of the above needs a new standing super-user. Session-generation bump, rotation, and audit re-verify are
operator actions through existing scoped chokepoints. Break-glass elevation (if used) is itself audited + time-boxed
(PAM elevation, IAM slice B2) — recovery does not create an un-audited god path.

## Secrets
No step echoes/logs a rotated key, token, or password (§2f). Rotation is by-reference through each secret's provider.

## Accreditation mapping
Session-kill + full credential/KEK rotation + audit-integrity re-verification, all through audited scoped chokepoints,
satisfies the incident-response + access-control controls; cross-references the verified session-revocation, KMS
rotation, and audit-immutability invariants.
