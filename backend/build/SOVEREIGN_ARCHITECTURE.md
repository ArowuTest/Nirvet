# Sovereign Architecture Guide

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §1a. Three reference architectures for a **data-sovereign** Nirvet
deployment, each with its trust boundary, data flow, and — the load-bearing detail — **where the KEK lives and how it
is separated per tenant**. Every arch is buildable from the verified Helm chart (`deploy/helm/nirvet`,
`GATE_DEPLOYMENT_PACKAGING_SECURITY.md`) and the KMS provider abstraction (`GATE_KMS_PROVIDER_ABSTRACTION.md`).

## Data-residency / sovereignty (stated for the accreditor)
All customer data **and all key material stays in-country**. There is no cross-border egress path:
- The air-gap Helm profile (`values-sovereign.yaml`) applies a **default-deny NetworkPolicy** — egress is allow-listed,
  not open. Verified by `scripts/check-deploy-security.sh`.
- The AI copilot can run against a **self-hosted LLM** (no external model call) — configured per-tenant
  (`GATE_KMS_PROVIDER_ABSTRACTION.md` is crypto; the AI-provider allowlist is the egress control). Air-gap = a
  strength here, not a limitation.
- Tenant data is decryptable only with the in-country KEK (Vault/HSM); a stolen DB backup that left the country is
  wrapped ciphertext — useless. This is the sovereignty guarantee reduced to a crypto invariant.

## Trust-boundary primitives (shared by all three)
- **Tenant isolation** = Postgres `FORCE ROW LEVEL SECURITY` under a non-superuser role (`nirvet_app`), tenant bound
  per-transaction (`WithTenant`). Not app-layer filtering — the DB refuses cross-tenant reads.
- **Per-tenant key separation** = one KEK per tenant (Vault transit key per tenant / HSM key per tenant). Compromise
  of one tenant's key never exposes another's data. Blast radius = one tenant.
- **Audit immutability** = append-only audit log (mig 0017); every privileged decision recorded.
- **Session revocation** = a session-generation bump kills all live JWTs at the `MintSession` chokepoint.

```
                    ┌──────────────── in-country trust boundary ────────────────┐
   analysts ──────▶ │  Nirvet app (RLS, per-tenant AAD) ──▶ Postgres (wrapped)   │
   (mTLS/SSO)       │        │ wrap/unwrap DEK                    ClickHouse       │
                    │        ▼                                   object store      │
                    │   KEK provider (Vault/HSM) ── per-tenant keys                │
                    └───────────────────────────────────────────────────────────┘
                         ▲ no cross-border egress (default-deny NetworkPolicy)
```

## 1. Single-site (minimal sovereign deployment)
One agency data centre. App + Postgres + ClickHouse + object store + one Vault (or HSM) — all in one DC.
- **KEK**: a single in-DC Vault/HSM; per-tenant transit keys even when there is one tenant (forward-compatible).
- **Trust boundary**: the DC perimeter; no egress beyond allow-list.
- **DR posture**: local backups per BACKUP_RESTORE.md (RPO = backup interval; restore drilled RTO≈2s at test scale).
- **Use when**: a single agency runs its own SOC in-house; the floor of sovereign.

## 2. Dual-site (primary + DR)
Primary DC + a DR DC in-country. The DR arch that the **decrypt-at-DR drill** (DR_FAILOVER.md) was built to prove.
- **Replication**: Postgres streaming/async → DR; ClickHouse + object store replicated; **KEK replicated to DR**
  (Vault Raft/DR replication, or an HSM reachable at DR). RPO/RTO documented per replication mode.
- **The crypto-availability invariant**: the DR site MUST reach its KEK before promotion, or it promotes to a *dead
  SOC* (wrapped data, no key). Proven by the DR-failover drill: KEK unreachable → fails closed; KEK reachable →
  decrypts. This is the #1 thing a "we replicated the DB" plan misses.
- **No split-brain**: promotion fences the old primary (single-writer). Failback = re-sync then reverse.
- **Use when**: an agency needs BCP/DR continuity — the accreditation-grade posture.

## 3. National-SOC (central operator → N agencies)
One accredited operator (the Ghana SOCaaS operator) runs a multi-tenant SOC for N agencies. The multi-tenancy-at-scale
model.
- **Tenancy → agency mapping**: one RLS tenant per agency; the operator's own staff are a platform-admin tenant with
  scoped cross-audience READ (customer read-model), never raw cross-tenant data access
  (`project_nirvet_audit_authz_fix`: raw operator/audit data is platform-admin, not SSO-admin).
- **Per-agency KEK separation**: a distinct Vault transit key (or HSM key) per agency — the blast-radius argument the
  accreditor cares about: operator compromise of one agency's key ≠ all agencies. Each agency's data is
  cryptographically sovereign even within a shared operator platform.
- **Scale**: the A2 250-agency soak (owner/ops env) validates this posture under load; RLS + per-tenant keys are the
  isolation guarantees that must hold at fleet scale.
- **Use when**: the target GTM — a national operator serving many agencies under one accreditation.

## Accreditation cross-reference
Each arch maps to the BCP/DR + data-sovereignty controls in `build/ACCREDITATION_MAPPING.md`; the per-tenant KEK
separation is the sovereignty control an accreditor will probe hardest, and it is a verified code invariant
(`TestEnvelope_ProviderConfusionRefused`, per-tenant AAD), not a slide.
