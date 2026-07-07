# ADR-0004 — Connector credential vault

**Status:** Accepted (assumed sign-off, Jul 2026; pre-go-live review pending)
**Stack:** Go · GCP Cloud KMS · PostgreSQL

## Context

Connectors hold customers' **OAuth refresh tokens, API keys and service-principal secrets** for Microsoft 365,
Entra, Defender, CrowdStrike, cloud providers, etc. A breach of this store hands an attacker the keys to
customers' own security and cloud tenants — the single highest-blast-radius asset in the platform. This is the
one component where an MVP shortcut is unacceptable (NFR-001, doc 02 §7). Since production is GCP, we wire the
real solution from the start rather than build a throwaway path.

## Decision

**Envelope encryption backed by GCP Cloud KMS, with a per-tenant key hierarchy, from day one.**

1. **No secret ever in plaintext** — not in env vars, not in a normal DB column, not in logs/traces/errors, not in
   AI prompts. Connector secrets exist decrypted only in memory, only at connector-run time, and are zeroized
   after use.
2. **Key hierarchy:** GCP Cloud KMS holds the **root CMK** (per-tenant or per-environment key ring) → for each
   secret generate a **data encryption key (DEK)** → encrypt the secret with **AES-256-GCM** → store *ciphertext +
   KMS-wrapped DEK* in Postgres. The CMK never leaves KMS.
3. **`tenant_id` is bound into the AES-GCM AAD** (additional authenticated data), so a ciphertext cannot be
   decrypted or replayed under another tenant's context even if rows were swapped — cryptographic backstop to the
   ADR-0001 RLS boundary.
4. **Least-privilege scopes:** connectors request the minimum OAuth scopes — **read-first**; action/write scopes
   (isolate device, disable user, block IP) only where the tenant's **authority-to-act** grants them (doc 03 §6).
5. **Rotation:** support rotating both the customer credential and the KMS key (KMS key versioning); re-wrap DEKs
   on CMK rotation without re-encrypting payloads. Per-tenant rotation is a first-class operation (doc 02 §7).
6. **Audit every access:** each decrypt/use of a connector credential writes an immutable audit event
   (who/what/when/which connector/why) — feeds NFR-003 and is exactly what auditors and regulators inspect.
7. **Don't roll our own crypto.** Use KMS + a vetted AES-GCM implementation. If we later want centralized
   encryption-as-a-service, dynamic secrets and leasing, **HashiCorp Vault (Transit engine)** is the sanctioned
   upgrade — but direct KMS envelope encryption is simpler, serverless and equally strong for now.

## Consequences

**Positive:** best-in-class secret handling from the first connector; cryptographic tenant binding (AAD) on top of
RLS; clean rotation story; full access audit; the pre-go-live reviewer finds a mature design, not a liability.
Because Render can call GCP KMS via a service account, there is **no throwaway MVP secret path to rewrite**.

**Negative / risks:** a KMS dependency and per-decrypt latency/cost (mitigate with short-lived in-memory caching
of decrypted secrets during an active connector run, never persisted). The GCP service account used from Render
must itself be tightly scoped and its key protected — it becomes a sensitive credential (document its handling).
Sovereign tenants may require **customer-managed keys (CMEK/BYOK)**; the hierarchy already supports a per-tenant
CMK, so this is configuration, not redesign.

## MVP vs best-in-class

- **MVP:** GCP KMS envelope encryption, per-tenant DEK with tenant_id AAD, decrypt-in-memory-only, access audit,
  least-privilege read-first scopes.
- **Best-in-class later:** CMEK/BYOK for regulated/sovereign tenants, optional Vault Transit, automated secret
  rotation schedules, and hardware-backed keys (Cloud HSM) for the highest tiers.

## References

Doc 02 §7 (security architecture — secrets), SRS §8 (connectors) & §13 (security/tenancy), doc 03 §6
(authority-to-act), NFR-001/003/009. Related: [ADR-0001](0001-multi-tenancy.md),
[ADR-0003](0003-ingestion-pipeline.md).
