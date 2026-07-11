# build/ — implementation

**The application scaffold is live at the repo root (`../backend`, `../frontend`, `../deploy`).** This folder now
holds the Architecture Decision Records that govern it. The requirements & design suite is in
[`../docs/markdown/`](../docs/markdown/) (orientation: [`../knowledge/platform-overview.md`](../knowledge/platform-overview.md)).

> **Where the code lives:** `../backend` (Go API + worker + migrations), `../frontend` (Next.js console),
> `../deploy` (docker-compose). See [`../RUNNING.md`](../RUNNING.md) for how to run and what's verified.

## Architecture Decision Records → [`adr/`](adr/)

Accepted under assumed sign-off (owner, Jul 2026); a security architect reviews the final solution before go-live.

- [ADR-0001 — Multi-tenancy & isolation](adr/0001-multi-tenancy.md) — pooled Postgres + RLS default; siloed for regulated/sovereign; `isolation_tier`.
- [ADR-0002 — Event & telemetry storage](adr/0002-event-store.md) — Postgres system-of-record; `EventStore` interface → ClickHouse hot store; GCS raw evidence; BigQuery cold.
- [ADR-0003 — Ingestion pipeline](adr/0003-ingestion-pipeline.md) — durable at-least-once + idempotent dedup + DLQ + per-tenant quota + tenant-fair scheduling; Postgres `SKIP LOCKED` (MVP) → **NATS/JetStream** (built scaling backend); Pub/Sub optional.
- [ADR-0004 — Connector credential vault](adr/0004-connector-credential-vault.md) — envelope-encryption design (Cloud KMS at go-live); interim AES-GCM master key with tenant_id AAD; every decrypt audited via the `Vault.Open` chokepoint (GC-1).
- [ADR-0005 — Cloud portability](adr/0005-cloud-portability.md) — every cloud-coupled capability behind a platform interface, config-selected. Object store = S3-compatible adapter (B2/R2/S3/GCS-interop), queue = NATS, KMS pending.
- [ADR-0006 — Canonical event schema](adr/0006-canonical-event-schema.md) — versioned OCSF-inspired normalized event; vendor/product/MITRE promoted to columns.

## Implementation status (Jul 2026)

**The platform is built, not a scaffold.** All 18 SRS §6 domains are implemented behind the invariants below;
the Go API + worker, 100 migrations, and the Next.js console live at the repo root. See [`../RUNNING.md`](../RUNNING.md)
for how to run and what's verified, and the go-live roadmap for what remains (customer-facing read-side RBAC/portal
UI, Cloud KMS adapter, and the pre-go-live security passes).

Where to look:

- **Reference architecture & requirements:** [`../docs/markdown/`](../docs/markdown/) (the SRS + design suite) —
  the authoritative spec; don't re-derive it.
- **Per-domain build status:** the go-live roadmap + project memory track DONE/PARTIAL/STUB across all §6 domains.
- **Engineering Definition of Done:** [`MODULE_DEFINITION_OF_DONE.md`](MODULE_DEFINITION_OF_DONE.md) — the honest
  per-module matrix.
- **Security status:** [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) is authoritative (5 Criticals + High/Med fixed;
  items deferred to pre-go-live listed).
- **Invariants every module honours:** [`../CLAUDE.md`](../CLAUDE.md) — tenant isolation (RLS), authority-to-act
  gating, assistive-only AI, audit-everything, the Definition of Done.

Nothing here is production-ready until the pre-go-live security-architect review and the launch-line items in the
roadmap are cleared.
