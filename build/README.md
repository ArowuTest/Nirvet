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
- [ADR-0003 — Ingestion pipeline](adr/0003-ingestion-pipeline.md) — durable at-least-once + idempotent dedup + DLQ + per-tenant quota; River/Postgres → Pub/Sub.
- [ADR-0004 — Connector credential vault](adr/0004-connector-credential-vault.md) — GCP KMS envelope encryption from day one; per-tenant DEK with tenant_id AAD.

## When implementation starts

The architecture is already specified — don't re-derive it. Pull from:

- **Reference architecture & tech direction:** [`../docs/markdown/02_technical_architecture.md`](../docs/markdown/02_technical_architecture.md)
  and SRS §5 / §5.3 (Next.js/React portals · API gateway REST/GraphQL · OIDC/SAML SSO · collectors + queues ·
  stream processing · PostgreSQL + object storage + OpenSearch/ClickHouse + vector store · rules engine ·
  workflow/SOAR engine · LLM gateway · Kubernetes/CI-CD).
- **What to build first (MVP):** [`../docs/markdown/06_build_backlog.md`](../docs/markdown/06_build_backlog.md) —
  the 36 MVP stories across epics E01–E09 (tenant mgmt, IAM/SSO, ingestion/normalisation, alert queue, case mgmt,
  evidence/audit, customer portal/reporting, Microsoft connectors, syslog/webhook/API collectors).
- **Invariants to honour in every module:** see [`../CLAUDE.md`](../CLAUDE.md) — tenant isolation, authority-to-act
  gating, assistive-only AI, audit-everything, the Definition of Done.

## Suggested first move

Confirm the tech stack and repo strategy with the owner, then scaffold the MVP slice (tenant + ingestion + alert
queue + case management) behind strong tenant isolation, with the OCSF-inspired normalized event model
(doc 02 §4) as the shared contract. Get expert cyber/SOC review before anything is treated as production-ready.
