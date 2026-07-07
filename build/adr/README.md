# Architecture Decision Records — Nirvet

Foundational decisions for the Nirvet SOC platform. Each ADR is the single source of truth for *why* a choice was
made; build against them and update them (never silently diverge).

## Status of these ADRs

**Accepted — assumed sign-off (owner, Jul 2026).** The owner authorised proceeding with best engineering judgment
and capturing decisions here, with a **formal expert security-architect review scheduled before go-live** (not
per-decision). These are built to a best-in-class standard so that review is a confirmation, not a rescue.
Assumed sign-off covers the **build phase only** — it is not go-live approval.

## Index

| ADR | Decision | One-line |
|---|---|---|
| [0001](0001-multi-tenancy.md) | Multi-tenancy & isolation | Pooled Postgres + RLS by default; siloed (dedicated DB / in-region deployment) for regulated & sovereign; `isolation_tier` on tenant. |
| [0002](0002-event-store.md) | Event & telemetry storage | Postgres = system of record; `EventStore` interface with Postgres (MVP) → ClickHouse (V1) hot store; GCS raw evidence; BigQuery cold. |
| [0003](0003-ingestion-pipeline.md) | Ingestion pipeline | Durable at-least-once + idempotent dedup + dead-letter + per-tenant quota; River/Postgres (MVP) → GCP Pub/Sub (prod). |
| [0004](0004-connector-credential-vault.md) | Connector credential vault | GCP KMS envelope encryption from day one; per-tenant DEK with tenant_id as AAD; decrypt-in-memory-only; full access audit. |

## Conventions

- **Stack (fixed):** Go backend (entity→repo→usecase→handler) · Next.js + TypeScript · PostgreSQL ·
  Render + Vercel + GitHub for MVP → **GCP before go-live**.
- **Non-negotiable invariants** (see [`../../CLAUDE.md`](../../CLAUDE.md)): tenant isolation everywhere ·
  authority-to-act gating · assistive-only AI · audit everything · Definition of Done.
- New foundational decisions get a new numbered ADR. Superseding an ADR: mark the old one `Superseded by ADR-NNNN`
  and link forward.

## Traceability

These ADRs realise requirements in the SRS ([`../../docs/markdown/00_SRS.md`](../../docs/markdown/00_SRS.md)) and
docs 01–06, and honour NFR-001/003/006/009 (security, auditability, residency, safety). The pre-go-live review
should check the built system against both the ADRs and the SRS §13 (security/multi-tenancy) and §18 (acceptance).
