# ADR-0003 — Ingestion pipeline

**Status:** Accepted (assumed sign-off, Jul 2026; pre-go-live review pending)
**Stack:** Go · River/PostgreSQL (MVP) · GCP Pub/Sub (prod)

## Context

Ingestion is where a SOC platform earns or loses trust: **a customer's security event must never be silently
dropped.** Sources are diverse (syslog, webhooks, API pollers), volume is spiky, and Render has no managed Kafka.
The infrastructure can be simple for MVP, but the *delivery semantics* cannot be. Backlog E03/E09 and US-012
(parser error queue) codify this.

## Decision

**A durable, at-least-once, idempotent pipeline with a dead-letter path and per-tenant quota — simple infra now,
Pub/Sub later.**

Pipeline stages (each idempotent and observable):
**receive → authenticate source → persist raw (durable checkpoint) → normalize (OCSF) → enrich
(asset / identity / threat-intel) → correlate / detect → alert.**

1. **Collectors:** a syslog listener (TCP/TLS), an authenticated webhook endpoint (HMAC/API-key/OAuth), and
   scheduled API pollers (OAuth, pagination, rate-limit backoff, checkpointing) — per doc 02 §5.
2. **Durable buffer:** **River** (Postgres-native job queue in Go: transactional enqueue, `FOR UPDATE SKIP
   LOCKED`). Chosen for MVP so there's one durable store and enqueue is transactional with the raw persist — no
   extra Redis. Redis/NATS only if a specific need appears.
3. **At-least-once + idempotent dedup:** every event gets a **dedupe key = source + native-id + payload-hash**;
   a unique constraint / seen-set makes reprocessing safe (backlog US-011). Persist raw **before** acknowledging
   the source, so a crash never loses an event.
4. **Dead-letter / parser-error queue (US-012):** events that fail validation or normalization go to a DLQ with
   the error and raw pointer — visible, replayable, alertable. **Nothing is dropped silently, ever.**
5. **Per-tenant quota & backpressure:** meter ingestion (GB/day or events/min) against the tenant's tier
   entitlement (SRS §15); throttle politely and alert near cap rather than falling over or unfairly starving other
   tenants. Enforced with tenant context (ADR-0001).
6. **Production (GCP):** promote the backbone to **Pub/Sub** (durable, autoscaling, native dead-letter topics),
   workers on Cloud Run/GKE, sink to ClickHouse (ADR-0002). Kafka only if replay/stream-processing needs later
   exceed Pub/Sub — not expected early.

## Consequences

**Positive:** correct durability/idempotency from day one with humble infra; the raw-first checkpoint makes
normalization/detection replayable (supports ADR-0002 backfills); DLQ + quotas make the service operationally
honest; clean, low-risk path to Pub/Sub at scale.

**Negative / risks:** at-least-once means consumers must be idempotent everywhere (dedupe key is load-bearing —
test it). River on Postgres shares the primary's IO budget; watch it as volume grows and cut over to Pub/Sub
before it strains the DB. Poller connectors depend on the credential vault (ADR-0004) and must handle
token-refresh + rate limits without leaking secrets into logs.

## MVP vs best-in-class

- **MVP:** syslog + webhook + a couple of Microsoft pollers → River → Postgres EventStore, with dedup, DLQ and
  quota in place.
- **Best-in-class later:** Pub/Sub backbone, autoscaling stream enrichment, real-time correlation, per-source
  health/health-SLA dashboards (backlog connector-health), and exactly-once-effect via idempotent sinks.

## References

SRS §8 (Integration/Connector), doc 02 §5 (integration architecture), backlog E03/E09/US-011/US-012, NFR-005
(latency), NFR-008 (extensibility). Related: [ADR-0002](0002-event-store.md),
[ADR-0004](0004-connector-credential-vault.md).
