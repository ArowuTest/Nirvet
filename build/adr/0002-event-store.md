# ADR-0002 — Event & telemetry storage

**Status:** Accepted (assumed sign-off, Jul 2026; pre-go-live review pending)
**Stack:** PostgreSQL (MVP) · ClickHouse (V1) · GCS · BigQuery (cold)

## Context

Nirvet has two very different data workloads: (a) the **SOC system of record** — tenants, users, alerts as
workable objects, cases, evidence metadata, detections, audit — transactional, relational, moderate volume; and
(b) **security telemetry** — raw + normalized events at potentially GB/day per tenant, needing fast time-range
scans, field search, aggregations, and tiered retention (SRS §7). Forcing one store to do both is the classic
SOC-platform scaling mistake. Evidence must also be immutable and defensible (chain-of-custody, doc 02 §4).

## Decision

**Separate the system of record (Postgres) from the telemetry store, behind an `EventStore` interface.**

1. **PostgreSQL = system of record.** Tenants, users/RBAC, alerts, cases, evidence *metadata*, detection config,
   audit log, billing. Strong consistency, RLS isolation (ADR-0001).
2. **`EventStore` is an interface from commit #1**, with two methods that matter: `Append(normalizedEvents)` and
   `Query(tenant, timeRange, filters)`. Swapping the backend is a contained change, never a rewrite.
   - **MVP backend = Postgres**: normalized events in a table partitioned by `(tenant_id, time)`, BRIN index on
     time, GIN on the JSONB payload. Sufficient for demos and first pilots.
   - **V1 backend = ClickHouse**: the hot telemetry store. Columnar, high compression, fast aggregations — the
     best cost/performance fit for security logs and the pattern behind most modern SIEM/analytics products.
     Self-hosted on GCP or ClickHouse Cloud. Every query carries a mandatory `tenant_id` predicate.
   - **OpenSearch is optional**, added only if investigators need rich free-text exploration beyond ClickHouse.
3. **Store raw AND normalized (dual-write):**
   - **Raw event → GCS**, immutable, SHA-256 checksummed, write-once (retention lock), referenced by pointer +
     hash from Postgres. This is the evidence/defensibility record.
   - **Normalized event → EventStore** in the **OCSF-inspired schema** (doc 02 §4: metadata / classification /
     actor / target / action-outcome / threat-context / evidence-pointer) for detection, correlation and search.
4. **Retention is tiered and per-tenant/tier** (SRS §7.3/§7.4): hot (ClickHouse, e.g. 30–90d) → cold
   (**BigQuery** or GCS/Coldline, 1yr+ for compliance) with configurable policy, legal hold, and deletion
   workflows.

## Consequences

**Positive:** each store does what it's good at; MVP ships on Postgres with zero new infra; ClickHouse gives
order-of-magnitude better cost/perf at real volume; raw-in-GCS gives defensible evidence; retention tiering
controls the platform's biggest cost driver (log storage) and satisfies compliance.

**Negative / risks:** dual-write (raw + normalized) needs care to stay consistent — treat raw persist as the
durable checkpoint, normalize downstream (ADR-0003), and make normalization replayable from raw. Running
ClickHouse is real ops (sharding/replication at scale) — defer until volume justifies it; the interface means we
pay that cost only when needed. Cross-store tenant isolation must be enforced in the EventStore layer (mandatory
tenant predicate) — cover it with the ADR-0001 isolation tests.

## MVP vs best-in-class

- **MVP:** Postgres EventStore + GCS raw + simple time+tenant retention. Proves the model end to end.
- **Best-in-class later:** ClickHouse hot store, BigQuery cold tier, per-tenant retention/legal-hold UI,
  searchable evidence with verifiable chain-of-custody, and replay-from-raw for re-normalization/detection
  backfills.

## References

SRS §7 (Data/Schema/Storage/Retention), doc 02 §4 (normalized event model), NFR-004 (scalability), NFR-006
(residency/retention). Related: [ADR-0001](0001-multi-tenancy.md), [ADR-0003](0003-ingestion-pipeline.md).
