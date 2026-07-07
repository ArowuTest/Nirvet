# ADR-0005 — Cloud portability (local → Render/Vercel → GCP)

**Status:** Accepted (owner directive, Jul 2026; pre-go-live review pending)
**Deciders:** Owner + build agent

## Context

Nirvet must be **portable from day one**. We start on Render (Go API) + Vercel (Next.js) for speed, but the
**intended go-live architecture is GCP or in-country/local hosting** (sovereign SOC, ADR-0001). Provider lock-in
in the core would make that move expensive and would block the sovereign proposition. So no core code may depend
on a specific cloud SDK — only on interfaces the platform owns.

## Decision

**Every cloud-coupled capability sits behind a platform interface; the implementation is selected by config.**
Swapping providers is a wiring change in `cmd/api`, never a change to callers.

| Capability | Interface | Local / MVP | Render | GCP (go-live) |
|---|---|---|---|---|
| Relational store | `platform/database` (pgx) | Docker Postgres | Render Postgres | Cloud SQL / AlloyDB |
| Telemetry store | `platform/eventstore.EventStore` (ADR-0002) | Postgres | Postgres | **ClickHouse** / BigQuery |
| Object/evidence store | `platform/blobstore.Store` (this ADR) | local filesystem | disk/GCS | **GCS** (`NIRVET_GCS_BUCKET`) |
| Ingest queue | `platform/queue.Queue` (ADR-0003) | Postgres (SKIP LOCKED) | Postgres/Redis | **Pub/Sub** |
| Secret/credential vault | `platform/crypto.SecretCipher` (ADR-0004) | AES-GCM master key | KMS | **Cloud KMS** (`NIRVET_KMS_KEY_NAME`) |
| LLM | `ai.Gateway` | offline fallback | Anthropic | Anthropic / Vertex |
| Rate limiting | `platform/ratelimit` | in-memory | in-memory | Redis (shared) |

### Rules

1. **No provider SDK import outside its adapter.** e.g. `cloud.google.com/go/storage` may appear only inside the
   `blobstore` GCS adapter, never in domain code.
2. **Config-selected backends.** `New(...)` constructors choose the implementation from env
   (`NIRVET_GCS_BUCKET`, `NIRVET_KMS_KEY_NAME`, DSNs). Default = local.
3. **Twelve-factor.** All config via env; no hard-coded endpoints, regions, or credentials.
4. **Containerised.** The API and worker are stateless containers; state lives in the swappable backends. This
   makes them runnable on Render, Cloud Run, GKE, or a sovereign VM identically.
5. **Data residency is a deployment property**, not a code property (ADR-0001 `isolation_tier`): a sovereign
   tenant is the same binaries with GCS/KMS/Cloud SQL pinned to an in-country region.

## Consequences

**Positive:** the Render→GCP move (and sovereign/local deployments) is incremental and low-risk; each backend can
be adopted when justified (e.g. ClickHouse at V1) without touching business logic; the sovereign proposition is
credible because portability is structural.

**Negative / follow-ups:** the GCS `blobstore` adapter, Pub/Sub `queue` adapter, and KMS `crypto` adapter are
currently TODO stubs behind their interfaces — they must be implemented and load-tested before the GCP go-live.
Interface discipline must be enforced in review (grep for provider SDK imports outside adapters).

## References

ADR-0001 (deployment models), ADR-0002 (event store), ADR-0003 (ingestion), ADR-0004 (credential vault);
SRS §4 (deployment models), §5 (architecture).
