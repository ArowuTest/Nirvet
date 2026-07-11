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
| Object/evidence store | `platform/blobstore.Store` (this ADR) | local filesystem | **S3-compatible** (B2/R2/S3) | **GCS** (S3-interop or native) |
| Ingest queue | `platform/queue.Queue` (ADR-0003) | Postgres (SKIP LOCKED, tenant-fair) | Postgres / **NATS** | **NATS/JetStream** (Pub/Sub optional) |
| Secret/credential vault | `platform/crypto.SecretCipher` (ADR-0004) | AES-GCM master key | AES master key | **Cloud KMS** (`NIRVET_KMS_KEY_NAME`, pending) |
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

**Negative / follow-ups (status Jul 2026):**
- **Object store — DONE.** An **S3-compatible `blobstore` adapter** (minio-go, path-style) is LANDED and covers
  interim (Backblaze B2 / Cloudflare R2) AND production (AWS S3, or GCS via its S3-interop endpoint). A native-GCS
  SDK adapter is therefore no longer required for go-live. Config is env-only (`NIRVET_S3_*`); verified live
  against B2. Path-traversal-guarded; a prod guard rejects the ephemeral local store unless explicitly allowed.
- **Ingest queue — DONE (NATS).** The scaling backend is **NATS/JetStream** (durable streams + real dead-letter
  subject + replay), selected by `NIRVET_NATS_URL`, behind `platform/queue.Queue`. Pub/Sub remains an optional
  portability target, not a required build. (ADR-0003 updated to match.)
- **Secret vault / KMS — PENDING.** The **Cloud KMS envelope-encryption `crypto` adapter** is the one remaining
  TODO; it needs a real key ring to verify and is slotted at GCP provisioning. The interim AES-GCM master key is
  config-enforced (a startup guard blocks a weak/short key in production).

Interface discipline must be enforced in review (grep for provider SDK imports outside adapters).

## References

ADR-0001 (deployment models), ADR-0002 (event store), ADR-0003 (ingestion), ADR-0004 (credential vault);
SRS §4 (deployment models), §5 (architecture).
