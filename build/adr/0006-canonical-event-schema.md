# ADR-0006 — Canonical Event Schema & Schema Registry

**Status:** Accepted (assumed sign-off, Jul 2026; pre-go-live review pending)
**Relates to:** ADR-0002 (event store), ADR-0003 (ingestion). SRS §6.5 (normalization/entity resolution).

## Context

Nirvet ingests from many vendors (Microsoft Defender/M365, CrowdStrike, Okta, Palo Alto, AWS GuardDuty, and
more to come). If each connector's data flows downstream in its own shape, then detection, correlation, AI,
analytics and dashboards all have to special-case every vendor — the classic SOC-platform tar pit. The single
most valuable asset a platform like this builds over time is **one canonical event schema that every connector
emits, forever**, so everything downstream depends on the schema, never on a vendor.

## Decision

**Define a versioned, OCSF-inspired canonical Normalized Event that every source normalizer must produce, and
treat the schema as a first-class, versioned contract ("registry as code").**

1. **The normalizer registry IS the schema registry.** Each connector registers a `Mapper`
   (`ingestion.RegisterMapper`) that translates the vendor payload into the canonical shape. Downstream stages
   (detection/enrichment/AI/analytics) read only canonical fields. Adding a vendor = one mapper + one test; it
   never changes a downstream consumer. (This is the code-level realisation of a schema registry; a networked
   registry service, Avro/Protobuf wire schemas and compatibility CI are a later increment — see Deferred.)

2. **Every normalized event carries `schema_version`** (first-class column in both event-store backends). This
   is the enabler for evolution: consumers can branch on version, and backfills/re-normalisation can target a
   version. Current version = **`1.0`** (`eventstore.CanonicalSchemaVersion`).

3. **Canonical field catalogue (v1.0).** Structured, high-value fields are first-class; the full normalized body
   travels in `data`. Entities use *typed refs* (`user:`, `host:`, `ip:`, `resource:`) so a single field carries
   both type and value.

   | Canonical field | Meaning | Reviewer's field(s) |
   |---|---|---|
   | `id` | event UUID | event_id |
   | `tenant_id` | owning tenant | tenant_id |
   | `connector_id` | source connector | connector_id |
   | `source` | source key (e.g. `crowdstrike-falcon`) | source |
   | `schema_version` | canonical schema version | — |
   | `data.vendor` / `data.product` | vendor + product (e.g. CrowdStrike / Falcon) | vendor, product |
   | `class_name` / `activity_name` / `action` | what happened | event_type |
   | `severity` | canonical band (informational..critical) | severity |
   | `observed_at` / `collected_at` | event + ingest time | timestamp |
   | `actor_ref` | typed actor (`user:`/`ip:`) | actor, ip |
   | `target_ref` | typed target (`host:`/`ip:`/`resource:`) | asset, hostname, ip |
   | `outcome` | success/failure/malicious | — |
   | `data.mitre` | ATT&CK technique ids | mitre_tactic, mitre_technique |
   | `data.threat_intel_hits` / `data.ioc` | enrichment / indicators | ioc |
   | `raw_pointer` + `checksum` | evidence pointer to the immutable raw event | raw_payload |
   | `data` | full normalized body | normalized_payload |

4. **Evolution policy.** Additive changes (new optional fields) keep the same major version. Breaking changes
   (renaming/removing a field, changing a type) bump the major version and require a re-normalisation plan
   (events are replayable from the immutable raw store, ADR-0002/0003). Never silently repurpose a field.

## Consequences

**Positive:** downstream code is vendor-agnostic and stable; new connectors are cheap and safe; analytics and
dashboards have one shape to aggregate; `schema_version` makes the schema evolvable without a big-bang migration;
the raw-event evidence store means any version can be rebuilt by replay.

**Negative / risks:** the canonical schema is now a contract — changing it carelessly breaks consumers, hence the
explicit version + evolution policy. Some vendor richness is flattened into `data`; promoting the hottest of
those (e.g. `mitre`, `ip`, `hostname`) to dedicated indexed columns is a v1.1 increment when query patterns
justify it.

## Deferred (logged, not silently skipped)

- Promote hot `data` fields (`mitre`, `ip`, `hostname`, `vendor`, `product`) to dedicated indexed columns in
  both stores (schema **v1.1**) when analytics query patterns justify the column cost.
- A networked schema-registry service with Avro/Protobuf wire contracts + compatibility checks in CI (only if we
  ever expose the raw event bus to external producers; the in-process mapper registry covers current needs).
- Entity-resolution/asset-graph (SRS §6.5) that links `actor_ref`/`target_ref` to a canonical asset/identity.

## References

SRS §6.5, doc 02 §4 (normalized event model), OCSF. Related: [ADR-0002](0002-event-store.md),
[ADR-0003](0003-ingestion-pipeline.md).
