# Architecture gates

**Rule:** before writing a major module (Detection, SOAR, AI, Connectors, Reporting, Dashboards, and future
work), do a short **design review against the SRS** — it's far cheaper to correct a design before the code than
after. A gate is a few paragraphs, not a document; it lives here.

## Gate checklist (per module)

1. **SRS section** it implements (e.g. §6.6 Detection) — re-read it.
2. **Interfaces / contracts** it exposes and consumes; does it stay behind the portability seams (ADR-0005)?
3. **Invariants** honoured: tenant isolation (RLS), authority-to-act, assistive-only AI, audit-everything, DoD.
4. **Data model** additions (tables, RLS policy, indexes leading with `tenant_id`).
5. **End-to-end fit**: where it sits in the flow *Customer → Auth → Tenant → Source → Normalize → Event Store →
   Detection → Alert → Incident → Dashboard → Playbook → Notification*.
6. **What's deferred** and why (cost, external creds, scale) — logged, not silently skipped.

## Gates applied so far (Jul 2026)

- **Detection (§6.6):** condition-rule engine (portable subset of Sigma), global+tenant rules under RLS, cached
  eval (no DB hit per event), alert idempotency `event_id:rule_id`. Deferred: full Sigma import, coverage heatmap.
- **SOAR (§6.11):** playbooks + runs, **authority-to-act** gate (`Allowed(mode, risk)`) + approval workflow,
  audit. Deferred: real connector action execution (needs live creds) — actions recorded as simulated.
- **AI (§6.12):** assistive-only gateway, tenant-scoped retrieval, evidence-linked, full audit, **offline
  fallback**. Deferred: RAG over case history, eval harness.
- **Connectors (§6.4/§8):** config + **vault-encrypted creds** (ADR-0004), source-key webhook ingestion.
  Deferred: real Microsoft Graph/EDR OAuth pull loops, syslog TCP listener.
- **Reporting (§6.13):** tenant aggregates. Deferred: templated PDF/evidence-pack export.
- **Cloud portability (ADR-0005):** evidence moved behind `blobstore.Store`. Deferred: GCS/Pub/Sub/KMS adapters.

## Gate: Microsoft Graph/Defender pull connector (§8 MVP) — reviewed Jul 2026

- **SRS §8 API-polling pattern:** scheduled workers, OAuth/token handling, pagination, rate-limit backoff,
  checkpointing. **§6.4** connector framework. Fits the flow at *Source → Normalize*.
- **Contracts:** the poller does NOT bypass the pipeline — it fetches raw vendor alerts and pushes each through
  `ingestion.Service.Ingest` with `source="microsoft-defender"` and the raw alert in `Data`, so the existing
  Defender normalizer, blob evidence, dedupe, detection and metrics all apply unchanged. Idempotent (ADR-0003:
  dedupe on source+native_id). Credentials via the vault (ADR-0004: client secret sealed; decrypted in memory at
  poll time only). Portability: Graph base URL and token URL are injectable, so the client is testable against a
  mock and unchanged for GCP.
- **Data:** connector `config` jsonb holds non-secret `client_id`/`azure_tenant`/`checkpoint`; `secret_ciphertext`
  holds the sealed client secret. A SECURITY DEFINER `connector_list_pullers()` lets the system worker enumerate
  enabled pull connectors across tenants (like the webhook lookup); per-connector checkpoint/health updates use
  the tenant context (no bypass).
- **Invariants:** tenant isolation (each ingest uses the connector's tenant), audit via ingestion, no destructive
  action (read-only pull). **Deferred:** delta queries, subscription/webhook push, Defender incident API,
  per-connector schedules — MVP polls on a fixed interval.

## Next gates (before starting)
- **MFA/SSO** (§6.2): OIDC/SAML; review session model + tenant IdP mapping.
- **ClickHouse event store** (ADR-0002 V1): implement the `EventStore` backend; review retention tiering.
- **Dashboards** (UI): only after the above; the API contracts already exist.
