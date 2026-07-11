# Module Definition of Done (DoD)

**Rule:** a module is not "done" until it can answer YES (or a justified N/A) to every question below.
Run this checklist before marking any module complete — retroactively and for new work. Honesty over green ticks:
a documented gap is fine; a hidden one is not.

## The 10 questions

1. **Unit tests** — pure logic covered, runs anywhere (no external deps)?
2. **Integration tests** — exercised against a real DB/dependency (gated on `NIRVET_TEST_DATABASE_URL`)?
3. **Audit logs** — mutations recorded to the immutable audit trail (NFR-003)?
4. **Multi-tenant aware** — every row/query/action tenant-scoped via RLS (ADR-0001)?
5. **RBAC** — endpoints gated by role (`RequireRole`)?
6. **Error handling** — typed `httpx.APIError`, no leaked internals, fail-closed on security?
7. **Documented** — package doc + this DoD; endpoints in the OpenAPI spec?
8. **OpenAPI/Swagger** — endpoints in `backend/api/openapi.yaml`, served at `/openapi.yaml` + `/docs`?
9. **Observable** — metrics + structured logging (+ request/trace IDs), tracing spans?
10. **Horizontal scale** — stateless handler; shared state in DB/Redis; worker uses `SKIP LOCKED`?

## Current matrix (honest, Jul 11 2026 — reviewer 2nd-pass doc refresh)

Legend: ✅ yes · ◑ partial · ⬜ gap · — n/a

> Note: the fuller, per-slice DoD/PARTIAL/STUB picture across all 18 SRS §6 domains lives in the go-live
> roadmap + project memory (`project_nirvet_domain_status`, `project_nirvet_full_buildout`). This table is the
> engineering-DoD snapshot; newly-landed §6 domains (investigation, platform-admin, asset, vulnerability,
> entity-graph, syslog ingress) are folded in below with conservative marks pending the pre-go-live column audit.

| Module | 1 Unit | 2 Integ | 3 Audit | 4 Tenant | 5 RBAC | 6 Errors | 7 Docs | 8 OpenAPI | 9 Observe | 10 Scale |
|---|---|---|---|---|---|---|---|---|---|---|
| auth/iam (+MFA) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| sso (OIDC + SAML) | — | ✅⁸ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| tenant | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ingestion + normalize | ✅ | ✅ | ✅¹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅¹⁴ | ✅ |
| syslog ingress (syslogd) | ✅ | ✅ | ✅¹ | ✅ | — | ✅ | ✅ | — | ✅ | ✅ |
| detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alert | ◑⁶ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| correlation (§6.7) | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| incident | ✅³ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| investigation (§6.9) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| entity-graph (§6.9) | ✅¹⁵ | — | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| asset (§6.15) | ✅¹⁵ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| vulnerability (§6.15) | ✅¹⁵ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| connector (+poller) | ✅¹⁶ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| soar | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ai | ✅⁴ | ✅¹¹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| threatintel (STIX 2.1) | ✅ | ✅¹⁷ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| reporting (+ export) | — | ✅⁷ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| compliance | — | ✅¹⁸ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| billing (slice A+B) | ⬜ | ✅⁵ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| notify (+ outbox, email/SMS) | ⬜ | ✅¹² | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| platform-admin (§6.18) | ✅ | ✅ | ✅ | ✅¹⁹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ticketing (SN/Jira) | ✅⁹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| eventstore (PG + ClickHouse) | — | ✅¹⁰ | — | ✅ | — | ✅ | ✅ | — | ✅ | ✅ |
| crypto / ratelimit / blobstore (+S3) | ✅ | ◑²⁰ | — | ✅ | — | ✅ | ✅ | — | ✅ | ✅² |

¹ ingestion audit = raw_events evidence trail (excluded from the mutation-audit middleware by design).
² rate limiting now has BOTH backends behind the `Allower` interface: in-memory (default) + a Redis token-bucket
  limiter (global across replicas, `NIRVET_REDIS_ADDR`) — horizontal scale ✅. Redis limiter verified against a
  real instance (burst/refill + two-instances-share-one-bucket).
³ incident is covered by the `Heartbeat_EndToEnd` integration test (promote → assign → note → playbook → close)
  and the `IncidentPromotion` test; assign/close/timeline links are all asserted. See `build/HEARTBEAT.md`.
⁴ ai unit tests cover the assistive-only guardrails: offline fallback restates OBSERVED evidence, never implies
  self-execution, routes response through the approval workflow; gateway availability; system-prompt guardrails.
⁵ billing integration test asserts ingest-quota enforcement (meter vs cap) and the non-positive-cap clamp.
⁶ alert has no standalone unit test (CreateFromEvent is DB-bound); its behaviour — idempotent dedupe, field
  mapping, promotion linkage — is covered by AlertDedupe, IncidentPromotion, Heartbeat and Reporting integration.
⁷ reporting aggregates covered by ReportingSummaryAggregates (severity/stage/open counts under RLS).
  tenant now has a unit test (name validation) + integration coverage (harness creates tenants w/ defaults).
⁸ sso covered by mock-IdP integration tests. OIDC (TestSSO_OIDCFlow): JIT provision + session + re-login,
  plus fail-closed nonce/audience/domain/forged-state. SAML (TestSAML_Flow) against a goxmldsig-SIGNED mock IdP:
  happy path + 7 fail-closed controls — tampered assertion, untrusted IdP cert, expired, wrong audience, wrong
  issuer, InResponseTo replay/CSRF, forged RelayState. XML dsig is NOT hand-rolled (gosaml2/goxmldsig); flagged
  for pre-go-live expert security review. OIDC + SAML share one tested login tail (completeSSO).
⁹ ticketing covered by mock-endpoint tests (ServiceNow + Jira create, basic auth, project-key guard) + the
  MirrorIncident DB path (no-op when unconfigured) + an integration test asserting the incident timeline records
  the external ticket ref on open.
¹⁰ eventstore has two backends behind one interface (ADR-0002): Postgres (default) + ClickHouse. Verified against
  a real ClickHouse: append idempotency, tenant isolation on query, severity filter — AND the full heartbeat runs
  end-to-end on ClickHouse (interface swap proven). Gated on NIRVET_CLICKHOUSE_DSN.
¹¹ ai integration = AICopilotIncidentTriage (grounded triage over incident+alerts+asset criticality+SLA; assistive
  wording; audited output via auditMeta) in the flow suite.
¹² notify integration = the durable outbox (SLABreachSweepAlertsOnce asserts enqueue→deliver pending→sent;
  SLANotifyOutboxRetryAndDeadLetter asserts retry→dead-letter, never dropped). Real channels now exist
  (COMM-001): email over SMTP (SSRF-safe via netsafe SafeDialTCP + CRLF header sanitization) and SMS via a
  configurable provider (SafeClient + provider_url validation). Teams/Slack remain the open transport slice.
¹⁴ ingestion observability now includes GC-4 per-job OTel spans across the async pipeline
  (ingest.process_job → ingest.detect → ingest.correlate), each carrying tenant/source attributes.
¹⁵ asset / vulnerability / entity-graph now have pure (DB-free) unit tests — Create input guards
  (asset, vulnerability), RFC3339 parse, and full entitygraph.Build composition via interface fakes (GC-3).
¹⁶ connector now has broader unit coverage incl. the Graph SSRF nextLink host-pin + AAD-tenant escape tests and
  the Defender OData-quote / Entra identity-resolve mock-server tests.
¹⁷ threatintel now has a REAL STIX 2.1 object store (`stix.go`, slice A+B) with tenant-composite uniqueness — no
  longer watchlist-only. Enrichment matches indicators with structured provenance (source/labels/kill-chain).
¹⁸ compliance now persists tenant-scoped control assessments with real per-framework scoring (CIS/ISO etc.),
  replacing the earlier flat-seeded score-0 behaviour (R6-C3); assessment writes are audited via the middleware.
¹⁹ platform-admin is the operator/sovereign super-tenant surface (§6.18); most actions are cross-tenant by design
  and gated by platform-admin RBAC + four-eyes on destructive tenant offboarding.
²⁰ blobstore now has an S3-compatible adapter (minio-go: Backblaze B2 / R2 / AWS S3 / MinIO / GCS-interop),
  path-traversal-guarded, verified live against B2 (round-trip gated on NIRVET_S3_* env).

## Cross-cutting notes

- **#3 Audit** — an audit middleware records **every** successful authenticated mutation, so audit is YES for all
  mutating modules automatically. Read-only modules (reporting/compliance) are n/a.
- **#9 Observability** — metrics (Prometheus) + structured logging + request IDs are platform-wide; **tracing**
  (OpenTelemetry) is implemented in `internal/platform/tracing` (W3C TraceContext propagation, route-templated
  server spans, OTLP/HTTP exporter gated on `NIRVET_OTLP_ENDPOINT`, no-op + zero overhead by default; access
  logs carry `trace_id`). Unit-tested (no-op default, span naming, error status). Portable per ADR-0005 —
  endpoint swaps local → GCP Cloud Trace with no code change.
- **#10 Scale** — API and worker are stateless containers; the ingest worker is safe to run N-wide
  (`FOR UPDATE SKIP LOCKED`). Only rate-limit counters are per-instance (Redis for global limits — ADR-0005).

## Security posture

A security review (Jul 2026) found and fixed 5 Criticals + several High/Med issues
(audit immutability, SSO role escalation, ingest severity ordering, ingestion
durability, production vault guard, SOAR four-eyes, worker panic recovery, self-service
password change, login brute-force lockout). Full findings, fix commits, and the items
**deferred to pre-go-live** are tracked in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).
That file is authoritative for security status.

## Test-coverage gaps closed (this pass)

- **#8 OpenAPI** — DONE: `backend/api/openapi.yaml` embedded + served at `/openapi.yaml` + `/docs`.
- **#9 Tracing** — DONE: OpenTelemetry in `internal/platform/tracing` (+ unit tests), wired into api & worker.
- **#1/#2 tests** — DONE: ai (guardrails), threatintel (enricher), billing (quota), reporting (aggregates),
  tenant (validation), incident (heartbeat). alert is integration-covered (no standalone unit — DB-bound).

## Honest scope caveats (matrix ✅ = "built + tested", NOT "feature-complete")

The matrix rates engineering DoD, not product completeness. What was "intentionally shallow" in the Jul-8
snapshot has largely been deepened since; the CURRENT honest picture:

- **threatintel** — now a REAL STIX 2.1 object store (slice A+B), not watchlist-only.
- **notify** — durable outbox PLUS real email (SMTP) and SMS channels (COMM-001). Teams/Slack transport still open.
- **compliance** — real per-framework control scoring (CIS/ISO), not static.
- **reporting** — JSON aggregates plus evidence-pack and PDF/CSV/XLSX export (injection-safe serializers).
- **syslog listener** — BUILT (`internal/syslogd`), alongside webhook + Microsoft pull.
- **SLA timers + breach alerting** — implemented (per-severity ack/resolve targets, derived breach flags,
  durable-outbox notification).

**Genuinely still open (product / UI / go-live track, not engineering-DoD gaps):**
- **customer-facing portal** and fine-grained **read-side RBAC** for customer/executive/regulator viewers
  (the read-model is drafted — `NIRVET_CUSTOMER_READ_MODEL.md` — pending owner approval before enforcement).
- the **MFA / SSO login UI** (API + enforcement exist; front-end pending designer HTML).
- **Cloud KMS** envelope-encryption adapter (interim AES master key is config-guarded; slot at GCP provisioning).
- Teams/Slack notification transports; billing pure unit tests.
