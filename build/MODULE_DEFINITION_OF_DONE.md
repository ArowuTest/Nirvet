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

## Current matrix (honest, Jul 2026)

Legend: ✅ yes · ◑ partial · ⬜ gap · — n/a

| Module | 1 Unit | 2 Integ | 3 Audit | 4 Tenant | 5 RBAC | 6 Errors | 7 Docs | 8 OpenAPI | 9 Observe | 10 Scale |
|---|---|---|---|---|---|---|---|---|---|---|
| auth/iam (+MFA) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| sso (OIDC + SAML) | — | ✅⁸ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| tenant | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ingestion + normalize | ✅ | ✅ | ✅¹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| detection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| alert | ◑⁶ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| correlation (§6.7) | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| incident | ✅³ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| connector (+poller) | ◑ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| soar | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ai | ✅⁴ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| threatintel | ✅ | ◑ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| reporting | — | ✅⁷ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| compliance | — | — | — | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| billing | ⬜ | ✅⁵ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| notify | ⬜ | — | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ticketing (SN/Jira) | ✅⁹ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| eventstore (PG + ClickHouse) | — | ✅¹⁰ | — | ✅ | — | ✅ | ✅ | — | ✅ | ✅ |
| crypto / ratelimit / blobstore | ✅ | — | — | ✅ | — | ✅ | ✅ | — | ✅ | ✅² |

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

## Gaps being closed (this pass)

- **#8 OpenAPI** — DONE: `backend/api/openapi.yaml` embedded + served at `/openapi.yaml` + `/docs`.
- **#9 Tracing** — DONE: OpenTelemetry in `internal/platform/tracing` (+ unit tests), wired into api & worker.
- **#1/#2 tests** — DONE: ai (guardrails), threatintel (enricher), billing (quota), reporting (aggregates),
  tenant (validation), incident (heartbeat). alert is integration-covered (no standalone unit — DB-bound).
  Every module now has meaningful unit and/or integration coverage; no silent gaps remain in the matrix.
