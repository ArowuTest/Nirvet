# Architecture gates

**Rule:** before writing a major module (Detection, SOAR, AI, Connectors, Reporting, Dashboards, and future
work), do a short **design review against the SRS** — it's far cheaper to correct a design before the code than
after. A gate is a few paragraphs, not a document; it lives here.

## Periodic platform review (every 2-3 weeks) — reviewer-recommended Jul 2026

Beyond the per-module gate below, review the whole platform on a cadence against these questions. The goal is to
catch architectural drift early, while it's still cheap to correct.

1. Does this design still support **500 customers** (and the target event volume)?
2. Can it deploy in **Ghana / Nigeria / Kenya / the UK** (and sovereign/on-prem) without a redesign?
3. Is it still **cloud-portable** (Render / small GCP → large GCP / sovereign DC), no provider lock-in?
4. Does it still preserve **tenant isolation** end-to-end (RLS + mandatory tenant predicates + vault AAD)?
5. Can we **replace an underlying implementation without changing business logic** (interfaces intact)?

**Scaling sequence (decided Jul 2026, reviewer-aligned).** Heavy infra is introduced *when scale demands it*,
behind interfaces that already exist — not up front:
- **Redis before NATS.** Introduce Redis (~20 customers / first horizontal API scale-out) for distributed
  rate-limit counters + cache — with N API replicas, per-instance in-memory limits diverge. The `ratelimit`
  package is the seam; add a Redis backend behind it.
- **NATS/Kafka** once event volume approaches **>500M/day** or multiple worker pools are needed (the `queue`
  interface, ADR-0003, is Postgres-backed today and swaps with no business-logic change).
- **ClickHouse** — already promoted to a real backend (ADR-0002) behind `EventStore`; Postgres stays default.

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

## Completed since
- **MFA / TOTP** (§6.2) — DONE & tested: stdlib RFC 6238, vault-encrypted secret, enroll/activate/disable +
  login enforcement. Deferred: WebAuthn, backup codes.
- **Heartbeat + Assign-analyst** (§6.8/§6.9) — DONE & tested: single continuous E2E thread guarded by
  `Heartbeat_EndToEnd`; added `incident.Assign` (same-tenant check, timeline entry) + FK hardening
  (migration 0009). See `build/HEARTBEAT.md`.
- **Distributed tracing** (NFR-007 observability / DoD #9) — DONE & unit-tested. Gate: built on OpenTelemetry
  (vendor-neutral → portable, ADR-0005; OTLP endpoint swaps local→GCP Cloud Trace with no code change).
  Contract: `tracing.Init` installs W3C TraceContext propagators always; a batched OTLP/HTTP exporter only
  when `NIRVET_OTLP_ENDPOINT` is set — otherwise a true no-op (zero overhead, no network, offline-safe).
  Server-span middleware names spans by the route template (`r.Pattern`, low cardinality), records
  method/route/status, marks 5xx as error, and is fail-open (never breaks a request). Access logs carry
  `trace_id` for log↔trace correlation. Wired into cmd/api (middleware chain) and cmd/worker (init).
  Invariants: no PII in span attributes (route template + status only, never full URLs/bodies), fail-open.
  Deferred: DB/pgx spans (otelpgx), span links carried across ingest→worker via the queue row, worker
  per-job spans — logged, not silently skipped.

## Gate: SSO — OIDC (§6.2 IAM-001) — reviewed Jul 2026
- **SRS:** IAM-001 (local users + SSO SAML/OIDC), IAM-008 (user lifecycle incl. invitation/activation — JIT
  provisioning is the SSO onboarding path), IAM-010 (log SSO logins/failures). Fits the flow at *Customer →
  Auth*: SSO is an alternate front door to the same Nirvet session JWT the password path issues.
- **Scope now = OIDC authorization-code + PKCE + nonce.** Per-tenant IdP connection; JIT user provisioning
  (find-or-create by verified email, default role, email-domain allowlist); id_token verified via the IdP's
  JWKS (RS256; iss/aud/exp/nonce checked). **Deferred (logged):** SAML 2.0 (XML dsig — its own gate), PAM /
  break-glass (IAM-004/006), device-trust/geo-anomaly (IAM-007), IdP-driven role mapping/SCIM.
- **Contracts / portability:** the OIDC client's discovery/token/JWKS URLs derive from the issuer but the HTTP
  client + a discovery override are injectable, so the whole flow is integration-tested against an httptest
  mock IdP (RS256-signed id_token) and is unchanged for GCP. No provider SDK — stdlib crypto + golang-jwt.
- **Data:** `sso_connections` (tenant-scoped, RLS+FORCE): protocol/issuer/client_id, `client_secret` sealed in
  the vault (ADR-0004, tenant AAD), redirect_uri, default_role, email_domain, enabled. The public callback is
  unauthenticated, so a SECURITY DEFINER `sso_get_connection(id)` resolves the connection cross-tenant (like
  `connector_list_pullers`); JIT user creation then runs inside that connection's tenant context. State is a
  short-lived signed JWT (auth secret) carrying connection_id + nonce + PKCE verifier — stateless, no server
  session store.
- **Invariants:** tenant isolation (connection + JIT user both tenant-bound); secret vault-encrypted, never
  logged; fail-closed (bad iss/aud/nonce/exp or email outside the allowlist → reject); audit every SSO login
  and every connection change. Note: MFA (IAM-003) for SSO users is expected to be enforced at the IdP;
  layering Nirvet MFA on top of SSO is deferred and documented.

## Gate: Connector expansion — source-normalizer registry (§6.4/§6.5, §8) — reviewed Jul 2026
- **SRS:** §6.4 connector framework, §6.5 normalization/entity resolution. The whole point: every source plugs
  into ONE pipeline (*Source → Normalize → EventStore → Detect → Alert → Incident*), so a new vendor is just a
  **source mapper + a connector config**, never new downstream code. This is "integration-first, not
  integration-dependent" made concrete.
- **Design:** replace the growing `switch` in `ingestion.Normalize` with a **registry** (`map[source]Mapper`).
  Each vendor registers a small mapper (raw vendor fields → canonical OCSF-inspired: class/actor/target/action/
  outcome/severity/mitre). `Normalize` runs the mapper (identity fallback) then canonicalises severity — so
  vendor numeric scales (GuardDuty 0–8.9, CrowdStrike 1–100) are banded inside the mapper. Adding a source =
  one file + unit test; zero pipeline change.
- **Scope now:** CrowdStrike Falcon (EDR), Okta (identity/system log), Palo Alto (firewall threat log), AWS
  GuardDuty (cloud findings) — the highest-value telemetry sources from the owner's list, each unit-tested and
  one proven end-to-end through the webhook connector + heartbeat. **Deferred (logged):** Azure Sentinel/Defender-
  for-Cloud, GCP SCC (source mappers, same pattern), and the OUTBOUND ticketing integrations ServiceNow/Jira
  (these are notify/SOAR action targets, not sources — a separate outbound gate). Real vendor *pull/OAuth loops*
  beyond Microsoft also deferred (webhook ingestion covers them now; pull is per-vendor auth work).
- **Invariants:** unchanged tenant isolation/idempotency/audit (all downstream of Normalize); mappers are pure
  functions (no I/O), defensively typed (never panic on a missing/oddly-typed field); severity always lands in
  the canonical set. Fits the flow exactly at the Normalize stage — the heartbeat proves it.

## Gate: Outbound ticketing — ServiceNow + Jira (§6.16, §8) — reviewed Jul 2026
- **SRS:** §6.16 notification/collaboration + §8 integrations. Fits the flow at *Incident → Timeline → Customer
  Notification*: when an incident opens, mirror it to the tenant's ITSM so the customer works it in their own
  system of record, and record the external ticket ref on the case timeline.
- **Design:** a dedicated `internal/ticketing` package (not a notify Channel — ticketing returns an external
  ref and is idempotent per incident, which the fire-and-forget Channel interface doesn't model). `Provider`
  interface `Create(ctx, cfg, ticket) (ref, url, err)`; **ServiceNow** (Table API `/api/now/table/incident`,
  basic auth) and **Jira** (REST v3 `/rest/api/3/issue`, email+API-token basic auth) impls. HTTP client + base
  URL injectable → mock-tested, unchanged for prod (ADR-0005). No vendor SDK.
- **Data:** per-tenant `ticketing_connections` (migration 0011, RLS+FORCE): provider, base_url, config jsonb
  (project key / assignment group), credential **vault-sealed** (ADR-0004). Runs in the tenant context (incident
  open is authenticated), so normal RLS — no SECURITY DEFINER needed.
- **Seam:** `incident.Service.WithTicketer`; `CreateFromAlert` calls it **best-effort** (a ticketing outage must
  never block incident creation), records `Ticket created: <ref> <url>` as a timeline `action` entry, and audits.
  This is product-configured outbound (the tenant set up their ITSM), not an ungated response action — so it is
  NOT SOAR authority-gated (unlike isolate-device); it's a notification/record, like notify.
- **Invariants:** tenant isolation (connection + call both tenant-bound); creds vault-sealed, never logged;
  best-effort + fail-open on the incident path; audit `ticket.created`. **Deferred (logged):** ticket
  update/close sync (two-way), async delivery (inline now), attachment/evidence push.

## Gate: ClickHouse event store (ADR-0002 V1) — reviewed + BUILT + verified Jul 2026
- **ADR-0002:** separate the SOC system-of-record (Postgres) from high-volume telemetry (ClickHouse) behind the
  `EventStore` interface — a contained backend swap, never a rewrite. Fits the flow at *Normalize → Store*.
- **Built:** `eventstore.ClickHouseStore` (clickhouse-go v2, no raw SQL strings beyond parameterised queries).
  ReplacingMergeTree(collected_at) `ORDER BY (tenant_id, dedupe_key)`. **Idempotency:** Append pre-filters
  dedupe keys already present for the tenant and inserts only new ones (returns the new count, matching Postgres
  semantics the pipeline relies on); ReplacingMergeTree is the race-window backstop. **Isolation:** ClickHouse has
  no RLS, so EVERY query carries a mandatory `tenant_id` predicate (also the PK prefix) — verified by a
  tenant-leak test. Config-selected via `NIRVET_CLICKHOUSE_DSN` (`eventstore.New`), Postgres default; wired into
  api + worker.
- **Verified against a REAL instance** (Docker `clickhouse-server:24.8`): dedicated store test (append
  idempotency, tenant isolation on query, severity filter) AND the **full heartbeat run end-to-end on ClickHouse**
  (interface swap proven — same pipeline, both backends green). Postgres default unchanged.
- **Known limitation (logged):** `reporting.Summary`'s `events_last_24h` still counts the Postgres `events` table;
  with ClickHouse enabled that count should read from the EventStore (small follow-up). Alerts/incidents (the
  system of record) are unaffected. **Deferred:** BigQuery cold tier + retention tiering (ADR-0002 §4), OpenSearch.

## Next gates (before starting)
- **Azure Sentinel / GCP SCC source mappers** (§6.5): same normalizer-registry pattern as CrowdStrike/Okta.
## Gate: SAML 2.0 SSO (SP-initiated) — §6.2 IAM-001 — reviewed Jul 2026

- **SRS:** IAM-001 (SSO via SAML/OIDC), IAM-008 (JIT provisioning), IAM-010 (log SSO logins). Same front-door
  seam as OIDC: SAML is an alternate path to the same Nirvet session JWT.
- **SECURITY DECISION (deliberate):** XML canonicalization + signature verification is where SAML goes fatally
  wrong (XML Signature Wrapping, canonicalization bugs). We do **NOT** hand-roll it. We use the vetted
  `russellhaering/gosaml2` (+ `goxmldsig`, + `mattermost/xml-roundtrip-validator` for XSW defense). This gate is
  still explicitly flagged for the **pre-go-live expert security review** — SAML is the highest-risk auth surface.
- **Flow (SP-initiated only; IdP-initiated is rejected):** `GET /auth/sso/saml/start?connection={id}` builds a
  SAML AuthnRequest, signs {connection_id, request_id} into RelayState (HMAC, 10-min TTL), and redirects to the
  IdP. The IdP POSTs a signed Response to `POST /auth/sso/saml/acs`.
- **Controls enforced at the ACS — ALL fail-closed:**
  1. **Signature required + valid** — assertion signed and verified against the connection's IdP certificate
     (`gosaml2.RetrieveAssertionInfo` errors on invalid/unsigned; `SkipSignatureValidation=false`).
  2. **Conditions time window** — NotBefore / NotOnOrAfter (`WarningInfo.InvalidTime` → reject).
  3. **Audience restriction** — assertion audience == our SP entityID (`WarningInfo.NotInAudience` → reject).
  4. **Recipient** — SubjectConfirmationData.Recipient == our ACS URL (gosaml2 checks against ACS).
  5. **Issuer** — assertion Issuer == connection IdP entityID.
  6. **InResponseTo binding** — the assertion's InResponseTo must equal the request_id we signed into RelayState
     (replay / CSRF / IdP-initiated-injection defense).
  7. **Email domain allowlist** — same as OIDC.
- **Data:** `saml_connections` (migration 0013, RLS+FORCE): idp_entity_id, idp_sso_url, idp_certificate (PEM,
  public — not a secret, no vault), sp_entity_id, acs_url, email_attribute (empty = NameID), default_role,
  email_domain. Unauthenticated ACS resolves the connection cross-tenant via SECURITY DEFINER
  `saml_get_connection(id)` (mirrors OIDC). JIT provisioning + session issue + audit reuse the shared completeSSO
  path (same as OIDC — one tested code path for the security-critical bit).
- **Deferred (logged):** signed AuthnRequests (SP private key in vault) and encrypted assertions — many IdPs don't
  require them; the critical direction (validating the IdP's signed response) is covered. SLO single-logout,
  SP-metadata publishing endpoint.
- **Pluggable detection DSLs** (§6.6, reviewer): **Sigma + CEL DONE**. Sigma (`detection.ImportSigma` → native
  Condition; POST /detections/import/sigma). CEL expression rules (`detection.CompileCEL`/`EvalCEL`; POST
  /detections/cel; migration 0014 `expression` column; compiled programs cached in the Engine and evaluated in the
  same loop as native/Sigma rules; expression must yield bool, validated at create time; fail-safe eval). The
  engine is NOT wired to one rule language. Remaining: **YARA deferred** (needs CGO/libyara — not pure-Go / breaks
  cloud-portability without a native dep); full Sigma condition grammar (or/not/`N of`/parentheses).
- **Redis-backed distributed rate limiting** (scaling): **DONE** — `ratelimit.Allower` interface + `RedisLimiter`
  (atomic token-bucket Lua), selected by `NIRVET_REDIS_ADDR`; verified two instances share one global bucket.
  Remaining: extend Redis to a general cache seam (session/hot-lookup) at the same scale point.
- **Schema v1.1 — promote hot fields to columns** (ADR-0006): `mitre`, `ip`, `hostname`, `vendor`, `product`
  from `data` to indexed columns when analytics query patterns justify the column cost.
- ~~**NATS queue backend**~~ DONE: `queue.NATSQueue` (JetStream durable stream + pull consumer, explicit ack,
  in-flight msg→ack bridge, NakWithDelay backoff, Term dead-letter after MaxAttempts), selected by
  `NIRVET_NATS_URL` (`queue.New`). Verified vs a real NATS: ack/no-redelivery, fail→redelivery-with-attempt,
  dead-letter after MaxAttempts, AND the full heartbeat runs on NATS (ADR-0003 swap proven). Postgres default
  unchanged. Remaining: GCP Pub/Sub adapter (same seam), per-connector DLQ stream + replay UI.
- **Dashboards** (UI): the API contracts already exist (designer supplies HTML).
