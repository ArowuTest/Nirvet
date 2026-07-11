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

## Case-management & investigation arc — §6.8/§6.9/§6.12/§6.13/§6.15 (Jul 2026)

Process note: these were built in a fast sequence and the gate entries are backfilled
here to restore the design-review record (gate-before-build resumes from now). All fit
the flow at *Incident → Timeline → (Investigation) → Reporting*, none are load-bearing
for the heartbeat (HEARTBEAT.md line 45): the spine stayed green on Postgres AND
ClickHouse after every commit. All map to real SRS §6 domains + MVP FRs (FR-002 asset,
FR-006 timeline, FR-007 evidence, FR-008 SLA).

- **Incident SLA timers + lifecycle (§6.8 case mgmt / FR-008).** Per-severity ack/resolve
  targets in code (`incident/sla.go`), due-times stamped at creation, `acknowledged_at`
  on first ownership, derived breach flags on read (migration 0020). Breach **alerting**:
  system sweeper (SECURITY DEFINER `incidents_sla_breaches`, mirrors the ingest reconciler)
  notifies + timelines once per breach (migration 0021). **Reporting posture** + **at-risk
  queue** (`GET /incidents/at-risk`). *Invariants:* tenant-scoped; notify best-effort;
  sweeper idempotent via notified markers. *Deferred:* SLA policy per-tenant config,
  business-hours calendars, breach dashboard widget.
- **Asset inventory + criticality escalation (§6.15 / FR-002).** Tenant asset registry
  (`internal/asset`, migration 0022, RLS+FORCE, upsert on ref). A promoted alert on a
  MORE-critical asset raises incident severity (never lowers) + tightens SLA + timelines
  it (`incident.WithAssetContext`). *Invariants:* tenant-scoped; escalation only fires on
  a matching more-critical asset, so the heartbeat (no registered asset) is unchanged.
  *Deferred:* vulnerability + exposure records, external asset-source sync, identity assets.
- **Entity graph (§6.9 — the section is literally "…and Entity Graph").** Read-only
  blast-radius view `GET /entities/graph?ref=` composing alerts+incidents+correlations+asset
  for a ref (`internal/entitygraph`, no table; added `alert.ListByRef`,
  `correlation.ListByEntity`). *Invariants:* pure composition over tenant-scoped reads —
  a graph can only hold the caller's own tenant data. *Deferred:* multi-hop relationship
  edges, graph visualisation payload, time-window scoping.
- **Evidence-pack export (§6.13 — "…and Evidence Packs" / FR-007).** `GET
  /incidents/{id}/evidence-pack` bundles case+timeline+alerts+events+assets+audit with a
  SHA-256 tamper-evident manifest (`internal/evidence`; added `eventstore.GetByIDs` on both
  backends, `audit.FindByActionContains`). *Invariants:* tenant-scoped composition;
  read-only; audit trail is the append-only log. *Deferred:* signed/PDF export, object-store
  archival of generated packs, chain-of-custody signature.
- **AI incident triage (§6.12).** `POST /incidents/{id}/triage` — assistive-only assessment
  composing incident+SLA+affected-assets+alerts+MITRE (`ai.WithIncidentContext`). *Invariants
  (doc 04 §3):* assistive-only (recommends via approval, never executes), tenant-scoped
  retrieval, evidence-linked (refs listed, observed vs inferred), full audit
  (`ai.triage_incident`), offline deterministic fallback when unkeyed. *Deferred:* RAG over
  case history, agentic multi-step investigation, eval harness.
- **Detection rule-pack (§6.6).** Broadened the global catalogue 5→11 rules across more
  ATT&CK tactics (execution/privesc/evasion/exfil/persistence/account-manipulation),
  migration 0023, inserted by the migrator (superuser, bypasses forced RLS). *Invariants:*
  global rules (tenant_id NULL) apply to all tenants; tenants still add their own; fits the
  Normalize→Detect stage. *Deferred:* aggregation/threshold rules (brute-force needs a
  windowed count the per-event condition model can't express), coverage heatmap.

## Gate: Round-2 security remediation (NFR-001/003/009; reviewer Jul 2026)

Round-2 external review (Claude Fable 5, read-only, to HEAD 86afcbd) found no new Critical
and confirmed tenant isolation airtight, but 5 Highs + Mediums concentrated in two root
causes. Owner directive: fix ALL now (no deferrals) for a clean pass. Fixed in the
reviewer's order, each gated + tested + green on both backends.

- **Root cause 1 — concurrency/idempotency/panic-safety under the multi-process topology
  (worker runs in-API *and* standalone).** House pattern adopted: **claim-then-act**
  (`UPDATE … WHERE <still-unclaimed> RETURNING`, act only if a row was claimed) for every
  idempotent action, and **recover-log-continue** around every long-lived loop (mirrors the
  per-job `processGuarded`). Covers H-C (correlation promotion), M-B (SLA notify), M-C
  (alert_count += 1 in SQL), H-E (poller/reconciler/SLA-sweeper panic guards).
- **Root cause 2 — BFLA on the flat `provider` tier.** Add a `senior` gate
  (platform_admin/soc_manager/analyst_t2/analyst_t3) for destructive/sensitive routes
  (connector create+delete, playbook run, incident close, alert promote, asset writes,
  threat-intel write, evidence-pack export); T1 keeps read + triage/assign/note. Audit
  before/after on asset criticality (M-D). Invariant: least privilege on top of the
  already-solid tenant isolation.
- **AI (H-A/M-F):** fence all event-derived text in an unguessable-sentinel data block
  (strip the sentinel from values, bound lengths) so injected instructions in customer
  telemetry can't steer the copilot; persist the AI output for audit (GuardFullAudit).
  Assistive-only + tenant-scoped retrieval already held.
- **Evidence integrity (H-B):** real Ed25519 signature over a digest that folds the
  envelope metadata (GeneratedAt/By/TenantID/SchemaVersion) + section checksums; ship
  signature + public key + timestamp + a verify path. Key from config now (vault/KMS-backed
  is the go-live step) — but the crypto is real, not a bare sha256.
- **Evidence tables (H-Res):** extend the C1 immutability from audit_log to the evidence
  tables — REVOKE DELETE on raw_events + events, REVOKE UPDATE on events, and a
  column-scoped trigger on raw_events allowing only `enqueued_at` to change (it legitimately
  needs that one UPDATE for the durability marker).
- **M-E/M-A/lows:** entity-graph batches incident fetch (`incident.GetByIDs`, no N+1);
  correlation requires corroboration (≥2 alerts) before single-event auto-promotion +
  per-tenant debounce; SSO re-validates role at login; gosec+govulncheck in CI; vault
  key-version byte.

## Gate: Vulnerability & exposure management — §6.15 slice 2 (Jul 2026)

- **SRS §6.15:** ASSET-004 (ingest vulnerabilities and map them to assets, criticality,
  exploitability, active-exploitation intel), ASSET-002 (assets carry vulnerabilities +
  related incidents), ASSET-006 (attack-surface / exposure view), ASSET-007 (correlate
  alerts with exposed vulns to increase priority/context). Builds directly on the asset
  registry (slice 1). Fits the flow at *Asset context → Incident/Investigation/Evidence*.
- **Design / contracts:** a `vulnerability` package (entity→repo→service→handler). A vuln
  maps to an asset by the same canonical `ref` the event pipeline + asset registry use
  (host:FIN-01 / user:jane@…), so no new join table — the ref is the key. Fields:
  cve, title, severity, cvss (numeric), exploited (KEV/active-exploitation flag), status
  (open|remediating|accepted|resolved), remediation_due. Register is an UPSERT on
  (tenant, ref, cve) so re-ingesting a scan updates in place (idempotent, mirrors asset
  upsert). Exposure summary aggregates open vulns (by severity, exploited-open, past-due).
- **Enrichment (ASSET-002/007):** the evidence pack and the AI triage context surface the
  affected assets' OPEN vulnerabilities, so an analyst/copilot sees exposure alongside the
  case — read-only composition (evidence already gathers the incident's asset refs).
- **Data:** `vulnerabilities` table (migration 0025, tenant RLS + FORCE, unique on
  (tenant, ref, cve), index on (tenant, status)). Postgres is SoR.
- **Invariants:** tenant isolation (RLS); WRITES gated to the `manager` tier (like asset
  criticality — vulns drive exposure/priority), reads to `provider`; UPSERT idempotent;
  severity/status validated to the canonical set; no destructive action.
- **Deferred (logged):** identity inventory (ASSET-003), automatic incident-priority
  increase from exposure (ASSET-007 full — kept as analyst/AI context this slice to avoid
  coupling the promotion path), exceptions/accepted-risk/compensating-controls +
  remediation target workflow (ASSET-008), asset confidence scoring (ASSET-009),
  data-quality customer tasks (ASSET-010), vuln-scanner *connector* ingest (ASSET-001 —
  register via API now; scanner pull is per-vendor auth work), attack-surface dashboards
  (ASSET-006 full — summary endpoint now, UI later).

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
- ~~**Schema v1.1 — promote hot fields to columns**~~ DONE (ADR-0006 v1.1): `mitre`/`vendor`/`product` promoted
  to indexed columns in both stores (PG migration 0015 + GIN; CH Array/LowCardinality); `EventStore.TopMITRE`
  ATT&CK analytics (PG unnest / CH ARRAY JOIN) surfaced in `reporting.top_mitre`; round-trip + TopMITRE verified
  on both backends. Remaining: `ip`/`hostname` columns when cross-entity analytics justify it.
- ~~**NATS queue backend**~~ DONE: `queue.NATSQueue` (JetStream durable stream + pull consumer, explicit ack,
  in-flight msg→ack bridge, NakWithDelay backoff, Term dead-letter after MaxAttempts), selected by
  `NIRVET_NATS_URL` (`queue.New`). Verified vs a real NATS: ack/no-redelivery, fail→redelivery-with-attempt,
  dead-letter after MaxAttempts, AND the full heartbeat runs on NATS (ADR-0003 swap proven). Postgres default
  unchanged. Remaining: GCP Pub/Sub adapter (same seam), per-connector DLQ stream + replay UI.
- **Dashboards** (UI): the API contracts already exist (designer supplies HTML).

## Gate — R3 reliability: SLA-notify durable outbox (SRS §6.8/§6.16)

- **SRS section / requirement**: §6.8 (SLA management, breach alerting) + §6.16 (notifications). Round-3 review §4/§6.5
  reliability residual: `SweepSLABreaches` claimed the breach marker BEFORE notifying and discarded the notifier
  error, so a transient delivery failure silently dropped the notification (exactly-once-or-**zero**). Owner
  directive: no deferrals — close for a clean pass.
- **Contract / interfaces**: `incident.Enqueuer` seam (`EnqueueTx(ctx, tx, tenantID, channel, subject, body)`) —
  keeps incident decoupled from notify, mirrors the existing `Notifier`/`Ticketer` seams. `notify.OutboxRepository`
  satisfies it. New `incident.Repository.ClaimBreachTx(...)` folds claim + timeline + enqueue into ONE tenant tx.
  `notify.Service.Drain`/`StartDispatcher` deliver + retry.
- **Invariants**: (1) exactly-once dedupe preserved — the conditional marker UPDATE still elects a single winner,
  and the outbox INSERT rides the SAME tx, so exactly one outbox row per breach kind even under the multi-process
  sweeper. (2) at-least-once delivery — a failed send leaves the row `pending` for retry; only after `maxAttempts`
  does it dead-letter to `failed` (observable), never silently lost. (3) tenant isolation — outbox has RLS
  ENABLE+FORCE + tenant_isolation; the cross-tenant dispatcher reads via a SECURITY DEFINER function
  `notification_outbox_pending` (mirrors `incidents_sla_breaches`, since `WithSystem` sees nothing through FORCEd
  RLS), and marks sent/failed under `WithTenant(row.tenant_id)`.
- **Data model**: migration `0027_notification_outbox.sql` — `notification_outbox` (id, tenant_id, channel,
  subject, body, status pending|sent|failed, attempts, last_error, created_at, sent_at); partial index on
  `(created_at) WHERE status='pending'`; SECURITY DEFINER drain fn granted to nirvet_app only.
- **End-to-end fit**: SLA sweeper → atomic claim+timeline+enqueue → dispatcher loop (inline worker, `safe.Do`
  guarded) → notify channel. Integration test drives a real breach and asserts an outbox row is enqueued then
  delivered (pending→sent).
- **Deferred**: routing the immediate create/assign notifications (best-effort, user present) through the outbox
  too — out of scope; only the unattended SLA-sweep drop was the finding. Real email/Teams/Slack channels are a
  tracked backlog task (§6.16 depth), not a code TODO (log channel ships as the seeded default).

## Gate — §6.1 Tenant profile & governance (config-first) — TEN-004/006/010

- **SRS section / requirement**: §6.1 — TEN-006 (org profile: escalation matrix/contacts, business hours,
  authority-to-act policy, legal/regulatory profile, critical-asset notes), TEN-004 (status lifecycle
  prospect→onboarding→active→suspended→churned→archived→legal_hold with guarded transitions), TEN-010 (append-only
  tenant change history for material settings). Owner rule: **no hardcoding — every policy is an admin-configurable
  DB record with a seeded default, never a code constant** ([[feedback-nirvet-no-hardcoding]]).
- **Contract / interfaces**: extend `internal/tenant`. New admin endpoints (platform_admin / customer_admin per
  scope): `GET/PUT /admin/tenants/{id}/profile`, `GET/PUT /admin/tenants/{id}/business-hours`,
  `GET/POST/DELETE /admin/tenants/{id}/escalation-contacts`, `GET/PUT /admin/tenants/{id}/authority-policies`,
  `POST /admin/tenants/{id}/status` (guarded transition), `GET /admin/tenants/{id}/history`. Downstream seams:
  §6.16 notification routing reads escalation contacts + business hours; §6.11 SOAR reads authority policies (both
  in later slices) — this slice OWNS the config, later slices CONSUME it.
- **Invariants**: (1) config-not-constants — SLA/authority/escalation/business-hours live in tables with a seeded
  default row per tenant at creation, overridable via API. (2) status transitions validated against a domain
  transition map (structural, not per-tenant tunable); illegal transitions rejected fail-closed. (3) TEN-010 —
  every material change appends to an **immutable** `tenant_change_history` (insert-only trigger, mirrors audit_log
  0017/0024). (4) authority-to-act default is **fail-closed** (approval required) so an unconfigured tenant can
  never auto-execute a high-impact action (NFR-009). (5) platform-level tables (WithSystem + RBAC), consistent with
  the tenants registry (not tenant-RLS, since a platform admin manages them across tenants).
- **Data model**: migrations `0028` — extend `tenants.status` allowed set; `tenant_profiles` (1:1, JSONB
  legal/regulatory + critical-asset notes + timezone); `tenant_business_hours` (weekly schedule + timezone);
  `escalation_contacts` (tenant_id, tier/min-severity, order_index, channel, address, active); `authority_policies`
  (tenant_id, action_type/impact_class, mode observe|approval|pre_authorized|emergency, approver_role,
  business_hours_only, seeded fail-closed default); `tenant_change_history` (append-only + insert-only trigger).
- **End-to-end fit**: tenant Create seeds default profile + business hours + fail-closed authority policy in the
  same tx (so no tenant is ever unconfigured). Heartbeat unaffected (additive). Later slices wire routing/authority.
- **Deferred (tracked tasks, not code TODOs)**: TEN-001 tenant hierarchy/MSSP downstream, TEN-003 onboarding
  templates, TEN-008 white-label branding, TEN-009 offboarding/export/cert-of-destruction — each its own §6.1/E15
  slice.

## Gate — §6.2 IAM slice A: service accounts + API keys — IAM-001/005/008

- **SRS section / requirement**: §6.2 — IAM-001 (service accounts + API keys as first-class principals),
  IAM-005 (least-privilege scopes + rotation for programmatic credentials), IAM-008 (lifecycle: create → rotate →
  revoke). Enables programmatic/connector/customer-API access (E09 US-035) without a human password.
- **Contract / interfaces**: extend `internal/iam`. A **service account** is a non-human, non-loginable principal
  (tenant + limited role). An **API key** authenticates as its service account. Key format `nvt_<prefix>_<secret>`;
  only `sha256(rawKey)` + the public `prefix` are stored — the secret is shown **once** at creation, never
  retrievable. New `auth.APIKeyResolver` interface (implemented by `iam.Service.ResolveAPIKey`) injected into a new
  `auth.AuthenticateWithAPIKeys(mgr, resolver)` middleware: `Authorization: Bearer nvt_…` (or `X-API-Key`) resolves
  to a `Principal`; anything else falls through to JWT. Endpoints (platform_admin / customer_admin own-tenant):
  `POST/GET /admin/service-accounts`, `POST/GET/DELETE /admin/service-accounts/{id}/keys`.
- **Invariants**: (1) secret never stored/logged — sha256 only; constant-time compare; high-entropy random secret
  (API keys are not passwords → sha256 is correct, not bcrypt). (2) tenant isolation — pre-auth lookup via a
  SECURITY DEFINER `auth_find_api_key_by_prefix` (mirrors `auth_find_user_by_email`); all management is tenant-RLS.
  (3) a resolved key Principal carries the service account's tenant + role, so **all downstream RBAC + RLS apply
  unchanged**. (4) revoked/expired keys fail closed; `last_used_at` updated best-effort. (5) least privilege — a
  service-account role cannot be `platform_admin` (guarded at create). (6) every create/rotate/revoke audited.
- **Data model**: migration `0029` — `service_accounts` (tenant-RLS) + `api_keys` (tenant-RLS: prefix UNIQUE,
  key_hash, role denormalized for fast auth, expires_at/last_used_at/revoked_at) + SECURITY DEFINER lookup fn.
- **End-to-end fit**: a connector/customer script calls `/ingest` with `Authorization: Bearer nvt_…`; the
  middleware resolves the service-account Principal; ingestion + RLS + audit proceed exactly as for a JWT user.
  Heartbeat unaffected (additive; JWT path untouched).
- **Deferred (tracked tasks)**: per-key **scopes** beyond role (fine-grained endpoint allowlist), automatic key
  **rotation reminders** (→ §6.18 ADMIN-009), user-owned personal API keys — next §6.2 slices. PAM/break-glass +
  session policy = §6.2 slice B; invitations + access reviews + ABAC = slice C.

## Gate — §6.2 IAM slice B1: session & access policy — IAM-007

- **SRS section / requirement**: §6.2 IAM-007 — configurable session timeout, IP restrictions, geo-anomaly
  logging. Directly removes a hardcoded constant (the global access-token TTL) per the no-hardcoding rule.
- **Contract / interfaces**: `session_policies` (1 row/tenant): access_ttl_seconds + ip_allowlist + geo_anomaly_
  logging — admin-configurable via `GET/PUT /admin/tenants/{id}/session-policy` (platform_admin any / customer_admin
  own). `auth.Manager.IssueWithTTL(p, ttl)`; `iam.Service.Login` issues with the tenant TTL. New
  `auth.SessionChecker` interface (impl by iam.Service.CheckSession) injected into `auth.AuthenticateFull` — the IP
  allow-list is enforced at ONE point on the already-resolved Principal (JWT or API key), not by touching token
  verification.
- **Invariants**: (1) TTL is a DB record (seeded default 900s, bounded 60–86400), never a code literal; login
  reads it (cached). (2) empty allow-list = no restriction (default), so existing behaviour is unchanged. (3)
  allow-list entries (IP or CIDR) validated at WRITE time — a bad entry is rejected, never silently ignored at
  enforce time. (4) an unparseable client IP fails **closed** against a non-empty allow-list. (5) denied access is
  audited when geo_anomaly_logging is on. (6) per-tenant policy cached 30s so authn stays a memory op on the happy
  path; cache invalidated on update. (7) fail-open only on a policy *load* error (availability > lockout).
- **Data model**: migration `0030` — session_policies (tenant-RLS FORCE), seeded for existing tenants; new tenants
  self-heal a default row on first access.
- **End-to-end fit**: login → token lifetime = tenant policy; every authed request → authn resolves Principal →
  CheckSession enforces the allow-list. Heartbeat unaffected (default empty allow-list; RemoteAddr always allowed).
- **Deferred (tracked tasks)**: idle/absolute session invalidation (needs server-side session store — JWT is
  stateless), device-trust indicators, true geo-IP lookup (no geo-IP DB dependency — current anomaly signal is
  "outside allow-list"). PAM elevation + break-glass = §6.2 slice B2 (next).

## Gate — §6.2 IAM slice B2: PAM elevation + break-glass — IAM-004/006

- **SRS section / requirement**: §6.2 IAM-004 (privileged access: justification, time-bounded elevation, approval
  for high-risk, logging), IAM-006 (break-glass: emergency reason capture, automatic alerting, post-use review).
- **Contract / interfaces**: `privileged_elevations` (tenant-RLS). PAM flow: request → four-eyes approve → active
  (until expires) → expired/revoked, or rejected. Break-glass: immediately active on creation + review_required +
  auto-alert. **Enforcement = AssumeRole/stateless**: an active elevation lets its owner mint a SHORT-LIVED
  elevated JWT (role = elevated role, TTL = min(remaining elevation window, tenant session TTL) — reuses §6.2-B1
  config, no new constant). Endpoints: `POST/GET /me/elevations`, `POST /me/elevations/{id}/token`,
  `POST /me/elevations/break-glass`; `POST /admin/elevations/{id}/approve|reject|review`, `GET /admin/elevations`.
- **Invariants**: (1) **four-eyes** — approver ≠ requester and approver ∈ {platform_admin, soc_manager}. (2)
  **no boundary break** — elevated role may never be platform_admin, and must be the SAME domain as the base role
  (provider↔provider, customer↔customer via auth.IsProviderRole) so a customer user can't cross into SOC. (3)
  time-bounded — requested duration bounded (5 min–8 h); token TTL never exceeds the elevation window; expiry is
  enforced at mint (an expired/revoked/rejected elevation mints nothing → base role returns). (4) **break-glass is
  loud** — immediate active, review_required=true, a high-signal audit entry AND an automatic alert (Alerter seam →
  notify). (5) post-use review closes review_required. (6) every state change audited; only the owner mints their
  own token; approve/review are senior-gated.
- **Data model**: migration `0031` — privileged_elevations (kind pam|break_glass; status requested|active|rejected|
  expired|revoked; approver/granted/expires/review fields). Tenant-RLS FORCE.
- **End-to-end fit**: analyst_t1 requests elevation to analyst_t3 for 1 h with justification → soc_manager approves
  → analyst mints a ≤1 h elevated token → acts as t3 → token expires → base role. Break-glass mirrors without the
  approval gate but alerts + flags for review. Heartbeat unaffected (additive).
- **Deferred (tracked tasks)**: instant cross-token revocation (JWT is stateless — bounded by short TTL, standard
  mitigation), scheduled auto-expiry sweep to flip status active→expired for reporting (derived at read-time now).
  Invitations + access reviews + ABAC = §6.2 slice C.

## Gate — §6.2 IAM slice C: invitation links + access-review report — IAM-001/008/009

- **SRS section / requirement**: §6.2 IAM-001 (temporary invitation links), IAM-008 (user lifecycle:
  invite → activate), IAM-009 (access-review reports for customer admins + compliance).
- **Contract / interfaces**: `user_invitations` (tenant-RLS). Admin creates an invite (email + role, bounded
  duration) → a one-time `nvi_…` token returned ONCE (only sha256 stored). The invitee self-serves at a PUBLIC
  `POST /auth/invitations/accept {token, password}` → creates + activates the user in the invite's tenant, marks
  the invite accepted. Admin endpoints under `/admin/tenants/{id}/invitations` (create/list/revoke, platform_admin
  any / customer_admin own). Access review: `GET /admin/tenants/{id}/access-review` composes users (role/status/
  MFA/last-login derived from audit_log) + service accounts + pending invitations + active elevations.
- **Invariants**: (1) token secret never stored/logged — sha256 only; shown once. (2) invited role is a known role,
  never platform_admin, and stays in the inviter's domain (a customer_admin can't invite a SOC role). (3) accept is
  one-time + expiry-bounded (accepted/expired invites fail closed) via a SECURITY DEFINER lookup (pre-auth, mirrors
  API-key/login). (4) accept creates the user atomically with marking the invite accepted; a duplicate email is a
  conflict. (5) every create/revoke/accept audited. (6) access review is read-only, tenant-scoped (RLS), and last-
  login is derived from the immutable audit trail (no new tracking column).
- **Data model**: migration `0032` — user_invitations (tenant-RLS FORCE) + SECURITY DEFINER
  auth_find_invitation_by_hash.
- **End-to-end fit**: admin invites analyst@x → sends the nvi_ link → analyst accepts with a password → active user
  → logs in (session policy TTL applies). Access-review surfaces the new user with MFA=false + first login. Additive;
  heartbeat unaffected.
- **Deferred (tracked tasks)**: ABAC attribute constraints (IAM-002) — cross-cutting enforcement, its own slice D;
  scheduled expiry sweep for invitations (derived at read time now); email auto-send of the invite (the token is
  returned to the admin; notify-channel delivery is §6.16).

## Phase 0 — Reconciliation (pay down debt from the full-repo audit)

A 5-agent depth audit (memory: project-nirvet-audit-reality) found the §6.1 config surfaces I shipped were written
but **consumed by nothing**. Phase 0 wires them to their enforcement points before building further breadth.

### A — SOAR consumes per-action authority_policies (task #77, done)
- **Problem**: two authority-to-act systems. SOAR `Run` read `tenants.authority_mode` (tenant-wide, enum
  `pre_authorised`); tenant `authority_policies` (per-action, enum `pre_authorized`) was written by the admin API
  but read only by a test. Divergent spelling would have mis-matched if ever wired.
- **Fix**: `soar.Authorizer` interface (`ResolveAuthorityMode` + `SetCatchAllAuthority`) implemented by
  tenant.Service; injected via `soar.Service.WithAuthorizer(tenantSvc)` in main + the integration harness. `Run`
  now resolves authority **per step.Action** (SOAR-003 granularity) from `authority_policies`. Enum unified on
  `pre_authorized`. `POST /soar/authority` repointed to upsert the `'*'` catch-all policy (legacy endpoint now
  drives the unified store). Legacy `tenants.authority_mode` retained only as a nil-authorizer fallback for
  unit tests.
- **Correctness**: the seeded `'*'` catch-all is now **`observe`** (the most fail-closed mode — nothing
  auto-executes — matching the platform's prior default), not `approval` (which permits low-risk auto-run).
  Migration 0033 normalizes the 250 already-seeded rows; SeedGovernance + ResolveAuthority fallbacks updated.
- **Invariant preserved**: heartbeat SOAR run still goes `pending_approval` (observe → all steps await). Verified.
- **Remaining**: SOAR still SIMULATES the action itself (real connector actions = §6.11 depth slice); this gate
  only fixes the authority *source of truth*.

---

## Gate — §6.11 real SOAR action execution, slice A (SOAR-001..009, §9.5 risk classes) — reviewed Jul 2026

**Why now.** Post-Phase-0 domain depth. The full-repo audit's biggest STUB: SOAR actions are 100%
`status="simulated"` — every step records "would invoke connector.action" and nothing runs. Phase 0-A fixed the
authority *source of truth* (per-action `authority_policies`); this slice turns simulation into **real dispatch**
and corrects the risk model to the SRS's own §9.5 class scale.

**SRS grounding.** SOAR-002 action catalog (notify, ticket, enrich, block IP/domain/hash, quarantine email,
disable user, revoke session, isolate endpoint, collect evidence, request customer action, generate report);
SOAR-003 authority per tenant/action/severity/hours/approval-group; SOAR-004 classify actions into the **five
§9.5 classes** (0 Informational, 1 Low, 2 Medium, 3 High, 4 Business-critical); SOAR-005 human approval for
high-impact unless contractually pre-authorised AND technically safe; **§9.5 Class 4 = incident-commander +
customer authority, NO full autonomous execution in MVP/V1**; SOAR-006 log every execution/input/output/
decision/approval/error; SOAR-007 dry-run/simulation mode; SOAR-009 failure handling + escalation to human.

**In scope (slice A).**
1. **§9.5 risk-class model.** Replace the ad-hoc 4-value `RiskClass` (low/medium/high/critical) with the five
   canonical classes `informational|low|medium|high|business_critical`. `Allowed(mode, class)` encodes the rule
   that **`business_critical` NEVER auto-executes** regardless of authority mode (fail-closed to approval) — the
   §9.5 no-autonomy guarantee, enforced in code not config.
2. **Action catalog (config, no-hardcoding).** New `soar_action_catalog` table: `action_key`, `title`,
   `risk_class`, `executor` (`connector|internal|manual`), `connector_key`, `enabled`; global (tenant_id NULL)
   or tenant-override, mirroring `playbooks` RLS. Seeded with the SOAR-002 catalog + their §9.5 classes. The
   step's risk class is now resolved from the catalog (admin-configurable) instead of hardcoded in each
   playbook step's JSON; a step whose action is absent from the catalog fails closed to `business_critical`
   (max approval) rather than defaulting permissive.
3. **Executor seam + registry.** `ActionExecutor` interface
   `Execute(ctx, tenantID, action string, params map[string]any) (Outcome, error)` where Outcome is
   `{Executed bool, Detail string}`. A registry resolves by the catalog `executor` kind.
   - **Grounding correction (from reading the code, not assumed):** `connector.Service` has **no** dispatch-by-key
     `Execute` and there is **no live per-tenant Actioner registry** — the audit's "connector actions unbuilt" is
     real. So real containment (isolate/disable/revoke/block/quarantine) is NOT runnable in this slice; forcing it
     would be dishonest. Those dispatch to the **simulating executor**: records `simulated (no live connector for
     <key>)` naming the connector.action it would invoke, preserving the full authority+approval+audit path. The
     live Actioner registry (vault creds + msgraph/Defender action impls) is its own later slice — the seam is ready.
   - **One genuinely-real executor ships now:** `internal:notify` (customer notification / `request_customer_action`)
     backed by the durable notification **outbox** — non-destructive, already-built, safe. Proves the seam does real
     work end-to-end (playbook step → outbox row → dispatcher delivers). Needs a small non-tx
     `OutboxRepository.Enqueue` (wraps `EnqueueTx` in its own tenant tx) + a narrow `soar.Notifier` interface.
   - `manual` actions record `awaiting_customer`. **Deferred to slice B:** other internal executors
     (ticketing/evidence/reporting) and the live connector Actioner registry.
4. **Execution + audit.** `Run`/`Approve` dispatch each permitted step through the executor and record the real
   outcome (`executed|simulated|failed|awaiting_approval|awaiting_customer|skipped`) with detail; **every step
   dispatch writes an audit row** (SOAR-006: action, class, authority mode, decision, outcome, error). A step
   error is caught per-step (SOAR-009): the step is `failed`, the run continues to the next step, and the run
   ends `completed` if all non-failed or `failed` if any hard-failed — never a panic.

**Out of scope (later slices).** Full SOAR-001 branch/wait/rollback playbook DSL (today steps are a linear
array); ticketing/evidence/reporting internal executors (slice B); the live EDR/IdP containment Actioner registry
(needs vault creds + action impls — the seam is ready); business-continuity auto-throttle (SOAR-010); customer
approval-request UX (§6.16/designer).

**Entities / schema / enums.**
- `soar_action_catalog` (RLS FORCE, global-or-tenant like playbooks). `risk_class` CHECK on the five §9.5 values;
  `executor` CHECK `(connector|internal|manual)`. `UNIQUE (COALESCE(tenant_id,'0..0'), action_key)` so a tenant
  can override a global action's class/executor. Index `(tenant_id, action_key)` for the per-step lookup.
- Go `RiskClass` constants unified on the five values; `soar_test.go` matrix updated. Existing `playbook_runs`
  step-result JSON gains no schema change (statuses are values in `steps_result`); the `StepResult.Status` set
  widens (documented). Existing seeded playbook's inline `risk` values are migrated to catalog classes
  (`revoke_sessions`/`reset_password` → `high`, `enrich`/`inspect_mailbox` → `low`).
- **Idempotency**: catalog seed `ON CONFLICT DO NOTHING`; admin upsert `ON CONFLICT DO UPDATE`. Executor dispatch
  is at-least-once within a run but a run is created once (existing behavior); connector-side idempotency is the
  connector's concern (documented).

**Correctness invariants (must hold).**
- Heartbeat SOAR run stays `pending_approval` under the seeded `observe` authority (all steps await). ✓ target.
- `business_critical` step never auto-runs even under `emergency` authority (new unit test).
- Absent-from-catalog action → treated as `business_critical` (fail-closed), never permissive.
- Four-eyes (requester ≠ approver) unchanged; per-step audit added.
- No cross-tenant catalog read (RLS FORCE; global rows readable, tenant rows isolated).

**Verify.** Unit: risk-class matrix incl. Class-4 no-autonomy + absent-action fail-closed + executor dispatch
(fake executor: executed/failed) . Integration: playbook run against a catalog action with a fake connector
executor asserts `executed` outcome + audit rows; run under `observe` still `pending_approval`. Migration applies;
build/vet/gofmt/heartbeat green.

---

## Gate — §6.8 incident lifecycle depth, slice A (CASE-002/004/009) — reviewed Jul 2026

**Why now.** Post-Round-4, first domain-depth slice. The audit flagged the incident model as thin, and
grounding confirms it: the stage enum is only `new|triage|investigating|contained|closed` (0002 CHECK),
`contained` is defined but NO code path reaches it (dead), `Close` just sets stage+note with no closure
criteria, and the timeline has no internal-vs-customer visibility. This is core SOC workflow and unblocks
§6.13 reporting/PIR.

**SRS grounding.** CASE-002 incident lifecycle stages (opened→assigned→investigating→waiting_customer→
containment_pending→contained→eradication→recovery→monitoring→closed→post_incident_review); CASE-003
every case has disposition/root-cause/etc.; CASE-004 internal-only vs customer-visible notes; CASE-009
closure criteria (disposition, root cause, impact, actions taken, lessons learned, customer ack). NIST
800-61r3 Respond/Recover informs the eradication/recovery/monitoring/PIR structure.

**In scope (slice A).**
1. **Stage state machine (CASE-002).** Widen the stage vocabulary to the full CASE-002 chain (add
   `assigned, waiting_customer, containment_pending, eradication, recovery, monitoring,
   post_incident_review`); migration widens the CHECK. An allowed-transitions map (structural domain
   vocabulary, mirroring `tenant.statusTransitions`), fail-closed on an illegal transition. New
   `Transition(ctx, p, id, to, note)` service method + `POST /incidents/{id}/transition`; every
   transition appends a timeline `status` entry and an audit row **atomically** (one tenant tx). Any
   active stage may → `closed` (a false-positive can close early), so existing flows keep working; the
   `contained` dead stage becomes reachable (investigating/containment_pending → contained →
   eradication → …). Assign continues to move an unowned case toward `investigating`.
2. **Closure criteria (CASE-009).** New nullable incident columns (disposition, root_cause, impact,
   actions_taken, lessons_learned, customer_ack). Transitioning to `closed` REQUIRES a ClosureInput with
   disposition + root_cause + impact + actions_taken (non-empty); disposition is validated against the
   canonical SOC vocabulary (true_positive, false_positive, benign_true_positive, duplicate,
   not_applicable — a structural enum like severity/stage, not a per-tenant tunable). `Close` becomes
   Close(ClosureInput); the columns are persisted with the close in one tx; reopening (closed→
   investigating) is allowed and audited.
3. **Note visibility (CASE-004).** Add `visibility` (`internal|customer`, default `internal`) to
   incident_timeline; migration widens the table + a CHECK. AddNote takes a visibility; system/status
   entries default `internal`. A `CustomerTimeline` service method + `GET /incidents/{id}/customer-timeline`
   returns only customer-visible entries, so a customer portal can never see analyst-only notes (enforced
   at query time, not just UI).

**Out of scope (slice B / later).** CASE-005 tasks (incident_tasks sub-entity — its own slice); CASE-007
category templates + per-tenant disposition config (config tables; category stays a free string for now);
CASE-006 parent-child / major-incident aggregation; INV-010 war-room; SLA re-computation on severity
change mid-lifecycle (already handled at create).

**Entities / schema / enums.**
- `incidents`: +disposition, +root_cause, +impact, +actions_taken, +lessons_learned (text, default ''),
  +customer_ack (bool default false). Stage CHECK widened (new migration DROP+ADD constraint, mirroring
  0002/0028's status-widen pattern). No new index needed (stage filtering is over the tenant-scoped
  list; existing incidents_tenant_created covers ordering).
- `incident_timeline`: +visibility text default 'internal' CHECK (internal|customer).
- Go: Stage constants added; `stageTransitions` map; `Disposition` validated set; `ClosureInput`;
  `Incident` struct gains the closure fields; `TimelineEntry` gains Visibility.
- **Idempotency**: a transition to the SAME stage is a no-op (returns current, like tenant.SetStatus);
  closing an already-closed incident is idempotent. **Audit-in-tx** (house rule): stage change + timeline
  + audit commit together via CreateWithSeed-style tx (extend repo with a Transition tx method).

**Correctness invariants.**
- Heartbeat stays green: its Assign→Close flow still works (investigating→closed is allowed; the heartbeat
  Close call is updated to supply the now-required closure fields).
- Illegal transition (e.g. closed→eradication) is rejected fail-closed.
- Closing without the required closure fields is rejected (CASE-009), never a silent close.
- A customer-timeline query NEVER returns an `internal` entry (tested with a mixed timeline).
- RLS unchanged (all incident tables already tenant-RLS FORCE); no cross-tenant read.

**Verify.** Unit: stage-transition legality (allowed/illegal/idempotent), disposition validation, closure
required-fields. Integration: full lifecycle walk (triage→investigating→containment_pending→contained→
eradication→recovery→monitoring→closed with closure) + illegal-transition rejection + customer-timeline
filter (internal note hidden). Heartbeat green; migrations apply; build/vet/gofmt clean.

---

## Gate — §6.16 real notification channels, slice A (COMM-001/010) + closes R-5 — reviewed Jul 2026

**Why now.** Post-§6.8. A lot of already-built capability dead-ends at the `log` channel: the SLA-breach
sweeper, the Phase-0 escalation-matrix routing, and the §6.11 SOAR notify executor all enqueue durable
outbox rows — but `notify.NewService` registers only `log` (with an explicit `// TODO` for real
channels), so an escalation contact with `channel=webhook/teams/slack` produces an outbox row that
**fails delivery** ("unknown channel") and dead-letters. This slice makes those deliver for real, and
is the correct home to close Round-4 **R-5** (the send-time SSRF re-check I deferred).

**SRS grounding.** COMM-001 (email/Teams/Slack/webhook/in-platform channels), COMM-002 (route per
escalation matrix/severity — already built, Phase 0-B), COMM-010 (don't send sensitive incident detail
to insecure channels). NFR-SEC / OWASP SSRF for the outbound HTTP.

**In scope (slice A).**
1. **Real webhook / Teams / Slack channels.** Implement `notify.Channel` for `webhook`, `teams`,
   `slack`: HTTP POST the message to the recipient URL (Slack/Teams incoming-webhooks accept a JSON
   body; webhook posts `{subject, body, to}`; Slack posts `{text}`; Teams a minimal card). Registered
   in `NewService`, so the outbox dispatcher delivers `channel=webhook/teams/slack` rows for real.
2. **`internal/platform/netsafe` (new) — closes R-5.** Move `IsInternalHost` (+ the numeric-IP guard)
   out of `tenant` into a shared leaf package, and add a hardened `*http.Client` whose
   `net.Dialer.Control` hook rejects a connection whose RESOLVED IP is internal/loopback/link-local/
   metadata — the real **send-time, post-DNS** SSRF defence (defeats DNS-rebinding, which a write-time
   string check cannot). The webhook channels dial only through this client. `tenant`'s write-time
   `validateEscalationAddress` reuses `netsafe.IsInternalHost` (single definition).
3. **Remove the `// TODO`** in `notify.NewService` (owner no-TODO rule) — replaced by the registered
   channels + a documented note on what's deferred.

**Out of scope (slice B).** Email (SMTP) + SMS channels — they need per-tenant sender config (SMTP
host/creds via the KMS vault, SMS gateway key), a config table + admin API; until then an `email`/`sms`
escalation contact still dead-letters (honest — no sender configured). COMM-006 throttle/digest,
COMM-007 templates, COMM-009 secure expiring links, COMM-008 localisation.

**Interfaces / portability.** No new external SDK — stdlib `net/http` + `net`. The webhook channels
take an injected `*http.Client` (the netsafe client) so they're testable against an `httptest` server
and unchanged for GCP. The `Channel` seam is unchanged (Key/Send), so this is purely additive
registration.

**Invariants.** Send-time SSRF guard on EVERY outbound POST (no channel bypasses the safe client);
https-only (rejected at the write-time validator + the client refuses cleartext internal); no secret
material in the posted body; the dispatcher stays panic-guarded + at-least-once (unchanged); tenant
isolation unaffected (recipient URL comes from the tenant's own escalation contact, RLS-scoped).

**Verify.** Unit: `netsafe.IsInternalHost` (incl. numeric/hex forms), the safe dialer refuses an
internal-IP connection, webhook channel POSTs the expected body to an `httptest` server + is refused
for an internal URL. Integration: an escalation contact with `channel=webhook` pointed at a test server
delivers via the outbox dispatcher (row → sent). Heartbeat green; build/vet/gofmt clean.

---

## Gate — §6.10 threat intel → real STIX 2.1 store, slice A (TI-001..004) — reviewed Jul 2026

**Why now.** Biggest remaining STUB. Grounding confirms threatintel is a `{type,value,tlp,score,tags}`
watchlist (`threat_indicators`) + a substring enricher — the memory's own test "watchlist ≠ STIX" is
literally true: no SDO/SRO objects, no malware/campaign/actor/attack-pattern, no sighting/confidence/
decay/kill-chain. This slice makes it a real STIX 2.1 object store feeding enrichment + correlation.

**SRS grounding.** TI-001 ingest via STIX/TAXII/MISP-like/CSV/API/manual; TI-002 objects = indicators,
malware, campaigns, threat-actors, attack-patterns, tools, vulnerabilities, reports, sightings; TI-003
confidence/source-reliability/first-seen/last-seen/TLP/expiry/kill-chain/ATT&CK/sharing-scope; TI-004
enrich alerts+incidents and show why a match matters. Built to the OASIS STIX 2.1 model captured in
[[reference-appsec-standards-2025]] (SDO/SRO/SCO, common props, TLP marking).

**In scope (slice A).**
1. **STIX object store.** `stix_objects` (id `type--uuid`, type, spec_version '2.1', tenant_id NULL=global
   or own, created/modified, confidence 0-100, revoked, valid_from/until, pattern + pattern_type
   (stix|sigma|snort|yara), labels[], external_references jsonb (ATT&CK/CVE), tlp (from
   object_marking_refs), value (extracted observable for matching), raw jsonb (the full object)). RLS
   FORCE, global-or-tenant like detection_rules (per-command policies, so a tenant can't rehome a global
   object). Supports the real SDO/SCO set; `stix_sightings` (SRO) is a lightweight companion for TI "seen"
   counts.
2. **Ingest.** AddObject (validated: type in the known set, spec_version, id shape) + ImportBundle (a STIX
   bundle's `objects[]`), UPSERTING by `id` only when the incoming `modified` is newer (STIX versioning),
   honoring `revoked`. Manual analyst submission (TI-001) is the same AddObject path.
3. **Typed enrichment (TI-004).** Extend the enricher to ALSO match event entities against STIX INDICATOR
   observable values (the `value` column, extracted from a simple `[type:value = 'x']` pattern or an SCO),
   returning confidence + TLP + labels + kill-chain — richer than the substring watchlist, and it records
   *why* (the matched object id + labels). Existing `threat_indicators` watchlist stays as the quick
   manual-IOC path (TI-001) and is matched alongside — additive, no enricher regression.

**Out of scope (later slices).** TAXII 2.1 inbound POLLER (slice B — needs a live TAXII server; the
enrichment/store it feeds is built here so wiring it is additive); exposing Nirvet as a TAXII SERVER
(slice C, sharing); the full STIX PATTERNING grammar (slice A extracts a single observable value from the
common `[type:value = 'x']` form and matches that — complex boolean patterns are deferred, logged not
skipped); relationship graph traversal beyond sightings; decay scoring curves.

**Entities / schema / enums.** `stix_objects` PK on `id` (text); index `(tenant_id, type)` + a partial
index on `value` where value<>'' for enrichment lookups; per-command RLS (SELECT global+own, INSERT/
UPDATE/DELETE own-only). `stix_type` CHECK constrained to the known SDO/SCO set. TLP CHECK
red|amber+strict|amber|green|clear (TLP 2.0). Go: `StixObject`, `validStixType`, `Sighting`.

**Invariants.** Tenant isolation (global feeds readable, tenant objects isolated, no cross-tenant); the
enricher stays cached (per-tenant TTL, no per-event DB hit); ingest is idempotent (upsert by id+modified);
audit on manual add/import; TLP respected in output (a match carries its TLP so downstream honors sharing).

**Verify.** Unit: STIX object validation (type/id/spec_version), upsert-only-on-newer-modified, observable
extraction from a simple pattern, TLP validation. Integration: import a small STIX bundle (indicator +
malware + relationship) → stored; an event entity matching a STIX indicator enriches with confidence+TLP+
labels; global object visible to a tenant, tenant object isolated. Heartbeat green; build/vet/gofmt clean.

---

## Gate — §6.14 compliance → config-driven control framework + real assessment, slice A (COMP-001/002/004) — reviewed Jul 2026

**Why now.** §6.14 is a 52-line hardcoded static struct: 6 NIST-CSF functions with fixed status strings,
identical for every tenant, no DB, no tenant scope, no evidence linkage. A textbook no-hardcoding
violation (owner rule). This slice replaces it with a config-driven framework/control model + a real
per-tenant assessment derived from live platform state, with manual override.

**SRS grounding.** COMP-001 map detections/incidents/evidence/actions → framework controls; COMP-002
framework templates (NIST CSF 2.0, CIS v8.1, ISO 27001) as config not code; COMP-004 evidence/assessment
with owners + status. Frameworks per [[reference-appsec-standards-2025]] (NIST CSF 2.0 functions
GV/ID/PR/DE/RS/RC).

**Config boundary (the key rule).** The framework catalogue, its controls, and each control's *mapping*
to a platform signal are DB CONFIG (seeded global defaults, tenant-overridable). The *signal resolvers*
(the code that inspects real state — is immutable audit present, is RLS enforced, does the tenant have
detection coverage, incident MTTR) are CODE, because they must query live state. So: WHAT proves a control
= config; HOW a proof is measured = code. A control with no auto-signal defaults to `gap` until manually
assessed — we never fabricate "met".

**In scope (slice A).**
1. `compliance_frameworks` (global seed: nist_csf_2_0, cis_v8_1, iso_27001_2022; + tenant-custom) — RLS
   global+own per-command.
2. `compliance_controls` (global seed: NIST CSF 2.0 functions + core categories, control_ref + parent_ref
   hierarchy, weight, `auto_signal` key + `auto_config` jsonb = the seeded mapping) — RLS global+own.
3. `compliance_control_status` (per-tenant: status met|partial|gap|not_applicable, score, source auto|
   manual, note, evidence_incident_id/evidence_ref, assessed_by/at; UNIQUE(tenant,framework,control_ref))
   — tenant RLS. Holds manual overrides + cached auto assessments.
4. Signal registry (code): resolver per `auto_signal` (capability-present, detection-coverage,
   incident-process, audit-immutability, …) → (status, note). Honest: unbuilt domains resolve to gap.
5. Service: ListFrameworks, ListControls(framework), Assess(tenant, framework) (manual status wins, else
   resolve auto_signal; roll up weighted score + per-function summary), SetControlStatus (manual override,
   audited). Coverage endpoint re-backed by the real assessment (no route break).
6. Handler + routes: GET /compliance/frameworks, GET /compliance/controls, GET /compliance/coverage
   (real, tenant-scoped), PUT /compliance/controls/{ref}/status (senior, audited).

**Out of scope (later).** COMP-003 country/sovereign packs (Ghana) as config; COMP-008 audit-readiness
dashboards; COMP-009 retention/deletion by jurisdiction; evidence-request workflow with owners/due dates;
scheduled attestation; auto-mapping detections→controls by ATT&CK. Full CIS/ISO control bodies seeded
minimally (framework rows + a few controls) — full catalogues are a data-load task, not logic.

**Entities/enums/RLS.** frameworks + controls: nullable tenant_id (NULL=global), per-command policies
(global+own read, own-only write) — same guardrail as detection_rules/stix_objects so a tenant can't
re-home/delete a global template. status: tenant-scoped single-policy RLS. Enums: status
met|partial|gap|not_applicable, source auto|manual. Indexes: controls(framework_key, tenant_id),
status UNIQUE(tenant, framework_key, control_ref).

**Invariants.** Tenant isolation (global templates readable, tenant status private); no fabricated "met"
(missing signal → gap); manual override always wins over auto and is audited with actor; assessment is a
read that never writes through a GET (RLS aborted-tx rule); weighted rollup deterministic.

**Verify.** Unit: signal resolver honesty (unbuilt → gap), manual-over-auto precedence, weighted rollup.
Integration: seeded frameworks/controls visible to a tenant (global), Assess produces per-control status
from live state, manual override persists + wins + is audited, tenant B can't see tenant A's status,
global template not writable by a tenant. Heartbeat green; build/vet/gofmt clean.

---

## Gate — §6.8 case management → FULL, slice B (CASE-005/006/007) — reviewed Jul 2026

**Why now.** Drive §6.8 from PARTIAL to FULL (owner directive: partials→full). Slice A shipped the CASE-002
stage machine + CASE-009 closure + CASE-004 note visibility + SLA. Slice B adds the case-STRUCTURE core:
tasks, parent/child (major incidents), and config-driven categories. Slice C (next) finishes with CASE-008
attachments/chain-of-custody + CASE-010 KB links → then §6.8 is FULL.

**SRS grounding.** CASE-005 investigation tasks/checklist with owner + status; CASE-006 parent-child /
major-incident linking (an umbrella case aggregating related incidents); CASE-007 category templates as
CONFIG (not the current free-text `category` string) with a seeded default set + tenant-custom.

**In scope (slice B).**
1. **CASE-005 tasks.** `incident_tasks` (incident_id, tenant_id, title, description, assignee_id, status
   open|in_progress|done|cancelled, due_at, created_by, created_at, completed_at). Create/list/update-
   status; assignee validated in-tenant (reuse Assignees resolver); status change + completion recorded on
   the timeline. Claim-then-act CAS on status so concurrent updates don't clobber (guarded UPDATE WHERE
   status=$expected optional; simple UPDATE with audit is fine for tasks).
2. **CASE-006 parent/child + major.** ALTER incidents ADD parent_id (self-FK, nullable) + is_major bool.
   Link a child to a parent (same tenant; cycle-guard: a parent cannot be set to itself or to any of its
   own descendants); unlink; list children; mark/unmark major. Setting a parent records both sides on the
   timeline. A child's severity/SLA is unchanged (aggregation is a view concern).
3. **CASE-007 category templates.** `incident_categories` (global seed + tenant-custom, key, name,
   default_severity, description, enabled) — per-command RLS (global-or-own read, own-only write) like
   detection_rules/stix. Seeded defaults (malware, phishing, unauthorized_access, data_exfiltration, dos,
   policy_violation, recon, misconfiguration, insider_threat, uncategorised). SetCategory validates the
   incident's category against the configured set (no more free-text); category list endpoint.

**Out of scope (slice C / later).** CASE-008 attachments/chain-of-custody, CASE-010 KB links (next slice);
category→default-playbook auto-suggest; SLA-per-category; child roll-up dashboards (UI).

**Entities/enums/RLS.** incident_tasks + incident_categories tenant-scoped; categories nullable tenant_id
(NULL=global) per-command policies. Enums: task status open|in_progress|done|cancelled. incidents gains
parent_id (self-ref, ON DELETE SET NULL) + is_major. Indexes: incident_tasks(tenant_id, incident_id),
incident_categories(tenant_id, key) unique, incidents(parent_id). Guard: cross-tenant assignee rejected;
parent cycle rejected; category must exist.

**Invariants.** Tenant isolation on all new tables; task assignee in-tenant only; parent link same-tenant +
acyclic; category validated against config; every mutation audited (mutation middleware) + material ones on
the timeline; GET handlers never write (RLS aborted-tx rule).

**Verify.** Unit: cycle-guard (self + descendant), task status vocab, category validation. Integration:
create task + update status (timeline entry written), link parent + reject cycle + reject cross-tenant,
category set validated against seeded config + rejected when unknown, tenant isolation on tasks/categories.
Heartbeat green; build/vet/gofmt clean.

---

## Gate — §6.7 correlation → FULL — reviewed Jul 2026

Drive §6.7 PARTIAL→FULL. Already done: clustering, config window/threshold/min-alerts, corroboration floor,
exactly-once auto-promotion, concurrency-safe update. Two slices close the rest.

**Slice B (COR-006 explainability + COR-009 analyst override).** Persist max_confidence on the cluster;
add an Explain(cluster) that returns the per-factor risk contribution breakdown (severity base, volume,
technique breadth, confidence) so an analyst sees WHY a cluster scored as it did (COR-006). Add an
analyst override of severity/risk with a required reason, audited, overridden_by/at recorded (COR-009);
List/Get order and display by the EFFECTIVE severity/risk (override wins). Overrides may only be set by
provider roles; the reason is mandatory. Migration adds columns; scanOne/SELECTs updated uniformly.

**Slice C (COR-007 suppression windows + COR-008 storm mode + COR-010 over-correlation).** A
correlation_suppressions config table (match by entity or technique, time-bounded maintenance window):
a matching cluster is still formed but auto-promotion is suppressed while active, flagged suppressed with
the reason (COR-007). Storm mode: a per-tenant storm threshold (clusters opened per hour) in
correlation_policies; when exceeded, Correlate stops opening N incidents and the coverage endpoint reports
storm state so the UI can switch to incident-command aggregation (COR-008). An over-correlation metric
endpoint (alerts-per-cluster ratio, largest cluster, single-alert-cluster %) to detect over-grouping
(COR-010). All thresholds config, not constants.

**Invariants.** Overrides tighten/annotate only via audited endpoint; suppression never drops alerts (only
gates promotion); storm threshold config-floored; tenant isolation; GET never writes. Verify: unit
(explain factor math, effective severity/risk precedence, suppression active-window logic, storm trip) +
integration (override persists + wins + audited, suppression blocks promotion, storm flags, isolation).

---

## Gate — §6.16 notification → FULL — reviewed Jul 2026

Drive §6.16 PARTIAL→FULL. Done: webhook/Teams/Slack channels (SSRF-safe), escalation routing, durable
outbox + dispatcher, in-platform log channel. Two slices close the rest.

**Slice B (COMM-001 email/SMS via per-tenant sender config).** The headline gap ("needs vault sender
config"). A notification_senders table holds per-tenant, per-channel sender config: email = SMTP
host/port/from/username + vault-encrypted password (crypto.SecretCipher, per-tenant); sms = provider
POST URL + vault-encrypted API key. Real emailChannel (net/smtp, STARTTLS) and smsChannel (generic JSON
POST {to,message} + Bearer, via an outbound client) look up the sender by the message's tenant, decrypt
the secret at send time, and deliver — so an email/sms outbox row is delivered, not dead-lettered, once a
tenant configures a sender. Message gains TenantID, threaded through the outbox Drain. Unconfigured →
graceful dead-letter (existing retry/cap). Sender secrets are write-only (never returned).

**Slice C (COMM-006/007/008/009).** notification_templates (tenant+global, per-channel, per-locale,
{{var}} render) so producers reference a template key + vars (COMM-007) with locale selection (COMM-008);
throttle/digest (per-tenant window that de-dupes or batches repeated notifications, COMM-006); secure
expiring links (signed, TTL-bounded token over a resource ref, verified on access, COMM-009).

**Invariants.** Sender secrets vault-encrypted per tenant + never serialized; tenant isolation on senders/
templates; SMS/email delivery honors the existing at-least-once outbox + dead-letter cap; SMTP uses TLS;
config-first (no hardcoded provider). Verify: unit (sender secret round-trip via cipher, template render,
throttle window) + integration (configure sender → email/sms channel resolves + attempts delivery,
tenant isolation on senders, unconfigured dead-letters).

---

## Gate — §6.6 detection slice C → FULL — reviewed Jul 2026

Drive §6.6 PARTIAL→FULL. Slice B delivered the §9.4 lifecycle (stage machine, version/snapshot/rollback,
owner + source_dependencies metadata, emergency deploy, create-as-draft; engine fires pilot/production/
tuned only). Slice C closes the three remaining reqs — the detection-as-code quality controls.

**DET-005 test-against-sample.** SRS §9.4 says every detection MUST carry test cases. A
detection_test_cases table (tenant-owned) holds named sample events (partial NormalizedEvent as jsonb) with
an expected_match bool. AddTestCase / ListTestCases / DeleteTestCase manage them; RunTests(rule) builds a
NormalizedEvent from each sample and evaluates the rule body (Condition.Matches or EvalCEL — the SAME
primitives the engine uses, so a test proves real firing) and reports pass/fail per case. Ad-hoc RunSamples
(inline samples, no persistence) for authoring. **Teeth:** promotion to production (Transition to
StageProduction, non-emergency) is GATED — the rule must have ≥1 test case and ALL must pass
(require_tests_for_production config, default true). Emergency deploy (senior-gated) still bypasses.

**DET-007 FP-disposition feedback loop.** An analyst dispositions an alert (POST /alerts/{id}/disposition
{disposition, reason}); disposition ∈ true_positive|false_positive|benign|duplicate. This closes the alert
AND, when the alert carries a detection_id, appends an append-only detection_feedback row attributed to that
rule (via a narrow FeedbackSink interface — alert stays decoupled from detection, mirroring Correlator/
Alerter). Per-rule stats (RuleFeedbackStats: counts by disposition, fp_rate over total dispositioned) feed
tuning; a tenant tuning view lists rules whose fp_rate ≥ configured threshold once the sample ≥ min_feedback
_sample (so a 1-of-1 FP doesn't cry wolf). fp_rate + tuning_recommended surfaced, not auto-acted (assistive).

**DET-009 data-source-dependency coverage warnings.** For each ACTIVE rule with non-empty
source_dependencies, compare against the tenant's actually-ingested sources (DISTINCT raw_events.source over
a configurable coverage_window_days). A dependency neither seen in that window is a coverage gap — the rule
is live but its data source isn't arriving, so it can never fire. GET /detections/coverage returns per-rule
missing deps + the observed source set. Grounded in real ingested data, not just declared connectors.

**Config (no hardcoding).** detection_settings (tenant PK): fp_rate_threshold (0.30), min_feedback_sample
(20), coverage_window_days (7), require_tests_for_production (true). Lazy default — GetSettings returns the
seeded defaults when no row exists; SetSettings upserts (audited). Every threshold/window/toggle is a DB
record, not a constant.

**Invariants.** Test cases + feedback tenant-owned, RLS own-only; feedback append-only (no update/delete
grant); promotion gate fail-closed (no tests → not promotable unless emergency); coverage/stats endpoints
are GET, never write; disposition sink best-effort must not block the alert close from committing its own
state; tenant isolation on all four tables; audited mutations (settings, disposition). Verify: unit (test
runner pass/fail incl. CEL, fp_rate math, coverage set-diff, promotion-gate logic) + integration (add test
case → run → promote blocked until pass, disposition writes feedback + closes alert + stats reflect it,
coverage flags a missing dep, settings round-trip, tenant isolation + negative cross-tenant). Heartbeat green.

---

## Gate — §6.10 threat intel slice B — reviewed Jul 2026

Drive §6.10 PARTIAL→ (toward FULL). Slice A delivered the real STIX 2.1 store (typed id, versioning,
validity/revocation, TLP, kill-chain, per-command RLS), AddStix/ImportBundle, a STIX-typed enricher, and
worker-written match provenance. Slice A matched a SINGLE observable per indicator (first `= 'x'` literal),
had no freshness decay, and did not use sightings. Slice B makes STIX matching real, time-aware and
corroboration-aware. (TAXII poller/server + relationship-graph traversal → slice C.)

**Full multi-value pattern extraction (matching quality).** `extractObservables(pattern) []string` pulls
EVERY quoted comparison literal from a STIX pattern (all AND/OR branches), deduped — so a compound
indicator `[ipv4-addr:value='1.2.3.4' OR ipv4-addr:value='5.6.7.8']` matches an event carrying EITHER. The
`value` column still stores the first literal (display/back-compat); the enricher expands each indicator
into one matchable value→object entry per extracted literal at cache-load, so a hit on any branch yields
one deduped Match. Fixes the "compound patterns silently keep only the first observable" slice-A gap.

**Config-driven decay (freshness).** A per-tenant `threat_intel_settings` (config-first, lazy default):
`decay_half_life_days` (30), `min_effective_confidence` (0), `sighting_boost_cap` (20). At enrich time a
STIX match's confidence decays by 0.5^(age_days/half_life) where age = now − (valid_from or created); a
match whose EFFECTIVE confidence falls below `min_effective_confidence` is dropped (a stale IOC stops
firing) — so intel ages out on a curve, not a cliff, and the cliff (valid_until/revoked) still applies in
SQL. Watchlist indicators are the manual/authoritative path and are NOT decayed.

**Sightings → confidence (corroboration).** `sighting` SROs already persist in stix_objects; the enricher
sums each sighting's `count` (default 1) by `sighting_of_ref` at cache-load and adds a bounded boost
(min(sum, sighting_boost_cap)) to the referenced object's effective confidence — a corroborated IOC scores
higher (TI-004 feeds COR-002). Boost applied AFTER decay, then clamped to 100.

**Invariants.** Settings tenant-scoped RLS, lazy default (no row ⇒ defaults); decay/boost are pure functions
of stored data (deterministic, testable); effective confidence clamped [0,100]; revoked/expired still
filtered in SQL (defense in depth); watchlist unaffected; enrichment stays per-tenant cached (no per-event
DB). Verify: unit (multi-value extraction incl. AND/OR + dedup, decay math at 0/1/2 half-lives, floor drop,
sighting boost + cap + post-decay order) + integration (compound indicator matches either branch; a
past-half-life IOC below floor stops matching; a sighting raises effective confidence; settings round-trip;
tenant isolation). Heartbeat green.

---

## Structural guardrails — the un-bypassable "control everywhere except one sibling" class-fix (Jul 2026)

The recurring R4→R6 theme was one class: a control applied everywhere except one sibling (SMS→ticketing→
OIDC missed SafeClient; stix_objects missed a tenant-composite key; the detect-slice-C M2 config guardrail).
Rather than keep patching instances, three mechanical guards now fail CI on the whole class:

1. **Outbound HTTP must use netsafe.SafeClient** — `scripts/check-outbound-http.sh` (a CI step after
   build/vet) rejects any plain `http.Client{}` / `http.DefaultClient` / `http.Get|Post|...` outside
   `netsafe/`, tests, or an inline `// netsafe-exempt: <reason>` waiver. Closes the SSRF-sibling class.
2. **Tenant-composite PK/UNIQUE** — `internal/schemacheck` (a DB-invariant test in the `go test ./...` CI
   step) fails if any PK/UNIQUE on a table with a `tenant_id` column omits tenant_id, unless the key is
   globally unique by construction (contains a uuid column, or is a single-column surrogate with a default
   / identity) or is an explicitly-waived global pre-tenant lookup (api-key prefix, invite token hash).
   Closes the cross-tenant-collision class (R5-H3); on introduction it surfaced + retired the dead
   stix_sightings stub.
3. **enum↔CHECK consistency** — same package: each registered column's CHECK value set must equal its Go
   source-of-truth const set (detection stage/disposition, roles, tenant tiers, severity, SOAR risk class),
   so a Go enum and its DB CHECK can't drift. Adding a new enum'd column means registering it — that is the
   enforcement.

Net: a new plain outbound client, a new tenant-natural-key without tenant_id, or an enum/CHECK drift can no
longer merge silently — each is a red build, not a future review finding.

---

## Gate — §6.5 normalization slice A — reviewed Jul 2026

Drive §6.5 PARTIAL→depth. Done: canonical OCSF-inspired event, 8 vendor mappers in a source-normalizer
registry, enrichment (asset/TI), entity-resolution basics. Slice A makes the normalization MEASURABLE and
VERSIONED so a vendor schema change is visible instead of silent — the NORM-003/006/009 cluster. (Alias/
entity resolution NORM-005 and redaction/masking NORM-010 → slice B.)

**Parser versioning (NORM-003).** Each mapper carries a name + integer version (registry gains a parallel
metadata map, set at registration). Normalize stamps `data.parser` + `data.parser_version` into every event
so which mapper (and version) produced a canonical event is queryable and a version bump is observable.

**Normalization confidence (NORM-006).** A pure completeness scorer: how many canonical fields the mapper
populated (class_name, severity≠informational-default, actor_ref|target_ref, action, outcome, mitre),
weighted → 0-100, stamped as `data.normalization_confidence`. Distinct from the vendor's detection
Confidence. A low score means the payload barely mapped — a coverage/drift signal, not a detection weight.

**Data-quality + drift (NORM-003/009).** A per-(tenant, source, day) `normalization_quality` aggregate
(events, sum_confidence, last parser+version) maintained by the worker via an in-memory accumulator flushed
once per RunOnce batch (not per event — no hot-row contention / write amplification). GET
/normalization/quality reports per source: events, avg_confidence, active parser+version, and a `drift` flag
when avg_confidence over the window falls below the tenant's configured `min_confidence` — i.e. a vendor
whose payloads stopped populating canonical fields lights up. Config = normalization_settings (min_confidence,
window_days), tenant-scoped RLS, lazy default. PUT /normalization/settings (senior).

**Invariants.** Scorer + drift flag are pure functions (deterministic, unit-tested); confidence is metadata,
never overwrites detection Confidence or gates firing; quality aggregation is best-effort and off the ingest
hot path (worker-batched); settings/quality tenant-scoped; reads are GET. Verify: unit (confidence scorer
across full/partial/empty mappings, drift-flag threshold) + integration (worker normalizes events → flush →
quality reflects avg confidence + parser version, a low-confidence source is flagged drift, settings
round-trip, tenant isolation). Heartbeat green.

---

## Gate — §6.11 SOAR slice B: REAL containment executors — DESIGN REVIEW (pre-code) — Jul 2026

**Status: DESIGN ONLY. No code until the appointed reviewer signs off.** This is the single
highest-consequence change on the roadmap: the platform goes from "can do nothing destructive"
(notify-only, everything else a truthful simulation) to "can really isolate a host / disable an
account / block an IP." Every SOAR control shipped R2–R4 (authority-to-act, four-eyes, claim-then-act,
per-action + credential-decrypt audit-in-tx, panic recovery, override-may-only-raise-risk) was rated
"latent, safe *because only notify executes*." Slice B removes that safety net, so the design is
reviewed on paper first and the implementation gets a dedicated adversarial review round, not a
general sweep.

### The core design tension (the decision to review)

Slice A's `ActionExecutor.Execute(ctx, tx, …)` runs INSIDE the run's DB transaction so effect + audit
+ run-state change commit together (R4-M2: effect and audit can never diverge). That is correct and
must stay for INTERNAL executors (notify/ticket/evidence/report — their "effect" is a DB row). It is
**wrong for a real connector call**: an external HTTP effect to Defender/Entra/PAN (a) cannot be rolled
back if the tx later aborts, and (b) must never run with a DB tx open across the network (long tx,
locks held, pool starvation). So slice B splits the seam:

- **Internal executors** — unchanged: in-tx `ActionExecutor`.
- **Connector (destructive) executors** — a **durable two-phase** model, NOT in-tx:
  - **Phase A (tx1, atomic):** re-verify gate (authority + approval + kill-switch + enablement + rate
    budget), then CLAIM the step — write an `soar_action_execution` row `status=executing` with a unique
    idempotency key `(run_id, step_index)`, decrement the rate-limit budget, and write the INTENT audit
    (who/what/target/params-hash) + the credential-decrypt audit. Commit. Nothing external yet.
  - **Phase B (no tx):** perform the connector call via the Actioner (vault-decrypted creds, netsafe
    SafeClient — already CI-enforced). Bounded timeout < any reclaim window.
  - **Phase C (tx2, atomic):** record the OUTCOME (`executed`/`failed` + connector response ref) + the
    result audit, and advance run state. Commit.
  - **Crash-safety / idempotency:** a reaper re-drives `status=executing` rows past a visibility timeout;
    re-drive is safe because (i) the claim's idempotency key prevents a second claim, and (ii) the
    Actioner call is required to be idempotent or pre-checked (e.g. "isolate" is a no-op if already
    isolated). An action whose idempotency cannot be guaranteed is Class-gated to require human confirm.

### Safety envelope (all REQUIRED before any external call)

1. **Authority + four-eyes chain, re-checked in Phase A** (never trust the Phase-1 read): §9.5 —
   Class0 none; Class1 policy-optional; Class2 analyst approval unless pre-authorized; Class3
   (disable user / revoke sessions / isolate endpoint / block domain|IP) customer/senior approval
   unless an explicit pre-authorized-containment policy; **Class4 (network-wide block, mass quarantine,
   cloud lockdown) — incident-commander + customer authority, NO full autonomous execution (stays
   manual/awaiting_customer in V1)**. Four-eyes: approver ≠ requester (already enforced); real executor
   path must re-assert it at claim time.
2. **Kill-switch + per-tenant enablement + global dry-run** (config, admin-gated, tighten-only):
   - a GLOBAL platform-admin kill-switch that forces every connector executor to simulate;
   - a PER-TENANT `destructive_actions_enabled` flag (default OFF — a tenant opts in);
   - a `dry_run` mode (global and per-tenant) where the Actioner logs the exact call it WOULD make and
     returns simulated, for validation before go-live. Precedence: kill-switch > tenant-disabled >
     dry-run > live. Any of them ⇒ no external effect.
3. **Rate-limit / circuit-breaker on destructive actions** (config, per-tenant, per-risk-class):
   a budget (e.g. N Class3 actions / hour) decremented in Phase A; exhausted ⇒ the step is withheld
   (awaiting_customer) not executed — bounds the blast radius of a compromised or looping playbook
   (mass-isolation). A global circuit-breaker trips connector execution off if the platform-wide
   destructive rate spikes.
4. **Audit-in-tx, three records:** intent (Phase A), credential-decrypt (Phase A, when vault creds are
   unsealed), outcome (Phase C) — all in the immutable audit_log, each in its phase's tx so a partial
   crash still leaves the intent + who authorized it.
5. **Reversibility (SOAR-010 business-continuity):** every containment action declares its inverse
   (isolate↔release, disable↔enable, block↔unblock); the execution row records enough (connector, target,
   prior state where derivable) to reverse; a one-click reverse run is itself a gated SOAR action. No
   containment without a defined undo.

### Connector Actioner registry

`Actioner` (parallel to the read-side connector Puller): `(connector_key, action) -> func(ctx, creds,
target, params) (ref, error)`, vault-decrypted creds + SafeClient. Real actions map to vendor APIs —
Defender isolate/release machine, Entra/Okta disable-user + revoke-sessions, PAN/edl block-IP/domain.
Unregistered (connector_key, action) ⇒ truthful simulation (unchanged). Registration, not an engine
change. Each Actioner is idempotent or pre-checks current state.

### Invariants / out-of-scope

Class4 never auto-executes in V1. RLS tenant-scoped on the new execution + config tables. Overrides
may only tighten (raise risk / narrow authority) — never loosen. Kill-switch/enablement/dry-run/rate
config is admin-gated and tighten-only. Connector clients are netsafe-only (CI-enforced). Full
branch/wait DSL (SOAR-001) stays deferred; slice B is linear playbooks with real leaf executors.

### Verify plan (and the adversarial review this feature gets)

Unit: gate precedence (kill-switch>disabled>dry-run>live), rate-budget decrement + withhold, idempotency
key rejects double-claim, reverse-action mapping. Integration: a Class3 action with a mock Actioner runs
the two-phase path (claim→call→outcome), crash between Phase B and C re-drives without double-effect,
dry-run makes no call, tenant-disabled/kill-switch force simulate, rate-limit withholds past budget,
four-eyes re-checked at claim, tenant isolation, Class4 stays manual. Adversarial round to probe:
double-execute under retry, gate bypass via Phase-1/Phase-A TOCTOU, rate-limit evasion, credential
exposure in audit/logs, a compromised-playbook mass-containment scenario.

### Reviewer checklist (please confirm before I write code)
- [ ] Two-phase durable model (vs in-tx) is the right call for external effects, and the crash/idempotency story holds.
- [ ] Safety envelope is complete (nothing missing that would let a destructive action fire un-authorized, un-audited, un-bounded, or un-reversible).
- [ ] Class3 vs Class4 handling matches §9.5 (Class4 = no autonomous in V1).
- [ ] Config surfaces (kill-switch, per-tenant enablement, dry-run, rate-limit) are the right set and are tighten-only.
- [ ] Anything you want added to the adversarial round.

### Revision 2 — reviewer conditions folded in (pre-code, 2026-07)

Conditional sign-off received; the four must-adds + cheap should-adds below are now part of the design.
Theme (again): turn each documented requirement into a STRUCTURAL guarantee the type system / control
flow enforces, not reviewer vigilance.

**MUST-1 — Idempotency + reversibility are declared at Actioner registration and structurally enforced.**
The whole crash-safety argument rests on "the Actioner is idempotent or pre-checks." So registration
carries that as data, not prose: `Actioner{ Fn, Idempotent bool, PreCheck bool, Inverse string,
Reversible bool }`. The engine **refuses to AUTO-run** any connector action that is not
(`Idempotent || PreCheck`) — it is forced to `awaiting_customer` (human-confirm) instead. The reaper's
"re-drive is safe" invariant is therefore guaranteed by the registration contract: an un-idempotent,
un-prechecked action can never reach the two-phase auto path, so re-drive can never double-fire it.
Likewise a Class3+ action with `Reversible=false` and no declared `Inverse` cannot be registered as
auto-runnable. First-add-of-`block_ip`-without-a-precheck is caught at wiring, not in prod.

**MUST-2 — Run-level supervisor model (the run is no longer one atomic tx).** With a connector step going
two-phase, a run mixing an internal step and a connector step CANNOT commit atomically — it is
legitimately partially-committed with one step parked `executing`. So: the **step is the durable unit**;
the **run is a supervisor** that resumes from the last non-terminal step. `Approve`/`Run` no longer wrap
the whole run in one tx — each step commits its own state; a crash mid-run re-drives the outstanding step
then continues. **Steps execute strictly in order; the supervisor must not advance past an `executing`
step** — real containment ordering depends on it ("collect evidence" must complete before "isolate
endpoint", or isolating first destroys volatile evidence). A `soar_run` gains a `current_step` cursor;
the supervisor is itself reaper-resumable.

**MUST-3 — Reverse honors OBSERVED prior state captured in Phase B, not the nominal inverse.** "disable
user" whose blind inverse is "enable user" is a landmine: if the account was ALREADY disabled by the
customer for an unrelated reason, SOAR's disable is a no-op, and a later auto-reverse would wrongly
RE-ENABLE an account the customer wanted off. So Phase B's pre-check records the observed prior state
(`prior_state` jsonb: `was_isolated`/`was_disabled`/…) on the execution row, and **reverse only undoes
actions that ACTUALLY changed state** (skip where prior_state already matched the target). This binds
MUST-1's pre-check to reversibility: capture prior state or you may not auto-reverse.

**MUST-4 — Every gate DENIAL is audited + surfaced (SOAR-006), not a silent status.** The envelope
audited actions that EXECUTE; a SOC's forensic question is often "why did containment NOT fire?" Every
withhold — rate-budget exhausted, kill-switch, tenant-disabled, dry-run, four-eyes-fail, not-idempotent-
so-forced-manual — writes an audit row with the reason AND emits a visible signal (notification /
run-timeline entry), never just a status flip. A silently-withheld isolation is the worst SOC failure
(R5 silent-gap theme applied to containment).

**Should-adds (folded in):**
- **Phase B re-reads the kill-switch immediately before the connector call** — the one legitimate
  second read: an emergency "STOP, we're mass-isolating prod" must abort steps already CLAIMED but not
  yet executed, not only steps that haven't claimed. Emergency-stop semantics operators expect.
- **Re-drive resumes at Phase B, never re-runs Phase A** — the claim (rate-budget decrement + intent
  audit + cred-decrypt audit) happens exactly once; a crash-loop cannot double-decrement the budget or
  double-write intent. The execution row's `status=executing` marks "Phase A done, resume at B."
- **Class4 in V1 = a human work-item with NO connector execution at all** (the safe reading): it creates
  an `awaiting_customer` step + incident-commander task and STOPS; it never enters the two-phase path in
  V1. (When V2 enables it, it will run the same gated two-phase path behind IC+customer authority.)
- **Dry-run runs the FULL gate** (authority + four-eyes + idempotency-declaration checks all evaluated)
  but does not decrement real budget and marks every audit row `dry_run=true`, so a tenant can validate
  the exact decision path before going live.
- **Target identity legible in the intent audit:** secret params are hashed, but the human-meaningful
  target ("isolated host X", "disabled user Y") is readable — the audit must answer "what did we
  contain?" without decrypting anything.

**Adversarial round — expanded (must reproduce + prove closed):** reverse-wrong-way (re-enable an
account the customer independently disabled → MUST-3); reaper double-fire on a non-idempotent action
(registration refuses auto-run → MUST-1); kill-switch flipped between claim and call (Phase-B re-read
aborts → should-add); withheld containment not audited/surfaced (→ MUST-4); crash mid-run leaves the run
partially committed and resumes at the outstanding step in order (→ MUST-2); supervisor races ahead past
an `executing` step / evidence-after-isolate ordering (→ MUST-2); budget double-decrement on crash-loop
(re-drive resumes at Phase B → should-add); plus the original five (double-execute under retry, Phase-1/
Phase-A TOCTOU, rate-limit evasion, credential exposure in audit/logs, compromised-playbook mass-
containment).

**Revised reviewer checklist:**
- [x] Two-phase durable model — approved.
- [x] MUST-1 idempotency/reversibility structural at registration + engine refuses auto-run otherwise.
- [x] MUST-2 run supervisor / step-is-durable-unit / strict in-order / no advance past `executing`.
- [x] MUST-3 reverse honors observed prior state captured in Phase B.
- [x] MUST-4 every denial audited + surfaced.
- [x] Should-adds folded (Phase-B kill-switch re-read, re-drive resumes at B, Class4 no-exec V1, dry-run full gate, legible target in audit).
- [x] Reviewer's five-minute confirming pass → fully green → proceed to code + dedicated adversarial round. **LANDED HEAD 763b218; dormant.**

---

## Gate — §6.11 SOAR slice C: FIRST REAL vendor Actioner (Defender isolate/release) — DESIGN REVIEW (pre-code) — Jul 2026

**One-line.** Register the first REAL vendor Actioner into the already-built, dormant slice-B two-phase
supervisor: Microsoft Defender for Endpoint **isolate ⇄ release**. This is where SOAR stops truthful-
simulating and performs a real, reversible, destructive containment for one action pair — behind
`soar_settings.destructive_enabled` (default OFF). Triggers the reviewer's dedicated adversarial round #34.

**SRS grounding.** SOAR-002 catalog **isolate endpoint** (+ its reverse); SOAR-004 §9.5 class = **3 High**
(→ customer/senior approval, never silent); SOAR-005 human approval for high-impact unless contractually
pre-authorised AND technically safe; SOAR-006 audit every execution/input/output/decision/error;
SOAR-007 dry-run; SOAR-009 failure→escalation. Reuses the slice-B engine verbatim (MUST-1..4 already proven);
this slice supplies the vendor implementation behind the seam, it does NOT change the engine.

**In scope (slice C).**
1. **Real `CredDecryptor`** (was wired `nil` in api+worker). A `connector`-vault-backed impl:
   `ConnectorCreds(ctx, tenantID, connectorKey) ([]byte, error)` → resolves the tenant's Defender connector
   config and vault-decrypts its secret (client_id / client_secret / azure_tenant). This is the Phase-B seam
   the supervisor already calls; slice B decrypts+audits the intent, this makes the bytes real.
2. **Defender action client** (`internal/connector`, alongside `graphClient`): client-credentials auth with
   an **injectable base URL + scope** (portability/testability), and three calls — resolve host→machine id,
   read current isolation state (PreCheck), `POST /machines/{id}/isolate` (IsolationType Full) + `/unisolate`.
   Note the **different API surface**: MDE machine actions live on `api.securitycenter.microsoft.com` with
   scope `Machine.Isolate`, NOT the `graph.microsoft.com/.default` alert-pull scope — the tenant's Defender
   app-registration must grant Machine.Isolate. All dials via `netsafe.SafeClient`.
3. **Two `Actioner`s** registered into the previously-empty registry at api+worker startup:
   `defender:isolate` (`Idempotent=false, PreCheck=true, Reversible=true, Inverse="release"`) and
   `defender:release`. PreCheck is mandatory + load-bearing (C-3): it reads the **machineAction history** and
   treats a matching Isolate in `Pending|InProgress|Succeeded` as already-requested (async-safe, not terminal-state).
   Once registered,
   `supervisedNeeded` matches a playbook isolate step → the real two-phase path engages **iff** a matching
   Defender connector is configured AND that tenant's `destructive_enabled=true`.
4. **Catalog seed** (migration): `isolate_endpoint`/`release_endpoint` → `executor=connector, connector_key=defender,
   risk_class=high`. Idempotent seed (`ON CONFLICT DO NOTHING`), global row (tenant-overridable, tighten-only).
5. **Dry-run** does the PreCheck read but NOT the POST → records `simulated` with the would-be action.
   (Kill-switch, per-class rate cap, four-eyes, Class-3 approval-gate are all enforced by the slice-B engine — unchanged.)

**Out of scope (later slices / follow-ons).**
- Other vendor actions (Entra ID disable-user / revoke-session, Palo Alto block-IP) — identical Actioner
  pattern, each its own slice.
- **Async completion reconciler.** MDE isolate is async (machineAction Pending→Succeeded). V1: `executed` =
  "action accepted by MDE" with the machineAction id as `connector_ref`; a background poller that confirms
  terminal machineAction status → marks the step confirmed/failed is a **named follow-on**, not slice C.
- Incident-asset → machine-id auto-resolution. Slice C takes an explicit target (machine id, or hostname the
  Fn resolves via `/machines?$filter=computerDnsName eq '…'`). Richer asset-graph mapping later.
- Live smoke against a real Defender tenant (needs owner app-registration creds w/ Machine.Isolate).

**Key design decisions — reviewer, please confirm these four (the honest wrinkles):**
- **D-1 API surface + scope (CONFIRMED, + host allowlist).** Use the MDE API (`api.securitycenter.microsoft.com`,
  `Machine.Isolate`), base URL + scope injectable so tests hit a mock and prod is config-driven. Needs a broader
  app-registration than the alert-pull connector (owner-side config). **Reviewer add:** validate the config-driven
  base URL against an **allowlist of expected Microsoft hosts** (e.g. `*.securitycenter.microsoft.com` /
  `*.security.microsoft.com`) — defense-in-depth *over* `netsafe`, so a misconfigured/hostile base URL can't
  redirect a real containment call to an attacker endpoint even if it resolves to a public IP.
- **D-2 PreCheck keys off machineAction HISTORY, not terminal state (CONFIRMED, sharpened).** MDE exposes no
  clean isolation boolean, AND isolation is async — so PreCheck must NOT wait for a terminal "isolated" state.
  It reads the machine's **machineAction history** and treats a matching **Isolate** action in
  **`Pending | InProgress | Succeeded`** as "already requested → `prior_state.changed=false`, skip the POST."
  This is what makes crash-while-`Pending` safe (see C-3): the terminal state may not be reached yet, but the
  in-flight action is visible. **Indeterminate** (history unreadable) → still issue isolate (safe to re-request;
  MDE dedups) and record `changed=unknown`; reverse treats `unknown` as "do NOT auto-undo" (fail-safe — never
  auto-release on a guess).
- **D-3 "submitted = executed" for V1 (CONFIRMED, + `confirmed=false`).** Given async, `executed` means
  accepted-by-MDE (machineAction id captured), not confirmed-isolated; reverse is symmetric. The execution row
  records **`confirmed=false`** for submitted-not-yet-confirmed so a later completion reconciler (named follow-on)
  can flip it. Reviewer confirmed acceptable for V1.
- **D-4 target contract (CONFIRMED).** Step `target` carries the machine id (or a hostname the Fn resolves). No
  upstream incident→machine mapping in this slice.

**Correctness invariants (must hold — round #34).**
- **C-1** `destructive_enabled=false` → step `withheld` + audited, **zero** isolate POSTs (mock call-count 0).
- **C-2** `dry_run=true` → PreCheck read only, **zero** isolate POSTs, recorded `simulated`.
- **C-3 (THE ONE — crash-while-`Pending`):** crash **after** the external POST but **before** Phase-C commit →
  reaper resumes at Phase B. Because isolate is async, the machine may still be **`Pending`** (not terminally
  isolated) at resume — so PreCheck keying off terminal state would double-POST. PreCheck instead reads the
  **machineAction history** and sees the in-flight **Isolate action in `Pending`** → treats it as already-requested
  → **does NOT POST again** → step recorded `executed` exactly once (mock isolate call-count stays 1). This is why
  MUST-1 forbids a non-idempotent action without PreCheck; PreCheck (history-based) is the resume-idempotency guard
  for a real async destructive call. **Round #34 headline probe: crash-while-`Pending` must not double-isolate.**
- **C-4** reverse honors `prior_state.changed`: `true` → POST unisolate; `false`/`unknown` → skip (no-op), audited.
- **C-5** Class-3 under `observe`/`approval` authority → `awaiting_approval`, no auto-exec; four-eyes on approve.
- **C-6** MDE API error → step `failed` (not stuck `executing`), reason recorded; run continues/ends per SOAR-009.
- **C-7** kill-switch flipped mid-flight (between Phase A claim and Phase B) → abort before POST, `withheld`.
- **C-8** per-class rate cap on Class-3 → `withheld` after N real executions in the window.
- Build/vet/gofmt/RequireDSN-CI/heartbeat green; slice-A + slice-B suites stay green at every chunk (build-time bar).

**Chunking (test-first, keep A+B suites green each step).**
- **C-1** real `CredDecryptor` (connector-vault-backed) + wire into api+worker (registry still empty → no behavior
  change yet; slice-A/B suites unaffected).
- **C-2** Defender action client (auth + machine-lookup + isolate/unisolate, injectable base URL+scope) + unit
  tests vs a mock MDE server.
- **C-3** the two `Actioner`s (MUST-1 props + Fn + PreCheck prior_state) + register in api+worker + catalog seed migration.
- **C-4** adversarial round #34 (C-1..C-8) green against the mock MDE API.

**Landing.** All external calls mocked for build + round #34 (no creds needed). `destructive_enabled` stays OFF
by default; turning it on per-tenant is an explicit admin action. Live smoke waits on owner-provided Defender
sandbox creds. Ping reviewer for their dedicated round #34 on landing.

**Gate checklist.**
- [x] Reviewer confirms D-1..D-4 — with edits folded: D-1 base-URL Microsoft-host allowlist; D-2 PreCheck keys off
      machineAction history (`Pending|InProgress|Succeeded`), not terminal state; D-3 record `confirmed=false` for
      submitted-not-yet-confirmed; D-4 as written.
- [x] Reviewer confirms C-3 is the load-bearing invariant + must-test — **sharpened to crash-while-`Pending`**
      (round #34 headline probe: a resume while the isolate is still `Pending` must not double-POST).
- [x] Reviewer endorses Defender-isolate-first (risk-ordered: fully reversible, single-machine blast radius,
      pre-checkable) over leading with Entra disable-user; OFF-by-default + explicit per-tenant enable = correct posture.
- [x] **Owner's final nod**: Defender-isolate-first + OFF-by-default — CONFIRMED.
- [x] Built C-1..C-4 test-first (A+B suites green each chunk). **LANDED** — C-1 CredDecryptor (3ef2bc4),
      C-2 MDE client + D-1 allowlist (c026c8c), C-3 Actioners + register + catalog seed mig 0064 (b2ef28f),
      C-4 round #34 (8c3eb9d). All 7 round-#34 scenarios green incl. the C-3 crash-while-`Pending` no-double-POST
      headline; full repo suite green on a fresh migrated DB. Reviewer to run their independent round #34 pass.

---

## Gate — Admin-Configurable AI Providers (§1454/§1903/§3842, doc 04 §31) — DESIGN REVIEW (pre-code) — Jul 2026

**Source spec:** `outputs/NIRVET_IMPL_SPEC_AI_PROVIDER_AND_HOST_TELEMETRY.md` Part 1 (lead reviewer, Fable 5).
**Status:** near-free design inclusion done NOW (config shape decided below); BUILD after SOAR slice C. This is
SRS CONFORMANCE DEBT, not a new feature — the SRS already mandates admin-configurable AI providers + per-tenant
routing restrictions, and it is unbuilt.

**Why (grounding, verified in code).** `ai/gateway.go:29,:71` hardwires `https://api.anthropic.com`; only
`apiKey`+`model` are configurable; there is NO `ai_provider` config surface. Gap vs §1454 (global config shall
include AI providers), §1903 (model/provider config + data-routing restrictions **by tenant**), §3842 (private-
model strategy per country/regulated type), and the owner no-hardcoding rule. Already-good baseline (keep it):
AI is assistive-only (`GuardNoAutoContain`) and optional with an offline fallback (`Available()==apiKey!=""` →
`fallbackSummary`), so "AI off = zero LLM egress, SOC still works" is already true. This item adds the "AI on, but
only on a provider/endpoint the tenant is ALLOWED to use" path.

**In scope.** Config-first `ai_provider` record (global default + per-tenant override); a `Provider` interface with
≥3 kinds (`anthropic`, `openai_compatible`, `disabled`); per-tenant provider pinning + `tenant_ai_policy` restriction
(residency, §1903); a **platform-admin allowlist** of permitted model endpoints; vault-stored keys + decrypt-audit;
audit of provider_kind+endpoint+model+output. **Out (this slice):** streaming; per-task-type multi-model routing;
fine-tuning; a gateway proxy service. One resolved provider per (tenant, call) → call → audit.

**Config shape (DECIDED NOW — mirrors `soar_action_catalog`, FORCE RLS).** `ai_provider`
(tenant_id NULL=global; provider_kind CHECK; base_url NULL unless openai_compatible; model; api_key_ref = vault ref;
UNIQUE one row per tenant + one global). `ai_provider_allowed_endpoint` (platform-admin trust list: scheme+host[:port],
UNIQUE(scheme,host); http allowed only for an explicitly-approved on-prem endpoint). `tenant_ai_policy`
(tenant_id PK, allowed_kinds text[] default all — a sovereign tenant → e.g. `{openai_compatible,disabled}`). Seed one
global `anthropic` row = current default → existing tenants unchanged.

**THE load-bearing guard (get this exactly right): ALLOWLIST, do NOT block-internal.** A self-hosted sovereign model
is LEGITIMATELY on an internal/private address (on-prem GPU box) — so do **NOT** wrap the LLM endpoint in
`netsafe.SafeClient`/`IsInternalHost` the way OIDC/ticketing/SMS/MDE are guarded; that would reject the legitimate
internal endpoint. Internal ≠ malicious here. Instead: (1) `openai_compatible` base_url host[:port]+scheme MUST exactly
match an `ai_provider_allowed_endpoint` (rejected at save; resolver fails closed to `disabled` if it ever sees a
non-allowlisted one); (2) client appends only the fixed `/v1/chat/completions` path and DISALLOWS redirects; (3) the
platform-admin-curated allowlist IS the trust boundary (an internal address on it is trusted on purpose); (4)
`anthropic` keeps its fixed code-constant host (netsafe-exempt). Net: the only reachable targets are the hardcoded
Anthropic host or a platform-admin-allowlisted endpoint — tenant/admin input can never point the client at an
arbitrary URL. SSRF closed WITHOUT blocking the sovereign endpoint. **This is the one place a careless "wrap it in
SafeClient" fix breaks the feature — flag it in the build + review.**

**Resolver (fail-closed).** `ResolveProvider(ctx, tenantID)`: load `tenant_ai_policy.allowed_kinds` → load
`ai_provider` (tenant or global) → if resolved kind ∉ allowed_kinds → `disabledProvider` (never silently use a
forbidden provider) → build provider; openai_compatible base_url must be allowlisted else `disabledProvider`+audit.

**Config surface (admin-gated, audited, tighten-only).** platform-admin: `GET/PUT /admin/ai/provider`,
`GET/POST/DELETE /admin/ai/allowed-endpoints`, `PUT /admin/tenants/{id}/ai-policy`. tenant-admin: `GET/PUT
/tenant/ai/provider` (kind must be within allowed_kinds; base_url must be allowlisted; else 403/400). A
`tenant_ai_policy` restriction is platform-admin-set and CANNOT be loosened by tenant/lower role (same "overrides may
only tighten" pattern as SOAR/detection). Vault: api_key_ref through the existing vault; credential-decrypt audit on
unseal (same as connector creds).

**Verify / adversarial (round on landing).** resolver order (tenant→global→disabled); restriction fail-closed
(kind∉allowed→disabled, audited); allowlist enforced (non-allowlisted base_url rejected at save + fails closed);
openai_compatible request/response mapping; disabled→fallbackSummary; sovereign tenant pinned to
`{openai_compatible,disabled}` CANNOT select anthropic (403); an ALLOWLISTED INTERNAL endpoint WORKS (proves
internal-is-allowed — the crux); non-allowlisted refused; FORCE-RLS no cross-tenant provider read; vault decrypt-audit
present; `GuardNoAutoContain` intact; **AI-off tenant still functions**. Adversarial: base_url→169.254.169.254 rejected
unless a platform admin explicitly allowlisted it (trust is the admin's, by design); redirect off the allowlisted host
blocked; lower role cannot loosen `tenant_ai_policy`.

**Current seam (verified at HEAD f327698, so the resolver refactor is real, not hypothetical).** `ai.Service` holds
ONE startup-built `gw *Gateway` (`cmd/api/main.go:265` = `ai.NewService(ai.NewGateway(cfg.AnthropicAPIKey,
cfg.AIModel), …)`), called at exactly TWO sites — `service.go:137` (alert summary) and `:236` (incident summary) —
both gated by `s.gw.Available()`, with `s.gw.Model()` used for the audit label (`:131`, `:227`). The refactor is
therefore small and contained: introduce a `Provider` interface (`Available()`/`Model()`/`Complete(ctx,system,user)`)
that the existing `*Gateway` already satisfies structurally, and replace the singleton field with a
`resolve(ctx, tenantID) Provider` call at those two sites (both already operate on a tenant-scoped alert/incident, so
the tenant id is in hand). No call-signature churn leaks outside `ai/`.

**Proposed chunks (test-first; keep build/vet/soar+connector green each step; DORMANT until a provider row is set).**
- **A-1** migrations: `ai_provider` (+ seed one global `anthropic` = current default so existing tenants are byte-for-byte
  unchanged), `ai_provider_allowed_endpoint`, `tenant_ai_policy`; FORCE RLS + `schemacheck` invariants + from-zero migrate.
- **A-2** `Provider` interface + `anthropicProvider` (wraps today's Gateway, netsafe-exempt fixed host) + `disabledProvider`
  (`Available()==false` → existing `fallbackSummary`). Pure unit tests; no behavior change yet (resolver still returns the
  global anthropic row → identical output).
- **A-3** `openaiCompatibleProvider` (allowlisted base_url + fixed `/v1/chat/completions`, redirects DISALLOWED, plain
  `http.Client` NOT SafeClient — the load-bearing guard) + `resolve()` fail-closed (tenant→global→disabled;
  kind∉allowed_kinds→disabled+audit; base_url∉allowlist→disabled+audit). Unit + RLS tests incl. the internal-endpoint-works crux.
- **A-4** config surface: platform-admin `GET/PUT /admin/ai/provider`, `GET/POST/DELETE /admin/ai/allowed-endpoints`,
  `PUT /admin/tenants/{id}/ai-policy`; tenant-admin `GET/PUT /tenant/ai/provider` (kind∈allowed + base_url∈allowlist else
  403/400; tighten-only — a tenant can't loosen its platform-set policy). Vault `api_key_ref` + decrypt-audit on unseal.
- **A-5** wire `resolve()` into the two `service.go` call sites + audit provider_kind+endpoint+model on every call; confirm
  `GuardNoAutoContain` intact and an AI-off tenant still summarizes via fallback.
- **A-6** dedicated adversarial round (the Verify list above): allowlist-not-block crux, resolver order, restriction
  fail-closed, SSRF-to-metadata rejected-unless-explicitly-allowlisted, redirect-off-host blocked, FORCE-RLS cross-tenant,
  lower-role-can't-loosen.

**UI reconciliation (owner granted design-tweak authority).** The admin/tenant config surface maps to the designer's
`nirvet-soc-settings-policies.html` (policy/provider settings) and `nirvet-soc-ai-copilot.html`. I'll reconcile those to
the real contract as A-4 lands (allowed_kinds gating, allowlist-validated base_url field, disabled state, decrypt-audit
surfacing) — the allowlist guard is NOT negotiable to match a mockup that shows a free-form URL field.

**Gate checklist.**
- [x] Config shape decided now (this gate) so no other AI feature accretes on the hardcoded gateway.
- [x] Build precondition met: SOAR slice C + Entra vendor landed (this gate was held for them).
- [x] Seam verified in code (singleton `gw` at 2 sites → per-tenant resolver; refactor contained to `ai/`).
- [x] **Reviewer confirms the ALLOWLIST-not-block guard framing + chunk plan (CLEARED FOR A-1, tracked task #39).**
- [ ] Build A-1..A-6 test-first; dedicated adversarial round on landing (allowlist guard + internal-endpoint-works are the headline checks).

**✅ CLEARED FOR A-1 (reviewer, task #39).** Allowlist-not-block stated exactly right; internal-endpoint-works crux in
the test list; resolver fail-closed handles the restricted-tenant case correctly; chunk plan sound. Five minor
build-time notes to FOLD IN (none block):
1. **Cleartext-egress warning** — when an `http` (non-TLS) allowlist entry has a configured api key, warn/flag at
   save: the key crosses the wire in cleartext. Approved on-prem http is allowed, but surface the exposure.
2. **`api_key_ref` nullable** — a keyless local model (no auth) is legitimate; don't force a vault ref. Provider
   builds with no key when null; only anthropic/keyed-openai require one.
3. **Bounded `openai_compatible` client timeout** — the provider's `http.Client` gets an explicit finite timeout
   (mirror the 30s gateway budget), never a zero/unbounded client, so a hung sovereign endpoint can't wedge a call.
4. **Assistive-only carries to the new provider** — `GuardNoAutoContain` / `Assistive:true` must hold for
   openai_compatible exactly as for anthropic; an alternate provider must not become an auto-action path.
5. **Framing stays explicit** — the allowlist is a DATA-EGRESS / RESIDENCY control (§1903), not just SSRF hardening;
   keep that in the code comments + audit so the residency intent is legible, not incidental.

**→ BUILDING A-1→A-6 test-first, folding in the 5 notes. Design-file pass DEFERRED to A-4 (reconcile the two AI
screens against the BUILT contract, not the spec). Dedicated adversarial round on landing.**

**✅ LANDED & DORMANT (HEAD eea81da) — awaiting the reviewer's landing round.** A-1 migration 0067 (2277e7f) · A-2
Provider interface + adapters (83bdd03) · A-3 openai_compatible + fail-closed resolver + netsafe waiver (94f80b2,
a97845d) · A-4 config surface + vault seal + migration 0068 (05e0581) · A-5 resolver wired into the copilot + vault
unseal + per-call provider audit (705320c) · A-6 adversarial RLS forge probes (eea81da). 33 ai tests + schemacheck +
soar + connector green on a fresh DB; outbound-http guard green. Real behavior unchanged until an admin sets a
provider row (seeded global anthropic = today's default).

**All 5 build-notes folded:** api_key_ref NULLABLE (keyless), bounded openai timeout, keyless omits auth,
GuardNoAutoContain carried by the assistive-only Provider interface, allowlist framed as the §1903 egress/residency
control in code + audit. **The load-bearing guard proven end-to-end:** `TestResolve_AllowlistedInternalEndpointWorks`
stands up a real loopback server, allowlists it, and confirms the resolved provider COMPLETES against it (internal-is-
allowed); the client is `// netsafe-exempt` (CI-waived), never SafeClient.

**Migration note (0068):** 0067's ai_provider write policy `WITH CHECK (tenant_id = app_current_tenant())` rejected
the GLOBAL row (NULL=NULL isn't true) — WithSystem sets no GUC and doesn't bypass RLS. 0068 widened it to also allow
the global row ONLY under system context (`app_current_tenant() IS NULL`). A-6 proves a tenant still cannot
forge/write/update the global row → no platform-default-hijack.

**Reviewer next:** landing round on this feature (allowlist-not-block crux + internal-endpoint-works + tenant-can't-
forge-global as the headline checks). **Deferred to A-4-follow-on / owner:** reconcile the two AI screens
(nirvet-soc-settings-policies.html, nirvet-soc-ai-copilot.html) against the built contract (allowed-kinds gating,
allowlist-validated URL field, disabled state) — NEVER soften the allowlist to match a free-form-URL mockup. Then
#118 host-telemetry (do not interleave).

---

## Gate — Host-Telemetry Flow: osquery/Wazuh → collector → normalize → detect (§321–326, E09 US-033..036) — DESIGN REVIEW (pre-code) — Jul 2026

**Source spec:** `outputs/NIRVET_IMPL_SPEC_AI_PROVIDER_AND_HOST_TELEMETRY.md` Part 2.
**Status:** near-free design inclusion done NOW (§6.5 field-group requirement + §1.4 scope clarification below);
BUILD after SOAR slice C, pulled by a sovereign/low-maturity engagement.

**Why + the §1.4 boundary (record as a scope CLARIFICATION, not a breach).** §321–326 already scopes an on-prem/
air-gapped **adjacent collector** (customer-side collectors normalize/filter/forward telemetry; residency
configurable), and the Syslog + Webhook/API on-ramps (E09 US-033..036) exist. §1.4 scopes OUT "replacing full
enterprise EDR / equivalent endpoint agents" — so **we do NOT build an endpoint agent.** We INGEST telemetry from a
customer-deployed OPEN agent (osquery/Wazuh) into the in-scope collector. Forwarding telemetry into an on-ramp is
ingestion, not EDR. **§1.4 clarification (record, don't edit the immutable SRS source):** ingesting from a
customer-run open host agent is in-scope ingestion; building/shipping an agent remains out of scope. This is the
difference between serving and not serving the no-EDR / low-maturity / sovereign customer — plausibly Nirvet's core buyer.

**In scope.** New source kind(s) for host telemetry (`host_osquery`/`host_wazuh`, or one `host_agent`); a host-event
normalizer (osquery/Wazuh → canonical/OCSF, mirroring the existing 8 normalizers); a seed ATT&CK-mapped host detection
pack (from public osquery packs / Wazuh rulesets / SigmaHQ); per-source auth + tenant scoping (reuse US-036 HMAC/API
key + existing event-path RLS); per-source health/last-seen (US-032). Recommend/validate/DOCUMENT an open-agent config
— do NOT author an agent. **Out:** building an agent; bidirectional agent control / query push-down (v1 = ingest only);
agent auto-deployment.

**Two supported topologies.** (A) direct: osqueryd TLS logger → `POST /ingest` (kind=host_osquery, HMAC) → normalize
→ detect. (B) managed/sovereign (§321–326): Wazuh agents → self-hosted onshore Wazuh **manager** (normalize/filter/
forward) → `POST /ingest` (kind=host_wazuh) → …. Both reuse the EXISTING push ingest (`ingestion/handler.go Ingest`)
+ existing source auth. Topology B's Wazuh manager IS the in-scope adjacent collector for a sovereign in-country deploy.

**DESIGN INCLUSION NOW (near-free, so §6.5 isn't retrofitted).** Today the canonical event carries `ActorRef`/
`TargetRef` + an opaque `Data` map (normalize.go) — there are NO first-class host/process/file/user/network field
groups. **Requirement folded into the §6.5 canonical/OCSF schema design:** it must carry **host, process, file, user,
network** field groups so host events map cleanly instead of being bolted on later. Target OCSF mappings:
process exec→Process Activity (1007); file create/modify→File System Activity (1001); logon/auth→Authentication (3002);
net connection→Network Activity (4001). (Build the schema extension in this slice; the DECISION is captured now.)

**Security / sovereignty.** Per-source credential (HMAC/API key, US-036); ingest tenant-scoped (existing RLS); a source
belongs to exactly one tenant. Agent + Wazuh manager + Nirvet all self-hostable onshore (osquery Apache-2.0; Wazuh
GPLv2; Fleet MIT) — nothing phones home; non-egressing collection pairs with onshore deploy + AI-off/self-hosted-model
(Part 1) for an end-to-end in-country SOC. Input hardening: treat agent payloads as untrusted — size caps, schema
validation, parameterized (no field→SQL), path/filename sanitation on file events (same discipline as STIX/attachments).

**Health (US-032).** Per-source heartbeat/last-seen; ALERT when a host source goes silent past a threshold — a silent
endpoint is a detection gap (the SOC-worst-failure theme). Surface in connector health, not just a status field.

**Verify plan.** Ingest a representative osquery pack result + a Wazuh alert JSON → normalize → canonical (OCSF-mapped)
→ a seeded host detection FIRES; tenant isolation (source A's events never visible to tenant B); source auth rejects a
bad HMAC; malformed/oversized payload rejected not panicked; health signal fires on source silence; §6.5 mapping
round-trips the four classes above.

**Gate checklist.**
- [x] §6.5 field-group requirement (host/process/file/user/network) recorded now so it isn't retrofitted.
- [x] §1.4 scope clarification recorded (ingest-from-open-agent is in-scope ingestion; no agent build).
- [x] Build precondition met: SOAR slice C + Entra + #117 AI-provider all landed.
- [x] **Reviewer PRE-CODE pass given (alongside #117 — reviewer confirmed the gate at #117 landing).** Build-ready.
- [ ] Reviewer pass on landing (tenant-isolation + silent-source health are the specific checks).

**✅ CLEARED TO BUILD (reviewer pre-code pass).** SRS anchors are LINE NUMBERS: §321–326 = the On-Prem/Air-Gapped
Adjacent Collector deployment rows; this is a new source kind under backlog E09 (US-033..036) + E08 health (US-032),
NOT a new epic. Build when the owner picks it up; run test-first, reviewer landing round on the tenant-isolation +
silent-source-health checks. Full spec: build/NIRVET_IMPL_SPEC_AI_PROVIDER_AND_HOST_TELEMETRY.md Part 2. Do not
interleave with other work mid-build.

**✅ H-1..H-3 LANDED (HEAD 2d32581) — awaiting reviewer landing round.** Dormant until a tenant configures a
host_osquery/host_wazuh source. H-1 (89965d1) connector kinds + §6.5 host/process/file/user/network field groups +
normalizeOsquery/Wazuh → 4 OCSF classes (Process 1007/File 1001/Auth 3002/Network 4001), unit-tested. H-2 (b486b4d)
nested field-group resolution in the detection engine (data.process.cmdline; flat-key-first, back-compat) + migration
0069 seed pack (4 global ATT&CK rules T1105/T1053/T1003/T1110) + end-to-end test (osquery curl → seeded rule FIRES;
benign ls does not over-fire; Wazuh failed-auth fires). H-3 (2d32581) silent-source health US-032: last-seen already
recorded on keyed ingest (MarkSuccess); SilenceSweeper alerts once per silence episode via a SECURITY DEFINER
cross-tenant read (migration 0070), wired into the worker. migrations → 0070, from-zero clean; ingestion + detection
+ connector + schemacheck + outbound-http all green.

**Verify-plan status for the reviewer round:** ✅ 4-class OCSF mapping (H-1) · ✅ seeded host detection FIRES (H-2) ·
✅ silent-source health fires (H-3). REUSE-EXISTING (reviewer to confirm, not rebuilt): source auth rejects bad HMAC
(US-036 keyed webhook path), oversized/malformed payload rejected-not-panicked (existing ingest size caps/validation),
tenant isolation (existing RLS on the event path — host sources use the same collector). Reviewer headline probes per
gate: tenant-isolation + silent-source health.

### Round #34 remediation (7d69689) — H-1 + M-1 fixed
- **H-1 (High)** crash-resume reversibility, fixed at the supervisor SEAM: `phaseBC(resumed bool)` — a resume + PreCheck-noop attributes `changed=true` (our own in-flight action → reverse can release), a fresh claim finding target already-done stays `changed=false` (foreign). Covers every future PreCheck Actioner. Test: reverse-after-crash-resume asserts unisolate fires once.
- **M-1 (Medium)** OData filter injection escaped (`odataQuote` doubles single quotes in resolveMachineID + latestMachineAction). Unit-tested.
- 8 round-#34 scenarios green (C-3 no-double-POST intact); full repo suite green on fresh DB. Reviewer re-verify = task #36. `destructive_enabled` stays OFF.

### Round #34 re-verify (5c2e416) — H-1 re-fixed via CORRELATION; M-1 confirmed
- **M-1** confirmed fixed (odataQuote both sites). **H-1 first fix (7d69689) was itself FAIL-OPEN** (reviewer re-verify): the `resumed`-flag override attributed ANY resumed no-op to us, but a claim proves we CLAIMED (Phase A) not that we POSTed (Phase B) — a FOREIGN isolation + crash-in-window → reverse released a containment we never created.
- **Correct fix:** attribute by CORRELATOR not resumed. Supervisor injects a stable per-step correlator (run_id:step_index, `soar.ActionCorrelatorParam`) into params; the Defender Actioner embeds it in the MDE requestorComment on execute and, on a PreCheck-active, sets changed = the comment carries OUR correlator (own→reversible, foreign→not, crash-before-POST→fresh POST). Removed the resumed override entirely. C-3 no-double-POST intact.
- **Mirror test added** (was structurally unrepresentable): `TestDefenderRound_ForeignIsolationNotReversed` + connector-unit `TestDefenderActioner_ForeignVsOwnAttribution`. 9 round-#34 green; full suite green fresh DB. Reviewer re-verify again = task #36. LESSON: on a destructive resume, "we claimed" ≠ "we acted" — own-vs-foreign needs a correlator carried in the vendor effect, not an engine-state proxy.

---

## Gate — §6.11 SOAR slice C follow-on: async completion reconciler (D-3) — DESIGN REVIEW (pre-code) — Jul 2026

**One-line.** Turn a real containment's `executed` (= "submitted to MDE", the machineAction id captured) into
`confirmed` (= "MDE reports the isolation actually took effect"), and turn a later-FAILED isolate from a
silent "confirmed containment" into a surfaced, non-reversible, alerted failure. Hardens the honesty of the
existing Defender action BEFORE a second vendor multiplies it. Owner-selected next; reviewer-recommended
sequence (reconciler → 2nd vendor → live smoke). Dormant/OFF-by-default like all of slice B/C.

**SRS grounding.** SOAR-006 (log every execution OUTCOME, not just submission); SOAR-009 (failure handling +
escalation to human); §10.2 severity. The SOC-worst-failure theme: believing a host is contained when it is
not is worse than a visible failure. Closes the slice-C gate's D-3 named follow-on ("`executed` = accepted-by-
MDE, not confirmed-isolated; a completion reconciler that confirms terminal machineAction status is a follow-on").

**Why (grounded).** MDE isolate is ASYNC: the machineAction goes Pending → InProgress → Succeeded | Failed |
Cancelled | TimeOut. Today `phaseBC` records `executed` the instant MDE ACCEPTS the POST (connector_ref = the
machineAction id) — so a machineAction that later FAILS still reads as `executed` = confirmed containment. That
is a silent detection/containment gap on the destructive path.

**In scope.**
1. **Schema (mig 0065):** `soar_action_execution` gains `confirmed boolean NOT NULL DEFAULT false`,
   `confirmation_status text NOT NULL DEFAULT ''` (the terminal machineAction status), `confirmed_at timestamptz`.
   No new `status` CHECK value — a confirmed FAILURE flips `status='executed' → 'failed'` (within the existing
   CHECK), which also drops the row out of `listReversibleExecutions` (status='executed' filter) so reverse can't
   try to un-isolate a machine that was never isolated. Index for the poll query `(confirmed, status, claimed_at)`.
2. **`Confirm` capability on the Actioner (optional field, mirrors `Fn`):** add
   `Confirm func(ctx, creds []byte, connectorRef string) (done bool, success bool, status string, err error)` to the
   `Actioner` struct. Defender sets it (GET `/api/machineactions/{id}` → status); a synchronous action leaves it
   nil. `Confirm==nil` ⇒ the action has nothing async to wait on (the reconciler marks it confirmed=true).
3. **Reconciler loop (worker), system-level, panic-guarded** — mirrors `StartResumeLoop` + `soar_stale_executions`:
   a SECURITY-DEFINER query lists `executed`, `dry_run=false`, `NOT confirmed`, `NOT reversed`, non-empty
   `connector_ref` rows older than a small grace period (spans tenants). For each: look up the Actioner; decrypt
   the tenant's creds via the existing `CredDecryptor`; if `Confirm==nil` → mark confirmed=true; else call `Confirm`
   and apply the terminal-state table below. Idempotent (a confirmed/failed row is never re-selected); safe to run
   in exactly one worker.
4. **Failed-containment alert (SOAR-009):** a Failed/Cancelled/TimeOut isolate emits a HIGH-severity durable
   notification via the existing outbox (the worker already wires `notifySvc`) — "containment reported FAILED for
   <target>; host is NOT isolated". This is the honesty payoff.

**Terminal-state handling.**

| machineAction status | confirmed | row status | reverse | alert |
|---|---|---|---|---|
| Succeeded | true | executed | eligible (unchanged) | no |
| Failed / Cancelled / TimeOut | false | → **failed** | excluded (nothing to undo) | **yes** (SOAR-009) |
| Pending / InProgress (not terminal) | false | executed | eligible | no — retry next tick |
| still Pending past a STALL threshold | false | executed | eligible | **yes** — "stalled containment, unconfirmed" |

**Out of scope (later).** Auto-retry of a failed destructive action (NEVER auto-retry containment — human decides);
confirmation of the reverse/unisolate action (V1 confirms isolate only); confirmation for internal executors
(notify/ticket are synchronous). §6.3 UI.

**Config (no-hardcoding; per-tenant `soar_settings` or global `soar_platform`, lazy default):**
`confirmation_poll_interval_secs`, `confirmation_grace_secs` (don't poll immediately after submit),
`confirmation_stall_secs` (Pending-too-long → alert). Seeded defaults; tighten-only where a per-tenant override exists.

**Key design decisions — reviewer, please confirm:**
- **D-a** Confirmed-FAILURE flips the row to `status='failed'` (so it exits `listReversibleExecutions`) + alerts;
  it does NOT auto-retry. Correct that reverse must skip it (the isolate never took hold → nothing to undo).
- **D-b** `Confirm` is an optional Actioner field (`nil` = synchronous ⇒ reconciler marks confirmed=true). No
  supervisor/`phaseBC` change needed; the reconciler owns all confirmation writes.
- **D-c** The reconciler decrypts creds and calls a READ-only vendor endpoint (GET machineaction) — no destructive
  effect, so no gate/kill-switch/rate-cap needed on the poll itself (those guard EXECUTION, not status reads).
- **D-d** A machineAction that MDE has aged out / 404s past the stall window → treat as unconfirmable → alert
  "stalled/unknown", leave the row `executed` (do NOT silently mark failed OR confirmed on missing data).

**Correctness invariants (round on landing).**
- Succeeded → confirmed=true, still reversible; no alert.
- Failed → row `failed`, **excluded from reverse** (ReverseRun no-ops it), HIGH alert emitted once.
- Not-terminal → left executed/unconfirmed, retried next tick (no premature confirm/fail).
- Stuck Pending past `confirmation_stall_secs` → alerted once, not silently confirmed.
- Poll is read-only: no isolate/unisolate POST ever fires from the reconciler.
- Idempotent + tenant-isolated (SECURITY DEFINER list + per-tenant creds); panic-guarded; one-worker-safe.

**Chunks (test-first, A+B+C suites green each step).**
- **R-1** schema 0065 + repo (system list-unconfirmed, mark-confirmed, mark-failed) + config lazy-default.
- **R-2** `Confirm` Actioner field + Defender `confirm` (GET machineaction) + unit test vs mock. **Fold in the
  round-#34 LOW here** (own-vs-foreign correlator match → delimited `[nirvet:<corr>]` token instead of bare
  `strings.Contains`, since this chunk already touches the Defender attribution code).
- **R-3** reconciler loop + terminal-state table + failed-containment alert + reversibility exclusion; wire into cmd/worker.
- **R-4** adversarial: Succeeded→confirmed; Failed→failed+not-reversible+alert; Pending→retry; stuck→alert;
  Confirm-nil→confirmed; poll-never-POSTs; tenant isolation.

**Gate checklist.**
- [ ] Reviewer confirms D-a..D-d (fail→status flip + reverse-exclusion; optional Confirm field; read-only poll needs no gate; 404/aged-out = alert-not-guess).
- [ ] Owner confirms alert channel for a failed containment (durable notification via outbox = the proposed default).
- [ ] On green → build R-1..R-4 test-first, fold in the LOW; reviewer pass on landing.

### Revision — G-1/G-2 folded in (reviewer greenlit, owner agreed, pre-code)

Reviewer confirmed D-a..D-d (D-a verified against the real `listReversibleExecutions` filter) and greenlit the
build once these two folds are written in. Both are the reconciler asking the SAME two questions the destructive
loop already turns on — *whose action, and did it really happen* — instead of flattening every `executed` row to
"ours, and done":

- **G-1 — poll the REAL machineAction id, not the display ref.** `connector_ref` is a bare machineAction id on a
  fresh POST but a DISPLAY string (`own-isolate:<id>` / `foreign-isolate:<id>`) on a crash-resumed no-op row.
  Polling the display string 404s → a false "unconfirmable" alert that never confirms. FOLD: the Defender Actioner
  records the bare machineAction id in a dedicated `prior_state.action_id` in EVERY path (fresh POST → the returned
  id; precheck-noop → the found active action's id). The reconciler polls `prior_state.action_id` (falling back to
  `connector_ref` only if it is a bare id). `connector_ref` stays human-readable.
- **G-2 — reconcile/alert ONLY on rows we caused.** The list query + loop process a row ONLY when
  `prior_state.changed = true` (ours, and we effected it). A FOREIGN isolation (`changed=false`/`foreign=true`) or
  an own no-op is never confirmed, never flipped to `failed`, never alerted — otherwise a foreign isolation that
  MDE later reports Failed would fire a HIGH "containment failed" alarm for a containment that was never ours. The
  SECURITY-DEFINER list filters `(prior_state->>'changed')::boolean IS TRUE`.

**Owner decision — alert channel (BOTH).** A failed/stalled containment emits BOTH a HIGH-severity durable outbox
notification AND an internal alert/incident, so it lands in the SOC's triage queue (not only an email).

**Two pinning tests added to R-4 (the ones that would have caught G-1/G-2):**
- G-1: isolate → crash → resume (own, `changed=true`, display `connector_ref`) → reconciler polls `action_id` →
  MDE Succeeded → **confirmed=true** (no false 404/"unconfirmable").
- G-2: foreign isolation present → fresh isolate no-ops (`changed=false`) → its machineAction reports Failed →
  reconciler **skips it**: no `failed` flip, no alert (assert alert-count 0, row stays `executed`).

**Checklist — CLEARED to build:**
- [x] Reviewer confirmed D-a..D-d; G-1/G-2 folded above; landing review queued as reviewer task #37.
- [x] Owner confirmed alert channel = BOTH outbox HIGH + internal alert/incident.
- [ ] Build R-1..R-4 test-first (fold in the round-#34 LOW at R-2); ping reviewer on landing.

### LANDED (ffe7424) — reconciler R-1..R-4 built, dormant

- R-1 (2db73b0) schema 0065 + repo (confirm/fail lifecycle; G-1/G-2 enforced in the SECURITY-DEFINER list).
- R-2 (3dbd2da) Actioner.Confirm + Defender getMachineAction/confirm + FOLD the round-#34 LOW (delimited
  correlator token, so `:1` can't substring-match `:10`).
- R-3+R-4 (ffe7424) Supervisor.ReconcileOnce (D-3 terminal-state table, read-only poll, panic-guarded) +
  StartReconcileLoop in cmd/worker; ContainmentAlerter → soarContainmentAlerter = BOTH internal triage alert
  (alert.RaisePlatform) + durable HIGH outbox notification, deduped per execution; adversarial suite green.
- G-1 (poll the bare prior_state.action_id, not the display connector_ref) + G-2 (only reconcile rows we
  caused, prior_state.changed=true) both folded and pinned with tests. Sweep bounded ORDER BY claimed_at
  LIMIT 500/tick (no unbounded scan). Full repo suite green on a fresh DB; build/vet/gofmt clean.
- Test lesson: ReconcileOnce is system-level, so integration tests assert on THEIR row + THEIR tenant's
  alerts (not global sweep counts) and confirm their rows at cleanup — a reused DB with accumulated
  unconfirmed rows makes the sweep slow (many HTTP confirms); a fresh CI DB never hits this.
- [x] Built R-1..R-4 test-first; LOW folded. Reviewer landing review = task #37.

---

## Gate — §6.11 SOAR second vendor Actioner — DESIGN REVIEW / SCOPING (pre-code) — Jul 2026

**Status:** scoping while the reconciler landing review (task #37) is pending. BUILD after the reviewer clears the
reconciler. Held deliberately (the reviewer's rule): a second vendor built on the wrong attribution pattern would
re-open H-1b. This gate exists to pick the vendor AND settle the one thing that does NOT transfer cleanly from
slice C — own-vs-foreign attribution for a vendor with no per-action correlator field.

**What DOES transfer for free (the seam is ready):** the two-phase supervisor, the gate (kill-switch / destructive_
enabled default OFF / dry-run / per-class rate cap), MUST-1..4, reverse, the reconciler (D-3), the CredDecryptor,
the config-first catalog, and the round-#34 test harness. A second vendor is a new `defenderClient`-shaped client +
two Actioners + a catalog seed — UNLESS its attribution needs something the seam can't give.

**THE deciding question — how does the vendor answer "did WE cause this state?" (H-1b).** Slice C stamps a
correlator (`[nirvet:<run>:<step>]`) into the MDE machineAction `requestorComment` and matches it on PreCheck. That
works only for a vendor whose action carries a writable, readable per-action field. The two candidates differ
exactly here:

### Candidate A — Entra ID disable-user ⇄ enable-user (RECOMMENDED)
- **Cheapest build:** `entra-id` connector kind already exists; `disable_user` + `revoke_sessions` catalog rows
  already seeded (Class-3 high, connector, entra-id); the Graph client + client-credentials pattern is reusable
  (scope `https://graph.microsoft.com/.default`, permission `User.EnableDisableAccount` / `Directory.ReadWrite.All`).
  Action = `PATCH /users/{id} {"accountEnabled": false}`; reverse = `true`. Target `user:<id|upn>`.
- **Synchronous** (PATCH 204 = done) → NOT async like MDE → the reconciler `Confirm` can be `nil` (confirmed on
  sight), OR optionally a read-back of `accountEnabled==false`. Simpler than MDE.
- **Attribution — comment-less, but it FAILS SAFE (the important insight):** a Graph user object has no per-action
  comment to stamp a correlator into. PreCheck reads the TERMINAL state (`accountEnabled`):
  - fresh, enabled → we disable → `changed=true` (reversible);
  - fresh, already disabled (FOREIGN — an admin/another run) → no PATCH, `changed=false` → reverse never re-enables.
    **The H-1b fail-open is naturally closed** for a state-read vendor: a foreign-disabled account read on resume is
    still `accountEnabled=false` → `changed=false` → fail-CLOSED (never wrongly re-enable).
  - **Residual (fail-SAFE, not fail-open):** a crash AFTER our PATCH but before Phase-C commit → resume reads
    `accountEnabled=false` and cannot tell own-from-foreign → `changed=false` → a genuinely-ours disable becomes
    non-reversible (stranded disabled = availability gap). This is the SAFE direction (the reviewer's stated
    preference), and the reconciler already surfaces the unconfirmed action for a human.
  - **To also close the residual (optional, reviewer decision):** a durable PRE-OBSERVATION — the supervisor
    persists the observed `accountEnabled` BEFORE the PATCH (a small committed step between claim and act), so on
    any resume the before-state is known and `changed = was_enabled`. This is the general mechanism for ALL
    comment-less vendors and a small ENGINE refinement (an optional `Observe` hook). RECOMMEND: ship Entra V1 on the
    fail-SAFE terminal-state PreCheck (simplest, correct-direction), and add the durable pre-observation only if the
    reviewer wants own-crash reversibility now rather than as a follow-on.

### Candidate B — Palo Alto block-IP ⇄ unblock-IP
- **Reuses the correlator seam cleanly:** a PAN dynamic-address-group / registered-IP entry can carry a tag/
  description, so we stamp `[nirvet:<run>:<step>]` exactly like MDE → own-vs-foreign attribution is identical to
  slice C (no new mechanism, no engine change). This is the vendor that literally "inherits the seam."
- **But the biggest build:** new connector kind, new client (PAN-OS XML API or Panorama), new auth (API key, not
  OAuth). `block_ip` is seeded but mis-pointed at connector_key `defender` (would be corrected to a `palo-alto`
  kind). Higher blast radius (an IP block is network-wide; a shared-egress IP is a real hazard) → arguably wants a
  lower default or an extra confirm.

**Recommendation:** **Entra disable-user first.** Highest SOC value (contain a compromised identity), cheapest build
(existing kind + catalog + Graph client), synchronous (no async reconciler needed), and its comment-less attribution
FAILS SAFE — which is the correct direction and, notably, a cleaner story than MDE for the foreign case. It also
forces us to solve comment-less attribution, which generalizes to every future non-taggable vendor. PAN is the right
SECOND-second vendor once a network-containment engagement pulls it.

**Open decisions (owner + reviewer) before E-1:**
- D1 (owner): Entra disable-user as the next vendor? (vs PAN block-IP.)
- D2 (reviewer): accept Entra V1 on the fail-SAFE terminal-state PreCheck (own-crash → stranded-disabled, surfaced
  by the reconciler), OR require the durable pre-observation (`Observe` hook) now to restore own-crash reversibility?
- D3 (reviewer): Entra confirm — `nil` (synchronous, PATCH-204-is-truth) or a read-back of `accountEnabled`?
- D4: `revoke_sessions` (revokeSignInSessions) is NOT cleanly reversible (you cannot un-revoke a session) → declare
  it non-reversible → MUST-1 forces human-confirm for a Class-3 non-reversible action. Scope it as a LATER,
  separate action (its own gate), not part of the disable-user pair.

**Chunks (mirror slice C, after clearance):** E-1 Entra Graph action client (get accountEnabled, disable/enable;
injectable base/scope; D-1-style Microsoft-host allowlist) + unit tests · E-2 the two Actioners (PreCheck terminal
state; +Observe hook iff D2 chosen) + register + (catalog already seeded) · E-3 wire into api/worker registry · E-4
adversarial round (own/foreign/crash-resume-fail-safe/reverse/dry-run/kill-switch/rate — the slice-C matrix, plus
the Entra-specific foreign-already-disabled-never-re-enabled). Its own dedicated adversarial review on landing.

### Attribution decision — refined per reviewer steer (pre-code; the ONE thing to settle before E-1)

The reviewer named the two candidate mechanisms for "did WE disable this account?": (a) the Entra directory audit
log (by app-registration actor), or (b) committed `prior_state`. Worked through against the SAME crash interleavings
that broke slice C, BOTH have a failure mode — and the terminal-state read that "just works" fails SAFE. Analysis:

- **(a) Directory-audit-log correlation.** After our PATCH, `auditLogs/directoryAudits` records "Disable account"
  with `initiatedBy` = our service principal. REJECT for the reverse path: directoryAudits has **ingestion lag**
  (minutes, sometimes longer) → a reverse issued shortly after containment cannot see the entry yet → cannot
  attribute → must default anyway. It also needs a broad `AuditLog.Read.All`, and attributes by APP not by run/step
  (two disables of the same user by the same app are indistinguishable). Fragile exactly when reverse is
  time-critical. Useful only as an out-of-band audit, not the attribution source of truth.

- **(b) Committed `prior_state` (persist observed `accountEnabled` BEFORE the PATCH).** Closes the own-crash
  stranded-disabled case — but reintroduces a NARROW FAIL-OPEN: account enabled → we observe+persist
  `enabled=true` → **crash** → a foreign actor disables the account in the gap → we resume → current already
  disabled so we skip the PATCH → but `changed = observed_enabled = true` → reverse RE-ENABLES an account a
  foreign actor disabled. It trades availability for a (narrow) security fail-open — the exact direction H-1b
  taught us to avoid. Not acceptable as the default on the destructive path.

- **(RECOMMENDED) Terminal-state PreCheck — fail-SAFE under every interleaving.** PreCheck reads `accountEnabled`
  at act time; a resume that finds the account already disabled records `changed=false` and reverse never
  re-enables it. Consequence table:
  - fresh + enabled → disable, `changed=true` (reversible). 
  - fresh + already-disabled (foreign) → no PATCH, `changed=false` → never re-enabled. 
  - crash-after-PATCH (ours) → resume reads disabled → `changed=false` → **stranded disabled (fail-SAFE
    availability gap)** → the RECONCILER surfaces it as an unconfirmed/older action → a human re-enables.
  - foreign-disables-in-the-crash-gap → still reads disabled → `changed=false` → never re-enabled. 
  Every ambiguous case resolves to "do NOT auto-re-enable" — the safe direction the reviewer requires. The only
  cost is a rare stranded-disabled that is loudly surfaced, never a silent wrong re-enable.

**DECISION for reviewer confirming pass:** ship Entra V1 on the **terminal-state fail-SAFE PreCheck**. It is the
only option that never fail-opens on the destructive path; own-crash reversibility is a DELIBERATE, documented,
reconciler-surfaced deferral, not a gap we missed. If the reviewer wants own-crash reversibility now, the correct
way is NOT (b) alone but (b)+ownership-proof (the audit log or a Nirvet marker) to disambiguate the resume — which
is materially more surface for a rare availability case; recommend deferring it. This supersedes the earlier D2
"fail-safe vs Observe" framing: Observe/committed-prior_state is rejected as the DEFAULT because it fail-opens.

**Note on the generalization:** this means comment-less vendors attribute by fail-safe terminal state, and only
vendors with a writable per-action field (MDE requestorComment, a PAN tag) can be BOTH own-reversible-after-crash
AND fail-closed. That is a real, documented property of the destructive model, not a limitation to paper over.

**Decision log:** D1 CONFIRMED by owner — second vendor = **Entra ID disable-user**. Remaining before E-1: reviewer's
pre-code confirming pass on the terminal-state fail-SAFE attribution decision (+ D3 confirm nil-vs-read-back). D4
(revoke_sessions non-reversible) stays a separate later gate. No code until that pass.

### D5 — Protected-identity guard (blast-radius containment) — REQUIRED before E-1 (reviewer, non-negotiable)

Attribution answers *whose* action and *whether* it happened; it says NOTHING about *blast radius*. Disabling the
customer's last Global Admin / a break-glass account / a critical service principal / **the identity Nirvet itself
authenticates as** is the SELF-SEALING failure: it can lock the customer (or Nirvet) out of the tenant **including
the ability to reverse it** — no attribution correctness helps. So a protected-target refusal is a first-class
outcome that must exist BEFORE the disable Actioner is auto-runnable.

**A protected target → WITHHELD + mandatory human escalation (awaiting_customer) + audit (SOAR-006) + HIGH alert —
never a silent skip, never a plain fail.** Evaluated at PreCheck (a read, before any mutation). Three layers, because
any one alone misses cases:

- **L1 — static deny-list (config-first, per-tenant + global seed, tighten-only).** New `protected_identities`
  (tenant_id NULL = global; identity ref = objectId|upn; reason). The customer names their break-glass / critical
  service accounts. Config-first per the no-hardcoding rule; a tenant may add, and remove a global default only for a
  false positive — except the L3 self entry, which is immutable.
- **L2 — dynamic Graph directory-role check (a static list WILL miss someone — the reviewer's point).** At act time,
  Graph-query the target's ACTIVE directory roles (`/users/{id}/transitiveMemberOf/microsoft.graph.directoryRole`).
  Refuse/escalate if the target holds a protected role (config `protected_directory_roles`, seeded: Global
  Administrator, Privileged Role Administrator, Security Administrator, User Administrator; tenant-tunable). PLUS the
  **last-of-role** guard: refuse if disabling this user would leave a protected role with ZERO remaining *enabled*
  members (enumerate role members, count `accountEnabled`). Needs `RoleManagement.Read.Directory` /
  `Directory.Read.All`. This is a read → adds latency but is mandatory; a Graph error here → fail CLOSED (refuse).
- **L3 — self-protection (hard, non-configurable).** Never disable the identity Nirvet authenticates as (the app
  registration's own service principal / the client_id in the connector creds), nor a Nirvet-operated admin. Immutable
  refuse; cannot be removed from any deny-list.

**Generalization (documented; the reviewer keeps pulling this forward).** The same protected-TARGET seam retrofits to
MDE isolate as a HOST blast-radius guard — refuse/escalate isolating a crown-jewel / critical asset (the §6.15 asset
inventory already carries crown-jewel + criticality tags). Ship the guard as a vendor-aware seam so "don't-disable-
protected-identity" and "don't-isolate-critical-server" are one mechanism. Building the Defender host-guard is a
named follow-on (not this gate), but the SEAM lands with Entra.

**Config (no-hardcoding):** `protected_identities` (deny-list) + `protected_directory_roles` (which roles are
protected, seeded) — both admin-configurable with seeded defaults. L3 self is code-derived from the connector
identity, not config.

**Revised chunk plan:** E-1 Entra Graph action client (accountEnabled read, disable/enable, directory-role +
role-member reads; injectable base/scope; Microsoft-host allowlist) + unit tests · **E-2 the protected-target guard
(L1/L2/L3) as a supervisor-consulted seam + config tables + a `ErrProtectedTarget`→withheld/awaiting_customer+alert
outcome** · E-3 the two Actioners (terminal-state PreCheck; Confirm=nil) + register + wire (catalog `disable_user`
seeded) · E-4 adversarial round: own/foreign-already-disabled-never-re-enabled/crash-resume-fail-safe/reverse/dry-run/
kill-switch/rate PLUS the D5 cases — deny-listed identity → withheld+escalate; Global-Admin role → withheld;
last-of-role → withheld; **self (Nirvet's own SP) → withheld, immutable**. Dedicated adversarial review on landing.

**Gate checklist (Entra vendor):**
- [x] D1 owner: Entra disable-user.  [x] D2 reviewer: terminal-state fail-SAFE PreCheck.  [x] D3 reviewer: Confirm=nil.
- [x] D4 reviewer: revoke_sessions non-reversible → separate later gate.
- [x] D5 reviewer: protected-identity guard (L1 deny-list + L2 dynamic role/last-of-role + L3 self) folded in above.
- [x] Reviewer clears the updated gate → build E-1..E-4 test-first; dedicated adversarial round on landing.

**✅ LANDED & DORMANT (HEAD 3965d42) — awaiting the dedicated Entra adversarial round.** E-1 Graph client +
base-URL allowlist (a11409b) · E-2 D5 protected-identity guard + migration 0066 (e424fe9) · E-3 disable/enable
Actioners + shared `soarwire` alerter + api/worker wiring (3965d42) · E-4 adversarial suite
`sliceb_entra_integration_test.go` — all 5 probes GREEN on a fresh migrated DB: disable-happy (1 PATCH, no alert) /
foreign-already-disabled → reverse never re-enables (0 PATCH) / own-crash → stranded-disabled, reverse does NOT
re-enable (fail-SAFE) / clean reverse re-enables (2 PATCH) / D5 self+deny-list+Global-Admin+last-of-role → all
StatusAwaitingCustomer + 0 PATCH + 1 alert + "protected" note. soar + connector suites green. Real containment
engages ONLY when a tenant sets `destructive_enabled` (default OFF).

**Latent bug fixed on landing:** migration 0066 (E-2) used expression-based inline `UNIQUE (COALESCE(...), lower(...))`
table constraints — Postgres rejects expressions in inline constraints (`syntax error at or near "("`), so 0066
failed on EVERY fresh-DB migration, silently breaking CI/prod deploy since e424fe9. Replaced with `CREATE UNIQUE
INDEX`. Verified 66/66 apply from zero with the 4 seeded protected roles present. Lesson reinforced: run a
FROM-ZERO migrate in CI, not just against a reused dev DB.

Reviewer next: dedicated Entra adversarial round (own/foreign/crash/reverse/D5 as headline probes) + the two named
follow-ons (Defender-host protected-guard seam retrofit; live Entra/Defender sandbox smoke, needs owner creds).

**✅ DEDICATED ADVERSARIAL ROUND COMPLETE — CLEAN (no High, no Medium; report `NIRVET_REVIEW_ENTRA_VENDOR_ROUND.md`).**
Reviewer verified against source: D5 pre-mutation + fail-closed at the caller (Graph error → withhold, not proceed);
terminal-state fail-safe (no H-1b analog possible — no correlator, no resume-override); no OData injection (target
is path-addressed `/users/{PathEscape(ref)}`, not a `$filter`); 0066 from-zero fix confirmed. Cleared for the owner's
live Graph sandbox smoke (app-reg needs `User.ReadWrite.All` + `RoleManagement.Read.Directory`/`Directory.Read.All`);
`destructive_enabled` stays OFF until then.

Two LOW/tuning notes CLOSED (post-round tuning, suites green):
- **last-of-role over-escalation** — the guard already blanket-withholds ANY member of a protected role, which is
  strictly stronger than "last member of a protected role", so scoping last-of-role to the protected set (reviewer
  remedy) made it fully subsumed. Removed the all-roles last-of-role sweep (it only over-escalated on the last
  member of trivial NON-protected roles) + its per-role Graph round-trips. Protected roles fully covered by the
  blanket check regardless of member count. New probe `TestEntraRound_SoleMemberNonProtectedRoleAllowed` +
  updated `D5Guards/global_admin` (2 members, proves withheld-because-protected not because-last) + connector unit
  test flipped. Client keeps `roleEnabledMemberCount` for a future refined per-role policy. **Posture note for
  reviewer:** I kept the blanket "holds-protected-role → withhold" stance (you did not flag it); relaxing it to
  "withhold only the last member of a protected role" is a security-posture change I did not make without your call.
- **L3-self vacuous under app-only auth** — documented in the guard header: client-credentials `client_id` is a
  service-principal appId, not a `/users` object, so it can't match a real user disable; retained as a cheap
  immutable invariant that also covers a future delegated-auth mode. No logic change.

**✅ CLEARED FOR E-1 (reviewer, D1–D5 all verified against source).** Build E-1→E-4 test-first, SOAR A+B+C green each
chunk; dedicated adversarial round on landing (headline probes: D5 deny-listed/Global-Admin/last-of-role/self →
withheld+escalate+alert; terminal-state fail-safe foreign-already-disabled → reverse never re-enables). Reviewer note
(E-2, non-blocking): the last-of-role count is inherently BEST-EFFORT (TOCTOU) — a concurrent disable of another
member between the count and our disable could theoretically leave zero; there is no cross-Graph-API transaction, so
DOCUMENT it as best-effort (meaningfully reduces risk; not an airtight invariant). Sequencing: finish Entra vendor-2
(E-1→E-4) coherently BEFORE #117 (AI-provider config) then #118 (host-telemetry); do not interleave mid-build.

---

## Gate — §6.18 Platform Administration, Configuration & Feature Flags — slice A — DESIGN REVIEW (pre-code) — Jul 2026

**SRS:** §6.18 ADMIN-001..010 (00_SRS.md lines 1447–1504; all Must). §6.18 is the last true STUB — there is **no
`admin` package** today (`platform/` is infra: audit/auth/crypto/db/queue). Global config exists only as
domain-specific islands: `soar_platform` (kill-switch), `ai_provider`/`tenant_ai_policy` (#117), `tenants.status`.
This gate builds the **general platform-config + feature-flag surface and the security governance around it** — it
does NOT rewrite those islands (they stay authoritative for their domains; this references them).

**Why this first / why gated hard:** platform-admin is where a single toggle can weaken the whole platform. An admin
feature flag that can silently disable MFA, RLS, audit immutability, or the destructive-SOAR enablement gate is the
**platform-admin analog of the D5 blast-radius problem** — so feature-flag safety gets the same "some switches are
NOT freely flippable" treatment we gave protected-identity targets. This is the headline design concern; the reviewer
flagged it as the one to nail before code.

### Scope (slice A — the security-critical core; broad §6.18 phased)
**In:** ADMIN-001 general `platform_config` (material settings not already owned by a domain island) · **ADMIN-002
feature flags** with a **safety classification** · **ADMIN-004 config audit (immutable) + rollback (surfaces security
deltas)** · **ADMIN-005 tenant lifecycle** states + a **uniform offboarding routine** (closes the reviewer's
"offboarding = one routine over all tenant-scoped tables, not per-table FK cascade" thread, and TEN-009) ·
**ADMIN-008 maintenance windows** that do not silently drop incidents.
**Out (later slices, noted so nothing accretes wrong):** ADMIN-003 health dashboards (read-only aggregation),
ADMIN-006 data-repair/reprocess, ADMIN-007 content library, ADMIN-009 secrets-rotation reminders / cred-expiry,
ADMIN-010 support tickets.

### THE headline guard — feature-flag SAFETY CLASSIFICATION (get this exactly right)
Every flag key carries a **safety_class that is CODE-OWNED, not admin-editable** (a Go registry keyed by flag key —
an admin must NOT be able to reclassify a `protected` flag to `open` to bypass the guard; this is the
config-ization-without-guardrails trap the SOAR rounds taught us). Four classes:
- **`open`** — freely flippable by a platform-admin; audited. (e.g. a cosmetic beta feature, a non-security UI toggle.)
- **`guarded`** — security-*relevant* but not a control disable; requires an explicit reason + audit (e.g. enable a
  connector kind for a region, flip a beta data-path). Also the class for flipping a protected flag toward MORE-secure.
- **`protected`** — CAN disable a security control (MFA enforcement, destructive-SOAR enablement, AI egress
  restriction, alert/notification delivery). Flipping toward the **LESS-secure** state requires **elevated authority
  (senior/break-glass) + four-eyes + a required reason + it is time-boxed + it raises a HIGH platform alert**. Same
  authority envelope as a Class-3 SOAR action. Flipping toward more-secure is `guarded`.
- **`immutable`** — NEVER settable via config: RLS enforcement, audit immutability, tenant isolation, the
  SECURITY DEFINER→REVOKE-PUBLIC invariant. A config row that tries to flip an `immutable` key is **REJECTED at
  save (400) and the attempt is audited** — it is not honored, ever. These live as code constants; config cannot reach them.

**Fail-SAFE resolution (mirrors the AI resolver / SOAR withhold-on-uncertainty):** `ResolveFlag(key, scope)` returns
the flag's value, but a **missing / unknown / unreadable / malformed** flag resolves to its **SECURE default** — a
security control defaults ON, a risky feature defaults OFF. There is NO permissive fallback on uncertainty. Every flag
key declares its secure default in the code registry.

**Overrides may only TIGHTEN** (the standing institutional pattern — SOAR/detection/AI-policy): a narrower-scope
override (tenant < region < env < global) may make a flag MORE restrictive, never loosen a platform-set `protected`
flag. Precedence is deterministic and documented.

### The other four security concerns — folded in as first-class design requirements
1. **Config-audit immutability (ADMIN-004).** Every material config/flag change writes an **append-only, tamper-
   evident** row (reuse the `audit_log_immutable` trigger pattern — no UPDATE/DELETE, even by padmin) capturing
   key/scope/old→new/actor/reason/safety_class/timestamp. History is never mutated.
2. **Rollback SURFACES the security delta (ADMIN-004).** Rollback = apply a prior value as a **NEW forward change**
   (never rewrite history) and it **re-runs the SAME safety-class gate** — rolling a `protected` flag back into a
   less-secure state needs the same senior+four-eyes authority as setting it. The rollback preview must show the
   security delta in plain terms ("this re-enables destructive SOAR for tenant X / disables MFA enforcement").
3. **Tenant lifecycle + uniform offboarding (ADMIN-005 / TEN-009).** Tenant states = active → suspended → legal_hold
   → exported → deleted, padmin-gated + audited + MT-008-style reason. Offboarding is **ONE uniform routine** that
   enumerates every tenant-scoped table (not per-table FK cascade — for a retention/compliance SOC, cascade-wipe is
   the WRONG posture): export produces the data set; **legal_hold BLOCKS deletion**; deletion honors retention windows
   and emits a certificate-of-destruction. A registry/generated list of tenant-scoped tables keeps it complete as the
   schema grows (candidate for a schemacheck-style CI guard: every table with `tenant_id` is covered by the routine).
4. **Maintenance windows don't silently drop incidents (ADMIN-008).** A window may suppress NOTIFICATIONS and/or pause
   SLA timers, but **ingestion / detection / correlation / alert+incident creation CONTINUE** — a maintenance window
   is never a detection blackout. Any suppression is explicit, scoped, time-boxed, and **every suppressed
   notification and every SLA pause is LOGGED** (no silent gap — the "silent-withhold is the worst SOC failure"
   theme). On window close, deferred notifications and SLA timers resume; nothing is lost.

### Config shape (DECIDED NOW — FORCE RLS where tenant-scoped; padmin-owned)
- `platform_config` (key within scope, scope enum, value jsonb, updated_by, updated_at) — general material settings.
- `platform_feature_flags` (key, scope {global,env,tenant,package,partner,region,beta}, scope_ref, enabled/value,
  updated_by, updated_at; UNIQUE per (key, scope, scope_ref)). **safety_class is NOT a column** — it comes from the
  code registry; the resolver + guard enforce it. Tenant-scoped rows FORCE RLS; global/env/etc. are padmin/system.
- `platform_config_audit` (append-only + immutability trigger: entity {config|flag}, key, scope, old_value,
  new_value, safety_class, actor, reason, created_at). One log for both config + flags.
- `maintenance_windows` (id, scope, scope_ref, starts_at, ends_at, suppress_notifications bool, pause_sla bool,
  banner text, created_by, created_at; audited). The dispatcher / SLA check consults active windows.
- Tenant lifecycle: extend `tenants.status` enum (+ legal_hold/exported/deleted) + `tenant_offboarding` job rows;
  the offboarding routine is code over a tenant-scoped-table registry.

### Chunk plan (test-first; keep every suite green each step; DORMANT until an admin sets something)
- **P-1** migrations (platform_config, platform_feature_flags, platform_config_audit immutable, maintenance_windows)
  + FORCE RLS/schemacheck/from-zero + the **flag safety-class registry (code)** + `ResolveFlag` (fail-safe default,
  tighten-only precedence, protected/immutable classification). Unit + RLS tests. No behavior change (no flags set yet).
- **P-2** config/flag **set + rollback** with the safety-class gate (open/guarded/protected/immutable), the
  security-delta preview, append-only immutable audit; handlers padmin, protected flips senior+four-eyes+HIGH-alert.
- **P-3** tenant lifecycle states + the **uniform offboarding routine** (export/suspend/legal-hold/delete honoring
  retention + legal-hold-blocks-delete + cert-of-destruction) + the tenant-scoped-table coverage guard.
- **P-4** maintenance windows: continue-ingest/detect; explicit+logged notification/SLA suppression; resume on close.
- **P-5** dedicated adversarial round (below).

### Verify / adversarial round (on landing — the headline probes)
Flag safety: a `protected` flag CANNOT be flipped less-secure without senior+four-eyes (a plain padmin is refused +
audited); an `immutable` key flip is rejected-at-save + audited, never honored; a missing/unknown flag resolves to
its SECURE default (fail-safe); a tenant override cannot loosen a platform `protected` flag (tighten-only); an admin
cannot reclassify a flag's safety_class (code-owned). Config: rollback into a less-secure state re-runs the gate +
surfaces the delta; config-audit is append-only (UPDATE/DELETE rejected even by padmin). Lifecycle: legal_hold blocks
deletion; offboarding covers every tenant-scoped table (guard); FORCE-RLS no cross-tenant config read. Maintenance:
events still ingest + detections still fire + incidents still open during a window; every suppressed notification /
SLA pause is logged; deferred items resume on close. Standard: FORCE-RLS cross-tenant, all mutations audited.

### Gate checklist
- [x] Config shape + the four safety classes decided now (this gate), so no admin feature accretes on an ungoverned toggle.
- [x] **Reviewer confirmed the feature-flag safety classification (D5-analog) + the four folds (task #41).**
- [x] Build P-1..P-5 test-first (cleared once the 3 must-adds below are folded); dedicated adversarial round on landing.

### Revision — reviewer must-adds folded (pre-code, CLEARED TO BUILD, task #41)
Classification + the four folds confirmed. Three must-adds + two reinforcements, all in families prior rounds taught us
to close before code:
- **M-1 — fail-safe CLASS resolution.** An unregistered/unclassified flag key resolves to `protected`, NEVER `open`
  (the absent-catalog→business_critical pattern applied to *classification*). The gate had fail-safe VALUE resolution
  (unknown→secure default) but not fail-safe CLASS — a key nobody classified must be treated as if it could disable a
  control, so a flip needs the elevated envelope until someone registers it.
- **M-2 — critical/P1 breaks through maintenance notification suppression.** Detection-continues is not enough; a
  SUPPRESSED critical is the silent gap. A maintenance window may hold P2-and-below notifications, but a P1/critical
  incident notification ALWAYS delivers (the storm-mode "critical always promotes" rule). SLA pause likewise never
  applies to a P1.
- **M-3 — clearing `legal_hold` needs the elevated envelope** (senior + four-eyes + reason + HIGH alert). Lifting a
  hold REMOVES an evidence-preservation control, so it is a `protected`-class transition, not routine lifecycle.
- **Reinforcement A — `immutable` is resolved from CODE ONLY.** The resolver reads immutable-key state from the code
  registry, never the DB, so a planted `platform_feature_flags` row for an immutable key is INERT (belt-and-suspenders
  beyond reject-at-save): even if a row is written by any path, the resolver never honors it.
- **Reinforcement B — protected time-box auto-reverts to the SECURE state** (PAM pattern). A `protected` flag flipped
  less-secure is time-boxed; a background sweep reverts it to its secure default at expiry (+audit +alert), so a
  forgotten temporary loosening cannot persist indefinitely.

**Landing-round headline probes (reviewer):** unregistered→protected (M-1), critical-breaks-maintenance (M-2),
legal-hold-clear-gated (M-3), immutable rejected-at-save AND inert-at-resolve (Reinf A), protected time-box
auto-revert (Reinf B) — plus the gate's original probes (rollback-surfaces-delta, config-audit-immutable, uniform
offboarding, tighten-only, FORCE-RLS).

**→ CLEARED TO BUILD P-1..P-5 test-first (M-1/M-2/M-3 + A/B folded structurally). Dedicated adversarial round on landing.**

### ✅ LANDED — slice A complete (HEAD 8c7359a, migrations → 0074), awaiting reviewer landing round
- **P-1** (safety-class registry + fail-safe resolver + immutable-inert + immutable audit) — **M-1**, **Reinf-A**.
- **P-2** (flag set/rollback safety gate: immutable rejected-at-save; protected weakening = senior + four-eyes + reason + HIGH alert; guarded/protected-toward-secure = reason; rollback re-runs the same gate).
- **P-3** (tenant lifecycle: legal-hold set routine, **CLEAR = elevated envelope + HIGH alert (M-3)**; uniform tenant-offboarding purge blocked while on hold + certificate of destruction).
- **P-4** (maintenance windows: never stop ingest/detect; **critical/P1 always breaks through suppression + SLA pause (M-2)**; **protected weakening time-boxed, worker sweep auto-reverts to secure at expiry (Reinf-B)**).
- **P-5** (this landing): padmin HTTP surface (`PUT /admin/flags`, `POST /admin/flags/rollback`, `POST|DELETE /admin/tenants/{id}/legal-hold`, `POST /admin/tenants/{id}/offboard`, `POST /admin/maintenance-windows`, all padmin-gated); **M-2 made LIVE** — the SLA sweeper consults the maintenance gate (`incident.MaintenanceGate`, structural, no import cycle), wired in the worker; adversarial round (cross-tenant flag isolation proven NOT an RLS leak; M-2 defer-vs-breakthrough proven end-to-end incl. "deferred ≠ lost").

**Landing-round evidence (all green on a migrated DB):** platformadmin 21/21 (incl. `TestResolve_CrossTenantFlagIsolation`, `TestMaintenance_CriticalBreaksThrough`, `TestReinfB_TimeBoxAutoRevert`); integrationtest `SLABreachPausedByMaintenanceWindow_M2`; incident; cmd/api; schemacheck; SECURITY-DEFINER + outbound-HTTP CI guards; build + vet clean. DORMANT: no windows/flags set by default; the resolver returns secure defaults, so behavior is unchanged until an admin acts.

**Deferred (slice B / later, non-blocking):** flag/audit READ endpoints (list flags, config-audit history) for the settings UI; true SLA clock-pause with deadline recomputation (current M-2 semantics = breach-notification defer, which is what customers want during planned maintenance — a full deadline-extension is a future refinement); notification-suppression at the dispatcher (needs a severity column on `notification_outbox`; M-2's SLA-pause consult is the higher-consequence half and is now live).

### 🔴→✅ Reviewer landing round: H-1 (High) FIXED (HEAD 52f64b4, migration 0075)
**Finding (inverted-severity tell):** `OffboardTenant` — the irreversible total-tenant purge — was gated *weaker* than `ClearLegalHold`, which merely enables deletion. Single padmin + reason; no four-eyes, no lifecycle/retention check; and `tenant_offboard_purge` is SECURITY DEFINER + `session_replication_role=replica` (disables audit-immutability), so every safeguard but the in-function legal-hold check rested on the too-weak caller. A single padmin (mistaken or compromised) could `POST /admin/tenants/{wrongID}/offboard` and wipe a customer's incidents/evidence/audit before export, before retention, with no second person.
**Fix:** (1) `OffboardTenant` takes `approvedBy` + calls `requireElevated` (senior + four-eyes + reason) — parity with `ClearLegalHold`; already raised the HIGH alert. (2) State + retention enforced as **defense in depth inside the SECURITY DEFINER function** (un-bypassable, like the legal-hold check): refuse unless `status='exported'` AND the retention window elapsed; order legal_hold → exported → retention. (3) New `MarkExported` transition + `POST /admin/tenants/{id}/mark-exported` gives a legitimate path to the exported state; `offboard_retention_days` is a per-tenant admin-configurable column (seeded default 30 — a contract term, not a code constant). Probes: OffboardNeedsFourEyes (403), RefusedFromActiveState (409), RefusedBeforeRetention (409), LegalHoldBlocksDelete-under-full-envelope (403), happy path (exported+elapsed+four-eyes → purge+cert). Re-verify report: `outputs/NIRVET_618_H1_REMEDIATION.md`.

---

## Gate — §6.9 Investigation Workbench, Timeline & Entity Graph — slice A — DESIGN REVIEW (pre-code) — Jul 2026

**SRS:** §6.9 INV-001..010 (00_SRS.md lines 912–967, all Must). API contracts API-INV-001..010 (lines 4330–4389) — every one stamped *"Tenant scoped; RBAC/ABAC enforced; audit where material."* War-room detail SCR (line 4056).

**Why this next / why gated hard:** Investigation is the analysts' daily-driver and it composes what is already shipped — but INV-006 (query builder / advanced search) would be the **FIRST user-controlled-predicate surface in the entire backend.** Today every SQL statement is parameterized (`$1..$N`) and there is NO dynamic-query builder anywhere; the only string-built SQL is a fixed column allow-list. A hunt-query engine that lets an analyst compose predicates is therefore the platform's primary new **BOLA / SQL-injection / data-exfiltration surface** — exactly the class the gate-before-code discipline exists to fence. Second-order: INV-007 (audit of queries/exports) is a real gap — the audit middleware audits only mutations and **GET requests are never audited**, so "who queried/exported what" is not currently recorded.

### Grounding — what already exists (DO NOT rebuild; compose these)
- **Entity rollup (INV-003/004 partial):** `entitygraph.Service.Build(tenantID, ref)` — one-hop blast-radius over an opaque string `ref` (alerts→incidents→correlations→one asset). NO typed entity kinds, NO edges as objects, NO pivot. `GET /entities/graph`.
- **Timeline (INV-002 partial):** `incident.TimelineEntry{At, Author, Kind∈note|status|action|evidence, Visibility∈internal|customer, Note}` — a flat case journal. ONE timestamp; no event-time-vs-ingest-time, source, entity, severity, confidence fields. `GET /incidents/{id}` + `/customer-timeline`.
- **Search (INV-006 thin):** `eventstore.Query{From,To,Severity,Search,Limit}` — `Search` is a 4-field ILIKE only, though `NormalizedEvent` carries class/activity/severity/confidence/actor+target_ref/action/outcome/mitre[]/vendor/product/source. `GET /events`. Alerts filter by status; incidents no filter.
- **Data gaps (INV-009 substantially covered — 3 real signals to UNIFY, not build):** `detection.CoverageGaps` (`GET /detections/coverage`), `connector.SilenceSweeper` (US-032 host-silence alerts), `ingestion.NormQuality.Quality` drift (`GET /normalization/quality`).
- **Evidence export:** `evidence.Service` signed (Ed25519) packs that already fold in audit rows, `GET /incidents/{id}/evidence-pack` (senior). **Reusable:** the `WithTenant` RLS envelope, `alert.ListByRef`/`correlation.ListByEntity`, `notify.MintLink/VerifyLink` signing primitive.

### Scope — slice A (the security-critical query/read backbone; §6.9 phased)
The security-load-bearing core. UI (INV-001 unified view) is a designer composition over these APIs (deferred). War-room and notebooks are deferred to their own slices/gates (below).

- **I-1 — Hunt-query / advanced search (INV-006, API-INV-006 `run-hunt-query` + API-INV-001 `search-events`).** THE security crux. A structured, **allow-listed predicate model** over the normalized-event fields: `{all:[pred...], any:[pred...]}`, `pred = {field, op, value}` with `field` from a FIXED registry (class, activity, severity, confidence, actor_ref, target_ref, action, outcome, mitre, vendor, product, source, event_time, ingest_time) and `op` from a fixed set (eq/neq/in/gte/lte/contains/exists). Compiles to parameterized SQL — **bound params ONLY, never string-concatenated user input**; unknown field/op → 400 fail-closed; runs under `WithTenant` so RLS FORCE is the backstop even if a predicate is malformed; bounded result size + time-range + a query-cost ceiling (no unbounded scan, no ReDoS — `contains` is a bound `ILIKE`, not a user regex). Reuses the `eventstore.Query` seam extended.
- **I-2 — Read-path audit (INV-007, closes the GET-not-audited gap).** A read-audit hook (NOT the mutation middleware) records every hunt query (the compiled predicate + row count), entity-graph read, raw-event fetch (API-INV-010 `get-raw-event`), and evidence-subset export (API-INV-007) — who, what, when, how many rows. Sensitive-case queries always audited. Append-only, tenant-scoped.
- **I-3 — Typed entity graph + pivot (INV-003/004, API-INV-002/003 `get-entity-profile`/`get-entity-graph`).** Promote the opaque `ref` to a typed entity (`kind` ∈ user/device/ip/domain/file/process/email/cloud/vuln/ticket/incident + `value`), derive first-class edges from alerts/incidents/correlations/assets/vulns, and support **pivot** = traverse from an entity to its neighbor set (bounded hops). Builds ON `entitygraph.Service.Build`.
- **I-4 — Structured investigation timeline (INV-002, API-INV-004 `get-timeline`).** Extend the timeline model to carry event_time vs ingest_time, source, entity_ref, severity, confidence, and a typed lane (analyst-action / automation-action / customer-comms / evidence-capture) — a forensic multi-field timeline, additive to the existing case journal.
- **I-5 — Data-gap panel (INV-009).** Unify the three existing signals into one `GET /investigation/data-gaps` so an analyst sees "what you are NOT seeing" (detection coverage gaps + silent sources + normalization drift) — prevents false confidence. Mostly aggregation.
- **I-6 — dedicated adversarial round** (the query surface gets a hard BOLA/SQLi/exfil pass).

### Security spine (the gate's headline — must be structural, not documented-and-hoped)
1. **Allow-list, not passthrough.** The query builder compiles from a FIXED field+operator registry to bound-param SQL. Any user string that could reach SQL text is rejected. Unknown field/op/value-type → fail-closed 400. This is the single most important control in the slice.
2. **RLS is the backstop, not the only control.** Every query is *also* tenant-scoped in its own WHERE (defense in depth), but runs under `WithTenant` so a bug in predicate compilation still cannot return another tenant's row (RLS FORCE on nirvet_app).
3. **Bounded cost.** Result cap, max time-range, and a query-cost ceiling are admin-configurable DB records with seeded defaults (no-hardcoding). No unbounded scan; `contains` is a bound `ILIKE`, never a user-supplied regex (no ReDoS).
4. **Read-path audit (INV-007).** The GET-not-audited gap is closed for the investigative surface: hunt queries, entity reads, raw-event fetches, evidence-subset exports are all recorded (who/what/rows/when).
5. **Raw-event access is privileged (API-INV-010).** Raw events carry the most sensitive customer data; `get-raw-event` is role-gated (provider+), audited, and retention-bounded.
6. **Pivot cannot escape tenant.** Entity traversal composes existing tenant-scoped readers; a pivot target is resolved under `WithTenant`, never by trusting a client-supplied cross-tenant ref.

### Deferred to later §6.9 slices (each gets its OWN gate before code)
- **Notebooks (INV-005)** — structured hypothesis/evidence/analysis/decision/next-action sections; low security risk (tenant-scoped structured storage); slice B.
- **Saved views + shareable internal links (INV-008)** — **has a real security surface**: a shareable link is a capability, so when built it must be tenant-scoped + signed + expiring + authz-checked at redemption (reuse `notify.MintLink`, but a link must NEVER widen scope or leak cross-tenant). Deferred to its own gate.
- **War-room / realtime (INV-010)** — no websocket/SSE exists today and there is no per-incident room-membership model (incidents have a single OwnerID). This needs a NEW transport with its own auth design: per-incident membership, tenant-scoped subscription, no cross-tenant event leakage on the live stream. Highest-net-new; its own dedicated pre-code gate.
- **`create-finding` / `link-related-case` (API-INV-008/009)** write contracts — fold into casework; slice B.

### Reviewer pre-code asks (confirm before I-1)
- Endorse **allow-list-compiles-to-bound-params** as the query model (vs. any DSL that could reach raw SQL), and that RLS-under-WithTenant is the mandatory backstop.
- Confirm the **read-path audit** belongs in slice A (paired with the query engine) rather than deferred.
- Confirm slice-A scope (I-1..I-5) vs. deferring war-room + saved-links + notebooks to their own gates — i.e. that the security-critical core is the query/audit/entity/timeline/data-gap backbone, and the net-new-transport (war-room) and capability-link (saved-links) surfaces each warrant their own gate.
- Any must-adds in the query-surface family (query-cost ceiling, sensitive-field masking in results, per-role field visibility) to fold structurally before code.

**→ Awaiting reviewer pre-code pass. No code until greenlit; then build I-1..I-6 test-first, dedicated adversarial round on the query surface at landing.**

### ✅ LANDED — §6.9 Investigation slice A complete (HEAD a30f961, migration 0076), awaiting reviewer landing round
- **I-1 hunt-query** (INV-006) — allow-list→bound-params; all 5 must-adds folded (code-owned registry, type-aware ops, per-field min-role/mask seam, predicate cap + no nesting, cost ceiling on the indexed observed_at). Proven: hostile value/field/op/`in`-member never reach SQL text.
- **I-2 read-path audit** (INV-007) — fail-closed one-row-per-execution; extended to entity/timeline reads.
- **I-3 typed entity graph + pivot** (INV-003/004) — code-owned kind allow-list; pivot derives neighbors from the tenant's OWN alerts (cross-tenant pivot isolation proven).
- **I-4 structured forensic timeline** (INV-002) — the additive event lane (event-vs-ingest time, source, entity, severity, confidence, outcome), built on the I-1 engine.
- **I-5 data-gap panel** (INV-009) — unifies detection coverage gaps + host-source silence (new tenant-scoped reader) + normalization drift.
- **I-6 adversarial round** — hostile field/op/`in`/exists all fenced; limit clamped; cross-tenant disproven.
- Evidence: 23 tests (query/entity/timeline/data-gap + 5 adversarial + RLS-isolation integration), schemacheck, SECURITY-DEFINER guard, build+vet clean, 76/76 from zero. Report: `outputs/NIRVET_69_INVESTIGATION_SLICE_A_LANDING.md`.
- Deferred to their own gates: notebooks (INV-005), saved-views/shareable-links (INV-008), war-room realtime (INV-010).

---

## Gate — §6.13 Reporting, Dashboards & Evidence Packs — slice A — DESIGN REVIEW (pre-code) — Jul 2026

**SRS:** §6.13 REP-001..010 (00_SRS.md lines 1150–1206, all Must). Non-functional: "Report generation shall be asynchronous for large reports" (line 2171); "Report templates and scheduled reports shall validate tenant scope at generation time AND delivery time" (line 2261). API row: line 424.

**Why gated (the security surface, exactly as the reviewer pre-loaded it):** reporting renders **untrusted tenant data into documents that open on someone else's machine**. That inverts the usual trust boundary — the output IS the attack vector. Four concrete classes:
1. **Formula / CSV injection (XLSX + CSV)** — a cell value beginning `=`, `+`, `-`, `@`, or a control char (TAB/CR/LF) is interpreted by Excel/Sheets as a *formula* on open (e.g. `=cmd|...`, `=HYPERLINK(exfil)`, `=WEBSERVICE(internal)`). The attacker is any actor who can get a string into an event/alert/incident field that lands in an export cell. This is the load-bearing control for tabular formats.
2. **Template injection (DOCX/PDF templates)** — a template engine that evaluates expressions turns tenant data into code execution / data disclosure. Must be a logic-LESS, data-substitution-only model (no arbitrary eval).
3. **SSRF via document renderers (PDF/DOCX/HTML→PDF)** — any renderer that fetches remote assets (images, CSS, fonts, `<img src>`) from URLs in the data/template can be pointed at internal endpoints / cloud metadata. Renderer must NOT fetch remote resources (embedded-only), or fetch only through netsafe.
4. **Resource exhaustion** — an unbounded report (row/cell/page count, file size, generation time) is a DoS and a memory blowup. Ceilings + async for large (SRS 2171).
Plus the tenant/authorization requirements the SRS states outright: **REP-008** (audit every generation, export, download) and **REP-009** (never export outside permission/tenant scope) with **scope re-validated at delivery time**, not just at creation (SRS 2261).

### Grounding — what exists today (compose / extend; do NOT rebuild)
- `reporting.Service.Summary(tenantID) -> Summary{...}` (~136-line `reporting.go`): a JSON at-a-glance rollup (incident/alert counts, SLAPosture) composed from existing stores under RLS. Route `GET /reports/summary` (provider). **No export formats, no document library, no async job, no report record — all net-new.**
- Reusable: `evidence.Service` (Ed25519-signed evidence packs — the REGULATORY/evidence-pack lineage, already tenant-scoped + audit-folding), the durable `queue` (async generation), the `investigation_query_audit` append-only pattern (REP-008 audit), `incident`/`alert`/`detection`/`asset` readers for content (REP-004 service-review pack), the `WithTenant` RLS envelope, `blobstore` (store the generated artifact), `notify.MintLink` (a signed, expiring, authz-at-redemption download link — reuse rather than invent).
- `go.mod` has NO xlsx/pdf/docx dependency yet — a library choice is part of this gate.

### Scope — slice A (the safe formats + the generation/authorization/audit backbone)
Deliver the export path whose security surface is well-understood and testable, and the generate/scope/audit spine every format needs. Defer the renderer-based formats (their SSRF + template surface gets its own design).

- **R-1 — report record + async generation job (REP-001/002).** A `report` row (tenant-scoped, RLS) with type, params (period/scope/filters), status (pending→running→ready→failed), artifact pointer. Large reports generate ASYNChronously via the existing queue (SRS 2171); small ones may run inline. Report TYPES enumerated as config/data, not a code constant.
- **R-2 — content assembly (REP-003/004).** The monthly service-review pack + summary composed from existing readers (incidents, SLA posture, FP rate, top risks/MITRE, integrations health, open remediation) — all under WithTenant. Every report carries the REP-003 metadata header (data-period, tenant, scope, data-source coverage, limitations, evidence references).
- **R-3 — tabular export: JSON + CSV + XLSX (REP-007 partial) — THE security headline.** A single serializer applies **formula-injection neutralization to EVERY cell** (values starting `= + - @` / TAB / CR / LF are prefixed with `'`), so no code path can emit an un-neutralized cell. CSV via stdlib; XLSX via a pure-Go, no-network library (no renderer, no remote fetch). Watermarking (REP-002) as a data field.
- **R-4 — audit + authorization (REP-008/009).** Append-only `report_audit` (generate / export / download — who, what, format, row count). Tenant scope enforced at generation (WithTenant/RLS) AND re-checked at every download/delivery (SRS 2261); role-gated (senior for sensitive/regulatory exports). Download via a signed, expiring, single-tenant link (reuse notify link signing), authz re-checked at redemption.
- **R-5 — resource ceilings + adversarial round.** Row/cell/file-size/generation-time caps = admin-configurable seeded defaults (no-hardcoding). Dedicated adversarial round: try to land a live formula in a cell, exceed a ceiling, download another tenant's report, or export above role.

### Security spine (must be structural, not documented-and-hoped)
1. **Formula injection neutralized at the serializer** — the ONE place cells are written; every value is sanitized there, so a new report type or field cannot introduce an un-neutralized cell. Unit-proven with `=`, `+`, `-`, `@`, TAB, CR payloads.
2. **No renderer SSRF, no template eval (deferred formats)** — PDF/DOCX are deferred precisely because they need a renderer; when built, the renderer fetches NO remote assets (embedded-only) and templates are logic-less data-substitution. Stated now so the deferral is principled, not accidental.
3. **Tenant scope at generate AND deliver (REP-009 / SRS 2261)** — assembled under WithTenant; every download re-validates tenant + role at redemption (a scheduled/aged report cannot leak if scope changed). RLS-under-WithTenant is the backstop.
4. **Audit every generate/export/download (REP-008)** — append-only, tenant-scoped, one row per action.
5. **Bounded + async** — ceilings are seeded config; large reports run on the queue; the artifact lands in blobstore, never streamed unbounded into memory.

### Deferred to later §6.13 slices (each its OWN gate before code)
- **PDF / DOCX rendering (REP-007 remainder)** — the SSRF + template-injection surface; needs a renderer choice + a logic-less template design. Its own gate.
- **Scheduled delivery + distribution lists (REP-002)** — outbound delivery re-validates scope at send time; reuse the notify outbox; own gate.
- **White-label / MSSP reporting (REP-010)** — partner branding + downstream-tenant scoping; own gate.
- **Regulatory jurisdiction templates (REP-006)** — framework-specific packs; builds on the compliance module; own gate.
- **Approval workflow (REP-002)** — report approval before distribution.

### Reviewer pre-code asks (confirm before R-1)
- Endorse the **serializer-level formula-injection neutralization** (one choke point, every cell) as the tabular-export control, and the **slice-A scope = JSON/CSV/XLSX** with **PDF/DOCX deferred** to their own renderer-security gate.
- Confirm **download via a signed expiring link with authz re-checked at redemption** (reuse notify link signing) + **scope re-validated at delivery** (REP-009/2261) is the right authorization model vs. a direct authenticated GET.
- Confirm **report_audit** (REP-008) belongs in slice A.
- Any must-adds in the export-security family — e.g. filename/path sanitization for the artifact, a hard cell/row cap even in async mode, stripping of active content beyond formulas (e.g. DDE, hyperlinks), or per-format MIME/extension pinning.

**→ Awaiting reviewer pre-code pass. No code until greenlit; then build R-1..R-5 test-first, dedicated adversarial round on the export surface at landing.**

### ✅ LANDED — §6.13 Reporting export slice A complete (HEAD f057d79, migration 0077), awaiting reviewer landing round
- **R-3 serializers (formula-injection defense)** — typed cells; CSV type-aware neutralization (only string cells with a leading =+-@/TAB/CR/LF prefixed; numeric -5 stays -5, refinement #1); XLSX minimal dependency-free writer emits every data string as an INLINE STRING → formula/DDE impossible BY TYPE (refinement #2). JSON native.
- **R-1/R-2 record + generation** — reports table (RLS) + report_limits (seeded caps, nirvet_app SELECT-only); Generate under WithTenant, params tenant-fixed (no scope-widening), REP-004 service-review pack from existing Summary readers.
- **R-4 audit + download** — report_audit append-only (REP-008, generate/download); download is a session-authorized GET (RLS-confined, NOT a bearer link — refinement #3); response hardened: Content-Type pinned + nosniff + CRLF-safe RFC-6266 Content-Disposition + opaque UUID blobstore key (refinement #4).
- **R-5 caps + adversarial** — hard row/cell/byte ceiling BEFORE store, even inline (refinement #5); probes: download-another-tenant (→ not-found), exceed-ceiling (→ refused), CRLF filename strip, formula-in-cell (serializer tests).
- Evidence: reporting suite green (serializer security + generate/download/audit + tenant-isolation + cap + safeFilename), schemacheck, SECURITY-DEFINER guard, cmd/api, 77/77 from zero. Report: outputs/NIRVET_613_REPORTING_SLICE_A_LANDING.md.
- Deferred (own gates): PDF/DOCX rendering (renderer SSRF + template injection), async worker offload for very large reports, scheduled delivery + distribution lists, white-label MSSP, regulatory jurisdiction templates.

---

## Gate — §6.17 Packages, Entitlements, Billing & Commercial Controls — slice A — DESIGN REVIEW (pre-code) — Jul 2026

**SRS:** §6.17 BILL-001..010 (00_SRS.md lines 1387–1443, all Must). "Billing Usage Record" entity (lines 1548, 3799). **This is the LAST §6 domain** — after it lands, all 18 §6 domains have been gated-and-reviewed.

**Why gated (the risk flavor is MONEY + METERING, not injection):** the failure modes here are integrity and fraud. A billing system that lets a tenant under-report its usage, that double-counts on a retry, that lets a tenant edit its own pricing, or that does money math in floats, is broken in a way that costs real money and trust. The five pre-loaded concerns:
1. **Metering integrity** — can a tenant under-report or tamper with its own usage counters? Usage MUST be server-derived from authoritative signals the platform already tracks (ingest bytes, alert/connector/asset/report counts, playbook actions), NEVER client-asserted. There is no tenant endpoint to assert usage. The counter is append-only + auditable.
2. **Usage-event idempotency** — no double-count AND no silent loss. Each metered event carries an idempotency key (the SOAR claim-key / outbox-dedupe pattern) so a retry or replay neither inflates nor deflates the bill. This is the reliability crux — a system that double-counts on retry is as broken as one that drops.
3. **Tenant-scoped financial isolation** — invoices, usage, and plan data are RLS-scoped like everything else; one tenant can NEVER read another's billing. Billing READS are role-gated (a finance/admin role, not every analyst).
4. **Privilege on rate/plan/overage config** — a tenant CANNOT set its own pricing/plan/overage rate; those are platform-admin config, audited (the §6.18 safety-class thinking applied to money — pricing is a `protected`/`immutable`-class surface, admin-only, tenant-immutable).
5. **Margin/overage arithmetic correctness** — money is INTEGER MINOR-UNITS (kobo/cents), never floats; rounding, currency precision, proration, and overage-threshold edges get explicit test vectors.

### Grounding — what exists (extend; do NOT rebuild)
- `billing.Entitlements` (`entitlements` table, mig 0005): per-tenant tier + quotas (events_per_day, max_integrations, retention_days, ir_hours), RLS-scoped. `billing.Service` Get/Set (quota cache, cache-invalidated on Set — R6 lesson), `WithinIngestQuota` (enforces events/day at ingest), `RawCountToday`. Routes: `GET /billing/entitlements` (provider read), **`PUT /billing/entitlements` already padmin-gated** (good posture — a tenant can't raise its own quota).
- **NET-NEW:** a usage LEDGER (metered records), usage rollup/aggregation, packages + rates/pricing, overage detection, invoices/billing lines, margin. No money-typed values exist yet.
- Reusable patterns: the SOAR claim-key / notify-outbox idempotency-key pattern (B-2), the §6.18 protected-class + padmin-only + audited config posture (pricing), the append-only + immutable-trigger audit pattern (investigation_query_audit / report_audit / platform_config_audit), the WithTenant RLS envelope, existing authoritative signals (ingest bytes via billing.WithinIngestQuota's counters, alert/connector/asset counts, report_audit, SOAR action runs).

### Scope — slice A (the money-integrity core; §6.17 phased)
The security-load-bearing pieces — metering integrity + idempotency + pricing privilege + correct arithmetic. Dashboards, MSSP downstream billing, contract lifecycle, and finance-system integration are deferred.

- **B-1 — metering ledger (BILL-002).** Append-only `usage_events` (tenant, metric, quantity, period, source, idempotency_key, created_at) — REVOKE UPDATE/DELETE + immutable trigger. `metric` from a CODE-OWNED enum (log_volume, alert_count, storage, connector_count, asset_count, report_count, api_usage, playbook_actions, ps_hours). Every record has an idempotency key UNIQUE per (tenant, metric, key) so a replay/retry is a no-op (crux #2).
- **B-2 — server-derived recording (metering integrity, crux #1).** A `RecordUsage(ctx, tenant, metric, qty, idemKey)` API called ONLY by internal platform code from authoritative signals (never a tenant-facing endpoint) — so a tenant cannot assert or suppress its own usage. Wire the cheapest authoritative sources first (ingest volume, report count, playbook actions), each with a deterministic idempotency key.
- **B-3 — packages + rates as platform-admin config (BILL-001, crux #4).** `billing_package` + `billing_rate` (per metric, integer minor-units, currency) — platform-admin-only writes (padmin), tenant-immutable, audited (`billing_config_audit`, append-only). A tenant assignment to a package is padmin, not self-service. NO tenant path can change price.
- **B-4 — usage rollup + overage arithmetic (BILL-002/003, crux #5).** Aggregate the ledger per tenant/metric/period; compute billable overage = f(usage − included, rate) in INTEGER MINOR-UNITS with documented rounding + proration + threshold-edge behavior and explicit test vectors. Overage alerts (BILL-003) when usage crosses the contract threshold.
- **B-5 — financial isolation + role-gated reads + adversarial round (crux #3).** All financial tables RLS-FORCEd; billing reads role-gated (finance/admin tier, not every analyst). Dedicated adversarial round: tenant cannot assert/suppress its own usage, cannot set its own rate/plan, cannot read another tenant's usage/invoice, a replayed usage event does not double-count, and money math never uses floats.

### Security spine (structural, not documented-and-hoped)
1. **Server-derived metering only** — `RecordUsage` is internal; there is NO tenant endpoint to write usage. A tenant cannot under-report.
2. **Idempotency key on every usage event** — UNIQUE (tenant, metric, key); a retry/replay is a database-enforced no-op (no double-count, no loss).
3. **Append-only auditable ledger** — usage_events REVOKE UPDATE/DELETE + immutable trigger; the bill is reconstructable + tamper-evident.
4. **Pricing is padmin-only, tenant-immutable, audited** — the §6.18 protected/immutable-class posture applied to rates/plans; no tenant write path to price.
5. **Integer minor-units** — all money is int64 minor-units; a float in a money path is a bug. Test vectors for rounding/proration/overage edges.
6. **RLS + role-gated financial reads** — invoices/usage/plan tenant-scoped; reads gated to a finance/admin role.

### Deferred to later §6.17 slices (each its OWN gate before code)
- **Margin dashboards (BILL-008)** — aggregation/reporting over cost vs. revenue; own gate.
- **Partner/reseller pricing + downstream tenant billing (BILL-007)** — MSSP hierarchy; own gate (ties to TEN hierarchical/MSSP V2).
- **Add-on services + commercial-approval / anti-scope-creep workflow (BILL-004/005/009)** — onboarding/mobilisation fees, minimum commitments, approval gates.
- **Contract lifecycle (BILL-006)** — renewal/suspension/upgrade-downgrade workflows.
- **External finance-system integration (BILL-010)** — later phase per SRS.

### Reviewer pre-code asks (confirm before B-1)
- Endorse **server-derived-only metering** (no tenant usage-write endpoint) + **DB-unique idempotency key** as the integrity + reliability model.
- Confirm **pricing/plan writes stay padmin-only + audited** (protected-class), matching the existing `PUT /billing/entitlements` posture — tenant-immutable.
- Confirm **integer minor-units** as the money type and that slice A carries **explicit arithmetic test vectors** (rounding/proration/overage edges).
- Confirm slice-A scope (B-1..B-5 = the money-integrity core) vs. deferring dashboards / MSSP / contract-lifecycle / finance-integration to their own gates.
- Any must-adds in the money-integrity family — e.g. a period-close/lock so a closed billing period can't get late-arriving mutations, negative-quantity rejection, currency pinned per tenant, or a reconciliation check (ledger sum == rollup).

**→ Awaiting reviewer pre-code pass. No code until greenlit; then build B-1..B-5 test-first, dedicated adversarial round on the metering/pricing surface at landing.**

### Revision — reviewer must-adds folded (pre-code, GREENLIT to build B-1..B-5, reviewer task #44)
All five money-integrity asks confirmed. Five must-adds fold structurally before code — two are load-bearing pins:

- **PIN-1 — period-close is RECORD-DON'T-DROP.** Once a period is invoiced its rollup is immutable, but a late-arriving event must be neither silently applied to the closed invoice NOR dropped (the ledger is append-only; losing a real usage signal is its own integrity failure). So a late event is recorded, marked `late`/out-of-period, and surfaced as an **adjustment to the next OPEN period** — never a silent alteration of the closed one, never a discard. `billing_period` carries a status (open→closed); a usage_event whose period is closed is stamped as an adjustment against the current open period.
- **PIN-2 — per-metric idempotency-key GRANULARITY (the crux).** The unique-key-no-op only works if every discrete increment gets a DISTINCT deterministic key (nothing lost) while a retry of the SAME increment collides (nothing double-counted). Therefore every metric is an append-only **POINT-DELTA summed at rollup — NEVER a mutable running counter** (a cumulative daily snapshot re-recorded higher would be wrongly rejected as a duplicate → under-count). The key formula is pinned PER METRIC in the code-owned metric registry, e.g. `log_volume:<tenant>:<yyyy-mm-dd>` (one delta recorded at day-close), `playbook_action:<run_id>:<step>` (per occurrence), `report_count:<report_id>`, `alert_count:<alert_id>`. Real increments never collide; retries always do.
- **M-3 — negative-quantity rejected.** `usage_events.quantity CHECK (quantity >= 0)`. A negative event is the under-report fraud path. Legitimate credits/adjustments are a SEPARATE padmin-audited mechanism, never a negative usage event any internal caller can emit.
- **M-4 — currency pinned per tenant.** The tenant carries a contract currency; a rate applied to it must match (reject cross-currency); no rollup ever sums mixed currencies (kobo + cents is silent corruption).
- **M-5 — reconciliation (rollup == SUM(ledger)).** A test AND a runtime assertion that the rollup equals the sum of the underlying append-only events, so the aggregate can never drift from the source of truth.

**→ GREENLIT to build B-1..B-5 test-first with PIN-1/PIN-2/M-3/M-4/M-5 folded. Landing round = the money adversarial pass: replay an event (no double-count), emit a negative quantity (rejected), record into a closed period (adjusted-not-dropped), a tenant reading/writing its own rate or another tenant's invoice (denied), and a float anywhere in a money path (must not exist). AFTER §6.17 lands = all 18 §6 domains gated → the WHOLE-PLATFORM PRE-GO-LIVE PASS (owner-endorsed; its own multi-part effort).**

### ✅ LANDED — §6.17 Billing slice A complete (HEAD 04e20f4, migrations 0078+0079) — LAST §6 DOMAIN — awaiting reviewer landing round
- **B-1/B-2 metering ledger** — server-derived (RecordUsage internal, NO tenant usage endpoint → can't under-report); append-only usage_events (REVOKE UPDATE/DELETE + immutable trigger); UNIQUE (tenant,metric,key) = PIN-2 idempotency (replay no-op, distinct increment never lost); CHECK qty>=0 = M-3. PIN-1 record-don't-drop: a late event for a CLOSED period is recorded + adjusted forward (is_adjustment), never mutating the closed invoice, never dropped. Rollup = SUM(ledger) → M-5 reconciliation by construction (no mutable counter).
- **B-3 pricing** — billing_package + billing_rate (integer minor-units) written ONLY from the padmin route (tenant can't price); every change audited (billing_config_audit append-only). AssignPackage pins tenant contract currency to the package (M-4).
- **B-4 arithmetic** — ComputeInvoice: overage = max(0, usage−included) × rate, ALL integer minor-units (no float in any money path); currency mismatch refused (M-4); over-threshold metrics flagged (BILL-003).
- **B-5 isolation + role-gating** — all financial tables RLS-FORCE; pricing writes padmin-only, usage/invoice reads manager-gated (finance/admin, not every analyst). Adversarial round: replay→no-double, negative→reject, closed-period→adjust-not-drop, invoice tenant-isolation, code-owned metric registry, currency-mismatch→refuse, float→structurally-absent.
- Evidence: billing suite 12 green + schemacheck + SECURITY-DEFINER guard + cmd/api + 79/79 from zero. Report: outputs/NIRVET_617_BILLING_SLICE_A_LANDING.md.
- Deferred (own gates): margin dashboards (BILL-008), partner/reseller downstream/MSSP (BILL-007), add-on/commercial-approval (BILL-004/005/009), contract lifecycle (BILL-006), external finance integration (BILL-010).

---

## 🏁 §6 ROADMAP COMPLETE — all 18 §6 domains gated-and-reviewed
With §6.17 landed, every §6 domain has been through the gate-before-code discipline (pre-code design gate → reviewer pass → build test-first → landing round). **Next: the whole-platform pre-go-live pass** (owner-endorsed, reviewer strongly recommended) — the cross-cutting review layer the per-slice rounds structurally cannot substitute for: cross-domain auth flows, the full RLS surface at once, secrets/KMS end-to-end, the actual `-race` full suite on a fresh DB, dependency/supply-chain, deploy posture. Scope it as its own multi-part effort.

---

## Gate — §6.17 Billing — slice B: umbrella billing accounts + billing modes + suspension — DESIGN REVIEW (pre-code) — Jul 2026

**SRS:** BILL-007 (partner/reseller pricing + **downstream tenant billing metadata**), BILL-006 (renewal/contract/payment-terms/**service suspension**/upgrade-downgrade), BILL-005 (prevent silent scope creep). Ties to TEN hierarchical/MSSP. Extends §6.17 slice A (usage ledger + packages/rates + `tenant_billing` + `ComputeInvoice`). Parallel gated track alongside the pre-go-live pass (independent surfaces — they don't block each other).

**The use case (owner):** some tenants are metered but NOT billed directly — their cost is covered under an umbrella contract held by a paying entity above them (e.g. Ministry of Education is a live tenant; the Federal Government is the payer). Admin onboards them without direct billing, marks them covered, and we monitor the FG contract for payment — with the ability to suspend covered tenants if the umbrella payer defaults. Plus a genuinely-free `comp` mode (demo/sponsored/anchor tenants).

### Model
- **`billing_account`** — the payer / contract holder (e.g. "Federal Government of Nigeria"): currency, contract dates, `contract_value_minor`, payment terms, `payment_status` (current | overdue), `account_status` (active | delinquent | suspended). This is where payment monitoring lives.
- **billing modes** on `tenant_billing`: `direct` (tenant pays its own invoice — slice A), `covered` (metered; charges attribute to a `billing_account`; tenant not directly invoiced), `comp` (metered; zero-charge).
- **`tenant_billing.billing_account_id`** (nullable) — for a covered tenant, the account its charges roll up to.
- **account invoice** = the sum of its covered tenants' overage (account-scoped read); the covered tenant's own invoice is informational ("covered by <account>").

### Security spine (builder's 4 + reviewer's 5, merged — must be structural)
1. **The meter is MODE-AGNOSTIC.** `RecordUsage` never branches on billing mode — covered/comp tenants are metered byte-for-byte identically to direct. Mode is applied ONLY at invoice time. ("Not billed" ≠ "not metered": we always need the numbers for the umbrella reconciliation, margin, and abuse detection — a "free" tenant silently costing huge storage must stay visible.)
2. **`billing_mode` AND `billing_account_id` are padmin-immutable + audited.** A tenant can NEVER mark itself covered/comp (dodge payment) or re-parent itself to a different/absent account (attribute its cost elsewhere). BOTH fields are platform-admin-only writes; every change audited (the §6.18 protected-class posture). Self-marking and re-parenting are the two fraud paths and both are closed.
3. **Suspension has a SAFETY dimension — it is NOT a normal SaaS suspend (the reviewer-shaped decision).** For a security platform, "suspend" must NOT mean "stop protecting the customer" — turning off a ministry's monitoring during a payment dispute is a liability, not just a billing lever. **Decision to pin:** `suspend` = restrict ACCESS (portal login / API / report export / new configuration) and flag the account, while INGEST + DETECTION + ALERTING CONTINUE (the security function is never turned off for non-payment). A separate, harder `terminate` (actually stop protecting) is a distinct, more-gated action, out of slice B. Enforcement point: an authenticated-API middleware gate on a suspended tenant — NOT on the ingest/detection path.
4. **The account-level cross-tenant rollup is a DELIBERATELY-WIDENED cross-tenant read = the new BOLA surface (reviewer-shaped).** It is the ONE intentional exception to per-tenant RLS. It MUST be account-scoped: a payer/account principal sees ONLY the tenants covered by ITS account — never all tenants, never another account's. Implemented as an explicit account-membership-scoped read (a SECURITY DEFINER function keyed on account_id that enumerates only that account's covered tenants + REVOKE PUBLIC, or an account-scoped policy), audited — never a raw cross-tenant scan. A covered tenant still sees only itself (never its siblings or the account total).
5. **Account-level suspension is HIGH-BLAST-RADIUS.** It darkens/restricts MANY tenants at once (a whole umbrella of ministries). Gate it like a high-consequence action: senior/padmin + reason + a HIGH alert + audit (four-eyes on the account-suspend given the blast radius, TBD with reviewer); fully reversible the moment payment lands. Per-tenant suspend is lower-blast; account-suspend cascades.
6. **Account currency + contract monitoring + immutable historical attribution.** One currency per account; every covered tenant rolls up in it (reject a covered tenant whose currency ≠ its account — M-4 one level up, no mixed-currency account rollup). Track contract value/dates/payment status so "is the umbrella paying for what they consume?" is answerable. Historical attribution is immutable: a re-parented tenant's already-billed (closed) periods stay attributed where they were (record-don't-drop, one level up).

### Scope — slice B
- **SB-1 — `billing_account`** (payer/contract record) + padmin CRUD + audit. Contract value/dates/payment_status/account_status.
- **SB-2 — modes on `tenant_billing`** (`billing_mode` + `billing_account_id`), padmin-immutable + audited; meter stays mode-agnostic (NO change to RecordUsage). Covered tenant's currency pinned to its account.
- **SB-3 — invoice mode-application**: covered → attribute to account (tenant invoice informational); comp → zero-charge; `ComputeAccountInvoice(account)` = account-scoped sum over covered tenants (BOLA-safe, currency-consistent).
- **SB-4 — suspension semantics** (the safety decision): per-tenant + account-level suspend/reinstate; suspend = restrict-access-keep-protecting; account-suspend high-blast-radius gated + HIGH alert + reversible; the authenticated-API enforcement middleware (ingest/detection untouched).
- **SB-5 — account-scoped rollup read (the BOLA surface)** + dedicated adversarial round.

### Deferred (own gates)
- Reseller/partner **markup pricing** (a partner setting downstream *prices*, not just attribution — the pricing half of BILL-007).
- Margin dashboards (BILL-008), external finance-system integration (BILL-010), add-on services + commercial-approval / anti-scope-creep (BILL-004/005/009), the harder `terminate` (stop-protecting) tier.

### Reviewer pre-code asks (confirm before SB-1)
- Endorse the **suspend = restrict-access-keep-protecting** semantics for a sovereign security platform (vs. go-dark), with a separate harder `terminate` deferred.
- Confirm the **account rollup as an account-membership-scoped read** (SECURITY DEFINER + REVOKE PUBLIC, account-scoped) is the right shape for the one deliberate cross-tenant exception — payer sees only its own covered tenants.
- Confirm **both `billing_mode` and `billing_account_id` padmin-immutable + audited**, and the meter stays mode-agnostic.
- Confirm **account-level suspension blast-radius gating** — senior + reason + HIGH alert + audit; is four-eyes warranted given it darkens multiple ministries?
- Confirm SB-1..SB-5 scope vs. deferring reseller-markup / margin-dashboards / terminate.

**→ LANDED (3324b67, mig 0080). Reviewer greenlit pre-code; all five security-spine asks folded and verified in code:**
- **suspend = restrict-access-keep-protecting** — `AccessGate` middleware on the authenticated provider chain only; ingest/detection never consult suspension (a suspended tenant keeps being monitored). Platform staff (platform_admin/soc_manager) exempt; fail-open on lookup error. Harder `terminate` tier deferred to §6.17 own-gate.
- **account rollup = account-membership-scoped read** — `ComputeAccountInvoice` reads ONLY the account's own covered tenants via `billing_account_tenants(uuid)` SECURITY DEFINER (`REVOKE ALL … FROM PUBLIC` + `GRANT EXECUTE TO nirvet_app`, CI-guarded); a payer can never see another account's tenants or all tenants. Dedicated BOLA test (`TestAccountInvoice_ScopedToOwnTenants`) proves account A's rollup excludes account B's tenants.
- **`billing_mode` + `billing_account_id` padmin-route-only + audited** — written solely from `SetMode` on the padmin router path (`writeConfigAudit` on every change); the meter (`RecordUsage`) never sees mode. A covered tenant is currency-pinned to its account (M-4).
- **account-level suspension blast-radius gating** — `SuspendAccount` requires `auth.IsSenior` + a non-empty reason + raises a **HIGH** platform alert + audit, cascades access-suspend to all covered tenants, reversible. (Kept senior-gate + HIGH-alert + audit rather than hard four-eyes for slice A — four-eyes on account-suspend is a candidate for the §6.17 own-gate if the reviewer wants it at landing.)
- **scope** — SB-1..SB-5 shipped; reseller-markup pricing, margin dashboards, contract lifecycle, add-on/approval, external finance integration, and the harder `terminate` tier deferred to the §6.17 own-gate.

**Verification:** 16 billing tests green (4 new slice-B adversarial + 12 slice-A); SECURITY-DEFINER-revoke guard, outbound-http guard, and schemacheck all green; all 80 migrations apply cleanly from zero on a fresh container DB (`ON_ERROR_STOP=1`). `go build ./...` + `go vet ./internal/billing/...` clean.

**Reviewer landing round (pass-1 cross-domain trace) — one Medium, REMEDIATED:**
- **M-1 (suspension incomplete) — FIXED (59340a3).** `bsuspend` was on the `provider` chain only; the `aiProvider` chain (same roles, tighter AI bucket) bypassed it, so a suspended tenant kept its AI copilot and kept burning AI-gateway spend. Structural fix: a single `interactive(lim, roles…)` factory is now the ONLY builder for every authenticated customer-facing chain, with `bsuspend` baked in — no chain can silently omit the gate (provider/aiProvider/detEng/soarApprover/senior/manager/ssoAdmin + authed all derive from it; only platform-only `padmin` is outside it, and AccessGate exempts platform staff anyway). New regression test `TestAccessGate_ComposedBeforeRoleGate`. billing + cmd/api suites green; full non-race suite 34 ok/0 FAIL.
- **`soc_manager` scope confirmed = provider/SOC-management role** (auth.go:16-17 "provider-side SOC roles"; in `providerRoles`; `auth_test.go`). So the AccessGate management-tier exemption (platform_admin + soc_manager) and the account-invoice BOLA-safety (manager chain = provider-only, no customer principal reaches it) both hold.
- The two hardest spine points held on review: a suspended tenant genuinely keeps being protected (ingest/detection never touch the gate) and the account rollup is BOLA-safe (platform-scoped, account-scoped, REVOKE PUBLIC).

**Reviewer M-1 re-verify (pass-1 cross-domain trace) found a HIGH the M-1 fix introduced — now FIXED (355e34c):**
- **H (suspension breaks keep-protecting) — FIXED (355e34c).** The M-1 chain-collapse put `bsuspend` on `authed`, and `POST /ingest` rides `authed` — so a suspended tenant's **service-account telemetry** (agent/connector/API push) was 403'd → the tenant stopped being monitored. Broke spine #1 (keep-protecting) — the exact suspended-SOC-customer-blind liability; the composition-order test passed over it (covered the fix's shape, not the invariant it endangered). **Structural fix at AccessGate, not the chains:** `auth.Principal` gains a `ServiceAccount bool` marker (set ONLY by the API-key resolver `ResolveAPIKey`; NOT a JWT claim, so a human can't forge it); `AccessGate` exempts machine principals alongside platform-management. Suspension now blocks **interactive human access only**; machine/telemetry flows on ANY chain. Regression test `TestAccessGate_ServiceAccountKeepsFlowing` (suspended tenant's service account → /ingest 200; same-role human → 403). billing + iam + auth + cmd/api green; gofmt clean.
- **Note (reviewer, owner asked re diligence):** this is the 2nd fix-introduced regression (H-1→H-1b; M-1→this) — *why* remediations get re-verified against source, and why the pre-go-live cross-domain passes exist (this only surfaced by tracing billing-suspension × the auth-chain factory × the ingest path together).

**→ ✅ SLICE B CLEARED (reviewer, Jul 10 2026, re-verify of 355e34c clean).** The `ServiceAccount` marker is set in exactly one place (the API-key resolver), unforgeable via JWT (no such claim), and the keep-protecting invariant is genuinely tested (machine telemetry flows on every ingest path while suspended human access is blocked). The suspension control took three rounds to converge (SB → M-1 → High) and converged correctly. Four-eyes on account-suspend: NOT required for a reversible keep-protecting suspension (line is by consequence, not blast radius; reserve four-eyes for a go-dark escalation).

**🏁 §6.17 (both slices) CLEARED → ENTIRE §6 ROADMAP COMPLETE: all 18 domains gated, built, and reviewed. The slice-B arc doubled as the opening of pre-go-live pass 1 (cross-domain authz) and earned its keep — the ingest-suspension regression lived only at billing × auth-chain-factory × ingest, invisible to any per-slice review. Pass 1 continues across the rest of the principal→sensitive-action surface (AI chain, SOAR destructive routes, padmin, umbrella account-invoice cross-tenant read, elevation/break-glass token paths). Reviewer owns passes 1-3,6-7; builder owns pass 4 (`-race` on fresh migrated DB via CI). Expect these cross-cutting passes to surface the MOST findings — that's the pass doing its job, not a build-quality regression.**

---

## Gate — Operator FLEET cross-tenant primitives (READ + WRITE) — PRE-CODE DESIGN REVIEW — Jul 2026

**Context:** Ghana MSSP/operator reframe (`outputs/NIRVET_MSSP_OPERATOR_REFRAME.md` §9–§14). Launch-locked seams **#1 (fleet-scope bounded-read choke point)** + **#3 (cross-tenant write primitive)** — the single place cross-tenant read/write happens for operator/oversight roles. Deployment: single-operator dedicated instance; `operator_id` is V2 (sequential handoff decided). This gate **captures the already-settled design** (§9/§12, owner-decided) and **names its dependencies on pre-go-live pass 1**. It is a **DRAFT to be revised by pass-1 findings, not frozen** — it locks NO new cross-tenant decision ahead of the review that informs it. **No code on the fleet/write primitive until the reviewer's pre-code pass clears this gate.**

### A. Bounded cross-tenant READ primitive (seam #1)
- **One primitive, many scope-resolvers.** A `scope-resolver` maps an authenticated principal → the SET of `tenant_id`s it may read. Resolvers: `platform_admin` → whole instance; operator staff → the fleet (= whole instance today, `operator_id`-filtered later); org-sub-admin → their `org_id` tenant-set; anchor/payer → their account's covered tenants (reuse `billing_account_tenants`); `customer_admin` → {own tenant} (degenerate).
- **BOLA-safe by construction:** the tenant-set is resolved SERVER-SIDE from the principal, NEVER from a client-supplied id. A client-supplied org/account/tenant id is ignored in favour of the principal-derived scope.
- **Mechanism:** the scoped read runs via a **SECURITY DEFINER function** taking the resolved tenant-set and filtering to it (precedent: `billing_account_tenants`), with `REVOKE ALL … FROM PUBLIC` + `GRANT EXECUTE TO nirvet_app` (CI-guarded by `check-security-definer-revoke.sh`). Single-tenant `WithTenant`/RLS is NOT the mechanism here — this is a deliberate, bounded, audited cross-tenant read.
- **Hard cap + mandatory read-audit:** every fleet/scoped read is capped + paginated (≈250-tenant fleet → soak-gate input) and emits a read-audit (actor, resolver, tenant-set size).
- **Posture variant (vendor, §10):** same resolver (whole instance) but a **CONTENT-FREE projection** (counts/ages/ack-status/SLA-clock) with **no code path to alert bodies/telemetry** (metadata-by-construction). Content only via §6.2 PAM break-glass, data-owner-visible.

### B. Cross-tenant WRITE primitive (seam #3, operator-only, HIGHEST-RISK)
- **Target-from-resource:** resolve the target tenant from the RESOURCE being acted on (alert/incident's own `tenant_id`) — never `p.TenantID`, never a client-supplied id.
- **Scope check:** verify target ∈ the operator's fleet scope (the §A resolver).
- **Then `WithTenant(target)`** for the mutation, and **run the FULL existing per-tenant authority chain in the TARGET's context** — the per-target SOAR-authority guardrail: `destructive_enabled`, four-eyes, risk class (§9.5), D5 protected-target — all read from the TARGET tenant's `soar_settings`/policies, never operator-home, never a global operator capability. The primitive does NOT re-implement or short-circuit the chain; it composes with it.
- **Audit:** actor-home scope + target tenant on every cross-tenant write.
- **Invariants (own adversarial round):** operator cannot write outside fleet scope; a forged/mismatched body id cannot redirect the write (target comes from the resource); destructive SOAR resolves + re-checks target AT FIRE TIME not just queue time (reaper/reconciler concurrency, `-race`-covered); firing destructive on a `destructive_enabled=false` target → refused + audited; a pure oversight/posture principal has NO cross-tenant write path at all.

### C. Dependencies on PASS 1 (existing-guard baseline these compose with — reviewer verifying; gate revisable by findings)
- `ScopeToTenant` (platform_admin-or-own) — admin-path tenant guard.
- `WithTenant` / RLS `app.current_tenant` — the single-tenant boundary these primitives deliberately, boundedly cross.
- `auth.Principal.ServiceAccount` marker — machine principals must have NO oversight/fleet scope unless explicitly an operator service account.
- SECURITY DEFINER cohort + REVOKE-PUBLIC CI guard — the new read fn joins it.
- PAM/break-glass (§6.2) + evidence packs (§6.13) — the vendor content-access path.
- **If pass 1 surfaces an issue in any of these (as M-1 did), the primitive design ABSORBS it before code.**

### D. Open design questions for the reviewer's pre-code pass
1. **Scope-resolver shape:** one `fleet_tenants(principal)` returning the tenant-set (dedicated instance ⇒ all `tenant_id`s; `operator_id` filter = V2 seam). Confirm the single-choke-point shape — no scattered "all tenants".
2. **RLS mechanism for a multi-tenant scoped read:** SECURITY DEFINER fn taking a tenant-set (billing precedent) vs a session scope-set GUC. Builder recommends the SD-fn (proven, CI-guarded).
3. **Read cap + pagination** sizing for a 250-tenant fleet (soak-gate input).
4. **Audit schema** for cross-tenant read + write (actor-home, resolver, target, scope-size).
5. **Posture projection** table/columns — guarantee "no code path to content" STRUCTURALLY (separate table/repo, not a filtered view over the content table).
6. **Ordering:** the org-sub-admin resolver needs the `org_id` seam (seam #2) landed first → sequence the `org_id` migration before the org-sub-admin resolver.

**→ Awaiting reviewer pre-code pass (reviewer front-loading pass 1 on the §C baseline threads). No code on the fleet/write primitive until cleared. Parallel builds authorised meanwhile (least-entangled, non-authz seams): `org_id` grouping migration, connector scaffolding (egress/creds/SSRF surface, own gate — not cross-tenant authz), Ghana compliance-pack content (§6.14).**

### ✅ REVIEWER PRE-CODE PASS — GREENLIT (Jul 2026). Full artifact: `outputs/NIRVET_REVIEW_FLEET_WRITE_PRECODE.md`. Fold these 4 MUST-ADDS, then build. (Landing round re-verifies MA-1..4 + per-target-authority against source.)

- **MA-1 (READ — the single highest-risk line):** the cross-tenant read runs through a SECURITY DEFINER fn with RLS **inert inside it**, so that fn's own `tenant_id = ANY($set)` is the ONLY guard. It MUST **fail closed** (empty/NULL scope → ZERO rows, never all — with a dedicated test), the tenant-set MUST be a **bound array param** (`uuid[]`, never string-interpolated), and the fn MUST be **minimal — no business logic inside the definer boundary**. A bug on this line = full cross-tenant breach.
- **MA-2 (WRITE):** evaluate per-target SOAR authority by passing the target tenant as an **explicit `(actor, targetTenantID)` parameter** — do NOT mint a synthetic principal with `TenantID = target` (that carries the operator's privilege into the target and corrupts the audit identity).
- **MA-3 (WRITE):** the cross-tenant write MUST land in the **TARGET tenant's audit trail** (not only the operator's) — the agency sees who contained its endpoint (write-side of data-owner-visibility).
- **MA-4 (POSTURE):** the vendor posture view MUST be a **structurally separate store**, not a filtered view over the content tables — "no code path to content" only holds if content is unreachable from the posture repo.
- **Resolver:** confirmed single-choke-point. **Use the SD-fn; REJECT the set-aware GUC** (a set-aware GUC would force every existing RLS policy set-aware — a blast radius that weakens the single-tenant customer isolation that is the platform's core).

**→ GREENLIT. Builder folds MA-1..4 and builds the fleet/write primitive; syslog-listener gate proceeds in parallel (independent egress/creds surface). Reviewer continues pass 1 on the composed baseline (`ScopeToTenant`/`WithTenant`, `ServiceAccount` marker, SD cohort, PAM/break-glass); fleet/write landing round re-verifies MA-1..4 + per-target authority.**

## Gate — MA-4 Vendor Posture Oversight (Ghana operator seam #4) — PRE-CODE DESIGN REVIEW — Jul 2026

Last of the four launch-locked security-critical seams. Expands the fleet-gate MA-4 must-add ("the vendor
posture view MUST be a structurally separate store … 'no code path to content' only holds if content is
unreachable from the posture repo") into the full pre-code design. This is the accreditation-critical control
(brief §10): the vendor retains **standing HEALTH/POSTURE oversight (metadata-only BY CONSTRUCTION)** so it can
spot a neglected major issue and flag/escalate — but has **NO standing content read**. Content, when genuinely
needed for a disputed claim, is reached only via the **sibling control**: §6.2 PAM **data-owner-visible,
time-boxed, four-eyes, audited break-glass** (its own gate; reviewer pass-1'ing that path now). Standing content
surveillance would FAIL CSA accreditation; this design turns the auditor's hardest probe into a credit.

### Model — what posture IS and IS NOT
- **IS:** a per-tenant **projection of metadata only** — counts + ages + status, no bodies. Candidate columns
  (all derivable from `incidents`/alert *metadata*, never content): open-incident counts by severity; oldest
  open-incident age + mean time-in-stage; unacknowledged / ack-overdue counts (`acknowledged_at`/`ack_due_at`);
  SLA-clock state (breached / at-risk counts from `resolve_due_at`); escalation state; last-activity timestamp.
  **NEVER:** alert/incident titles or descriptions, telemetry, IOCs, entity/host/user names, evidence, raw events.
- **IS NOT:** a filtered `VIEW` over the content tables, and not an on-demand reader of them. A view/join over
  content is a *code path to content* — exactly what MA-4 forbids.

### The crux — the no-import-path invariant (structural, not behavioural)
MA-4's security value is **structural**, so it is locked at the package boundary, not asserted by an output test:
- **The `internal/posture` READ package imports NO content package** — not `alert`, `detection`, `incident`,
  `investigation`, nor any event/normalization/telemetry-ingest package. Its repository reads only its own
  `tenant_posture` table. Content is *unreachable* from the posture read path by construction.
- **CI teeth (modeled on `scripts/check-outbound-http.sh`):** a new `scripts/check-posture-no-content-import.sh`
  runs `go list -deps ./internal/posture/...` and **fails the build** if the transitive dep set contains any
  content package. Greppable, auditable, un-bypassable — the same shape as the SSRF and SD-REVOKE guards.

### Population — push, not pull
Posture is **written TO** by the content side on state transitions (a projection updated when an incident
changes stage / an SLA breach fires [#59] / an escalation routes [#78]) — **never read FROM content on demand**.
Two candidate mechanisms (open question for the pre-code pass — pick the one that keeps the boundary cleanest):
- **(a) Outbox/event:** the content side emits a posture-relevant event; a posture ingester projects it. Zero
  import in EITHER direction (content ↛ posture, posture ↛ content). Strongest boundary; more plumbing.
- **(b) Writer interface:** content packages call a tiny `posture.Projector` write interface. This is a
  content → posture import (acceptable — the forbidden direction is posture → content), keeps the read package
  content-free, less plumbing. The invariant (posture READ ↛ content) holds under either.

### Read authz — vendor posture oversight
- Read by the **vendor `platform_admin` seat** (DISTINCT from the operator-admin seat that transitions to the
  gov cyber org, §6.18). Because the store is **metadata-only by construction**, the read is over `tenant_posture`,
  not content — but it is still a cross-tenant read, so: scope **derived from the authenticated principal** (never
  a client id), **fail-closed** for any non-vendor principal, **read-audited**. Reuse the MA-1 bounded-read
  discipline (principal-derived tenant-set; hard cap) — open question whether via the existing fleet SD-fn or a
  dedicated posture SD-fn.
- **Posture NEVER links through to content.** A "show me the incident behind this count" action is NOT a posture
  feature — it is the break-glass control (separate gate), so the read that reveals content is always the
  data-owner-visible, audited one.

### Scope — slice A
Posture store (`tenant_posture` migration) + population-on-transition + vendor read endpoint + the
no-content-import CI guard + centerpiece tests. **Deferred (own gates):** richer/historical posture trend;
the break-glass content path (reviewer pass-1'ing now); posture-driven auto-escalation beyond the existing
#59/#78 reuse.

### Centerpiece tests
1. **Structural (the strongest proof):** `check-posture-no-content-import.sh` fails if `internal/posture` gains a
   content dependency — proving content is unreachable, not merely unused.
2. **Behavioural:** the vendor posture read returns only metadata columns (no body/title/telemetry field exists on
   the DTO); a non-vendor principal → fail-closed (empty); the read is audited.
3. **Population:** an incident stage change / SLA breach updates the tenant's posture row (projection is live), with
   no content leaking into the posture row.

### Open questions for the reviewer's pre-code pass
1. **Population mechanism:** outbox/event (a) vs writer-interface (b) — which does the reviewer prefer for the
   cleanest, most audit-legible boundary? (Both preserve posture READ ↛ content.)
2. **Vendor read path:** reuse the fleet SD-fn (MA-1) for the cross-tenant posture read, or a dedicated posture
   SD-fn? (Posture is metadata-only, but it is still cross-tenant.)
3. **Vendor scope:** whole-fleet posture for the vendor seat (single-operator instance), or resolver-based like
   the fleet console? (Leaning whole-fleet for the vendor seat, principal-derived + audited.)
4. **Metric set:** is the candidate column list above sufficient for "spot a neglected major issue", and is any
   candidate column secretly content (e.g. does "category" leak sensitivity)? Confirm the metadata/content line.

**→ Awaiting reviewer pre-code pass. No code until greenlit. Builder will then build slice A test-first with the
no-import CI guard as the crux. Nothing pushed; HEAD b992ec5 local.**

## Gate — Bulk Onboarding Factory (Ghana operator launch long-pole) — PRE-CODE DESIGN REVIEW — Jul 2026

The operator can't hand-onboard ~200 MDAs one at a time, so it needs a batch tenant-onboarding path. This is a
LAUNCH-REQUIRED (L) build, not a security-critical seam like the four — but a batch create is exactly where a
single tenant-id mixup becomes N mixups, so the security spine is **secure-defaults-at-creation + no
cross-tenant bleed**, baked in up front (reviewer must).

### Model
A padmin-only endpoint batch-creates N tenants from a list, each **fully isolated and securely defaulted from
the moment of creation**, by REUSING the single-tenant `tenant.Service.Create` secure path per row (NOT a
reimplemented shortcut). Initial human access is the §6.2 invitation flow (task #76) — **never a seeded/default
password** (a shared/derived credential across tenants is the smell this design exists to avoid).

### Security spine (the reviewer must — structural, verified per row)
- **Secure defaults at creation (already true in single-create — the factory must NOT weaken them):**
  `destructive_enabled` OFF (absence of a soar_settings row = off; the factory writes NO soar_settings row),
  authority catch-all `('*','observe')` (fail-closed — nothing auto-runs) via `SeedGovernance`, isolation
  defaults, `status=onboarding`. The factory calls the SAME `Create` (+`SeedGovernance`) per row so defaults
  can't drift between single and bulk paths.
- **No shared/derived secrets across tenants:** each tenant gets its own `uuid.New()` id and its own seeded
  governance rows under its own `tenant_id`; NO cross-tenant key/secret/seed reuse; NO default-password admin
  (initial access = per-tenant invitation link).
- **No cross-tenant bleed in the batch path:** each row's writes are scoped to that row's `tenant_id` — every
  per-tenant seed runs under its OWN `WithTenant(t.ID)`; the batch loop NEVER reuses a tx or GUC across
  tenants. A tenant-id is derived once per row and never mutated mid-row.
- **padmin-only:** the endpoint is platform_admin-gated (the operator onboards its customers).
- **Per-row failure isolation + idempotency:** one bad/duplicate row must NOT abort or corrupt the others;
  each tenant is fully-created-and-seeded OR not-created (no half-provisioned tenant); a re-run of the same
  batch must NOT double-create (idempotency key), so a retried onboarding of 200 MDAs converges.
- **Input validation at scale:** each row's name + tier/isolation enums validated per-row (reuse Create's
  fail-closed enum validation) — a typo in row 30 misconfigures nothing and doesn't ambiguously abort the batch.

### Scope — slice A
padmin `POST /admin/tenants/batch` taking `[{name, sector, country, service_tier, isolation_tier, external_ref}]`;
per-row reuse of `tenant.Service.Create` (identical secure defaults + SeedGovernance); an idempotency key
(external_ref or name) so retries don't duplicate; a per-row result report (created / skipped-duplicate /
failed+reason). **Deferred (own follow-ons):** CSV/file bulk-import + UI; async job for very large batches;
per-sector template packs (framework/policy presets); auto-invitation-at-create (or include as a flag if cheap).

### Centerpiece tests
1. Batch-create N tenants → EACH has the secure defaults: `destructive_enabled` off, authority `('*','observe')`,
   RLS-isolated (a seeded governance row for tenant A is invisible under tenant B).
2. NO cross-tenant bleed: tenant A's seed lands only in A; interleaved/failed rows don't write into a sibling.
3. Idempotent: re-running the same batch (same external_refs) creates no duplicates.
4. Per-row failure isolation: one invalid row (bad enum / duplicate) is reported failed/skipped while the
   valid rows still create-and-seed.
5. padmin-only: a non-padmin principal is refused.

### Open questions for the reviewer's pre-code pass
1. **Idempotency key:** dedup by a required `external_ref` (operator's MDA id), or by `name`? (external_ref is
   more robust to renames; needs a column/unique index.)
2. **Partial-failure semantics:** per-row result report (best-effort continue, my lean) vs all-or-nothing batch
   tx? A single tx for 200 tenants is a long lock + one bad row aborts all — leaning best-effort-per-row.
3. **Batch size cap + sync vs async:** a synchronous cap (e.g. ≤100/req) for slice A, async job deferred?
4. **Invitation at create:** trigger the initial-admin invitation per new tenant now, or leave it a separate
   padmin step (invite flow already exists)?

**→ Awaiting reviewer pre-code pass. No code until greenlit. Reviewer keeps pass 1 on padmin + break-glass in
parallel. Nothing pushed; HEAD ce24ebd local.**
