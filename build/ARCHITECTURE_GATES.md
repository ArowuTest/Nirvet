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

**Gate checklist.**
- [x] Config shape decided now (this gate) so no other AI feature accretes on the hardcoded gateway.
- [ ] Reviewer confirms the ALLOWLIST-not-block guard framing before code (the one careless-fix trap).
- [ ] Build after SOAR slice C, test-first; reviewer pass on landing (allowlist guard + internal-endpoint-works are the specific checks).

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
- [ ] Build after SOAR slice C, pulled by a concrete sovereign/low-maturity engagement.
- [ ] Reviewer pass on landing (tenant-isolation + silent-source health are the specific checks).

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
