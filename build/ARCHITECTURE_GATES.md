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
