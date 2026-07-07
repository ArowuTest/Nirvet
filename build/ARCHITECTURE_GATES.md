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

## Next gates (before starting)
- **SAML 2.0 SSO** (§6.2): AuthnRequest + signed assertion validation (XML dsig) — separate gate after OIDC.
- **ClickHouse event store** (ADR-0002 V1): implement the `EventStore` backend; review retention tiering.
- **Dashboards** (UI): only after the above; the API contracts already exist (designer supplies HTML).
