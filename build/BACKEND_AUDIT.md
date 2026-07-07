# Nirvet backend audit — Jul 2026

Champion-dev review of the scaffold backend against the SRS, backlog (E01–E09), and ADRs. Severity: **P1** = correctness/security, **P2** = efficiency/consistency, **P3** = polish. Status updated as fixed.

## Resolution status (Jul 2026) — ✅ all P1/P2 addressed

- **A [P1] duplicate alerts** — FIXED: `StoreRaw`/`EventStore.Append` report inserted-count; enqueue + detect only on new events; alert idempotency key `(tenant_id, dedupe_key=event_id:rule_id)`. Verified: re-ingest holds alert count steady.
- **B [P1] login index** — FIXED: `users (lower(email))` + case-insensitive lookup. **[P2] enum integrity** — FIXED: CHECK constraints on severity/status/stage/role/tier (verified: bad severity rejected).
- **D [P1] audit coverage** — FIXED: `audit.Mutations` middleware records every successful authenticated mutation (verified in `audit_log`). **[P1] rate limiting** — FIXED: token-bucket per-IP (login) + per-principal (API) (verified: 429s) + per-tenant ingest quota (billing).
- **D [P2] validation** — FIXED: severity/password/body-size limits.
- **C [P2] events module / incident tx** and **B [P2] trigram search** — deferred (noted; low value pre-ClickHouse).
- **F breadth modules** — all 9 now real & verified (detection, connectors, SOAR, AI, threatintel, reporting, compliance, billing, notify).

## Verdict (original)

The foundation is sound and the value loop + RLS isolation are correct. There is **one real correctness bug (duplicate alerts on re-ingest)**, several **indexing/efficiency gaps**, incomplete **audit coverage** and **no rate limiting** — all fixable. Patterns are consistent. Below is the actionable list.

## A. Correctness & idempotency

- **[P1] Duplicate alerts on re-ingest.** `ingestion.Ingest` stores raw with `ON CONFLICT DO NOTHING` but **always** enqueues a normalize job. On a duplicate ingest the event is de-duped (no dup event) but detection re-runs → a second alert. At-least-once job delivery has the same effect on retry. → **Fix:** `StoreRaw` and `EventStore.Append` report whether a row was newly inserted; enqueue only when raw is new, and run detection only when the event is new. Add alert idempotency key `(tenant_id, event_id, rule_id)`.
- **[P2] Two transactions for `GET /incidents/{id}`** (Get + Timeline each open their own `WithTenant` tx). → combine into one read tx.
- **[P3] No refresh-token flow** (config has RefreshTTL, only access tokens issued). Acceptable for MVP; note.

## B. Data model — indexing, constraints, efficiency

- **[P1] Login is unindexed.** `auth_find_user_by_email` filters `WHERE email = $1`, but `users` only has `UNIQUE(tenant_id, email)` — email is the 2nd column, so a lookup by email alone can't use it. → **Fix:** add `CREATE INDEX ON users (lower(email))` and match the function.
- **[P2] No enum integrity.** `severity`, `status`, `stage`, `role`, `isolation_tier` are free-text with no `CHECK`. A typo (`"crit"`) silently bypasses detection. → add `CHECK` constraints / normalization.
- **[P2] Event free-text search is a seq scan** (`class_name ILIKE '%x%'` leading wildcard). Fine at MVP scale; the ClickHouse move (ADR-0002) resolves it. Add a `pg_trgm` GIN index if we keep Postgres search past MVP. Noted, not fixed now.
- **[P3] `MaxConns=10` hardcoded**; make pool size configurable.
- Indexes already correct & tenant-leading: events`(tenant_id,observed_at)`, alerts`(tenant_id,status,created_at)`, incidents`(tenant_id,created_at)`, audit_log`(tenant_id,at)`, ingest_jobs`(state,run_at)`, timeline`(incident_id,at)`, unique dedupe keys on events/raw_events. ✓

## C. Consistency & patterns

- **DB layer uses `pgx` (not GORM) — deliberate.** For a SOC ingesting GB/day, GORM's reflection + opaque SQL is a liability; hand-written SQL keeps the hot path fast and auditable, and RLS needs explicit `SET LOCAL` tenant context per tx. entity→repo→service→handler layering is applied consistently across tenant/iam/alert/incident/ingestion. ✓
- **[P2] `events` has no domain module** — querying lives in `ingestion.Handler`. → extract an `events` module (handler/service over the EventStore) for consistency.
- **[P3] Cross-module tx** for promote is handled cleanly via a callback (incident→alert). ✓

## D. Security

- **[P1] Audit coverage is incomplete.** Only `auth.login` is audited. NFR-003 requires audit on **every** admin/analyst/SOAR action. → add `audit.Record` to tenant.create, user.create, alert.assign, incident.promote/note/close, ingest, and all new SOAR/connector actions.
- **[P1] No rate limiting.** No brute-force protection on `/auth/login`; no per-tenant ingest cap (ADR-0003 requires quota/backpressure; `billing.WithinIngestQuota` is an unwired stub). → token-bucket middleware (strict per-IP on login; general per-principal) + per-tenant ingest quota.
- **[P2] Weak input validation.** No password policy; severity not validated; no request body size limit. → add.
- **Isolation is correct** — RLS `FORCE` + non-owner role + `SET LOCAL`; verified live across 2 tenants. GET handlers are read-only (no aborted-tx footgun). ✓
- **[P3] Ingest auth** uses the caller's tenant; real ingestion needs per-source API keys / connector identity → delivered by the connectors work (E09 source auth).

## E. MVP completeness vs backlog (E01–E09)

| Epic | Built | Gap to close |
|---|---|---|
| E01 Tenant mgmt | create/list/get | service-tier update, escalation contacts |
| E02 IAM/RBAC/SSO | RBAC ✓ | **MFA, SSO** (deferred — need IdP; stub + flag) |
| E03 Ingestion/normalise | ✓ (dedup, DLQ) | idempotency fix (A) |
| E04 Alert queue | list/assign/promote | manual severity change endpoint |
| E05 Incident case | create/timeline/notes/close | tasks/actions richer than notes |
| E06 Evidence & audit | raw+hash ✓ | **export audit** endpoint, retention |
| E07 Portal & reporting | analyst console | monthly report (reporting module), approval workflow |
| E08 Microsoft connectors | descriptors only | real puller framework (connectors work) |
| E09 Collectors | webhook/api ✓ | **syslog listener**, source auth |

## F. Breadth modules — to implement for real (currently interface+stub)

detection (real rule engine, wired), connectors (framework + syslog + vault-persisted creds), soar (playbooks + approvals + authority-to-act), ai (Claude gateway + guardrails), threatintel (watchlist + enrichment), reporting, compliance, billing (quota enforcement), notify (channels + approval-gated sends).

## Execution order

1. Idempotency fix (A) → 2. Indexing + enum constraints + events module (B/C) → 3. Audit coverage (D) → 4. Rate limiting + validation + ingest quota (D) → 5. Breadth: detection → connectors → soar → ai → threatintel/reporting/compliance/billing/notify → 6. Migrations, build/vet, live re-verify, docs.
