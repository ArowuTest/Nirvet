# Running Nirvet locally

Monorepo: **`backend/`** (Go API + worker + migrations), **`frontend/`** (Next.js console),
**`deploy/`** (docker-compose Postgres). Decisions: [`build/adr/`](build/adr/).

## Prerequisites

Go 1.25+ · Node 20+ · Docker Desktop · (psql optional). All present on the build machine.

## 1. Start Postgres

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Postgres 17 listens on **host port 5433** (chosen to coexist with a local Postgres on 5432).

## 2. Migrate the database

The migrate command connects as a privileged role to create the app role, tables, RLS policies and the
SECURITY DEFINER auth function. The app itself connects as the non-owner `nirvet_app` role.

```bash
cd backend
NIRVET_MIGRATE_DATABASE_URL='postgres://postgres:postgres@localhost:5433/nirvet?sslmode=disable' \
  go run ./cmd/migrate
```

## 3. Run the API (with inline ingest worker in dev)

```bash
cd backend
NIRVET_DATABASE_URL='postgres://nirvet_app:nirvet_app@localhost:5433/nirvet?sslmode=disable' \
  go run ./cmd/api
# → listening on :8080 (set NIRVET_HTTP_ADDR=:8081 if 8080 is taken)
```

On first run it bootstraps a **provider tenant** + **platform admin**:
`admin@nirvet.local` / `ChangeMe123!` (override via `NIRVET_BOOTSTRAP_*`; rotate before go-live).

In production the worker runs separately: `go run ./cmd/worker` (set `NIRVET_INLINE_WORKER=false` on the API).

## 4. Run the frontend

```bash
cd frontend
cp .env.local.example .env.local   # set NEXT_PUBLIC_API_BASE to the API (e.g. http://localhost:8081)
npm install
npm run dev                        # → http://localhost:3000
```

Sign in with the bootstrap admin; the console shows Dashboard / Alerts / Incidents / Events.

## Smoke test (API only)

```bash
B=http://localhost:8081
TOKEN=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@nirvet.local","password":"ChangeMe123!"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
# ingest a critical event -> worker normalizes -> detection raises an alert
curl -s -X POST $B/ingest -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"source":"defender","native_id":"e1","class_name":"Malware","severity":"critical","target_ref":"host:WIN-07"}'
sleep 2
curl -s $B/alerts -H "Authorization: Bearer $TOKEN"       # 1 alert
# promote first alert -> incident, then list incidents
```

## Modules & key endpoints

All authenticated; provider (SOC) roles unless noted. See `cmd/api/main.go` for the full table.

- **Auth/IAM:** `POST /auth/login` (rate-limited), `GET /me`, `POST /admin/users`, `POST/GET /admin/tenants`
- **Ingestion:** `POST /ingest`, `GET /events`, public `POST /ingest/webhook/{id}` (source-key auth)
- **Detection:** `GET/POST /detections`, `POST /detections/{id}/enabled`
- **Alerts/Incidents:** `GET /alerts`, `POST /alerts/{id}/{assign,promote,summarise}`, `GET /incidents`, `POST /incidents/{id}/{notes,close}`
- **Connectors:** `GET/POST/DELETE /connectors`, `GET /connectors/catalogue`
- **SOAR:** `GET /playbooks`, `POST /playbooks/{id}/run`, `GET /soar/runs`, `POST /soar/runs/{id}/{approve,reject}`, `POST /soar/authority`
- **Threat-intel:** `GET/POST /threat-intel` · **Reporting:** `GET /reports/summary` · **Compliance:** `GET /compliance/coverage`
- **Billing:** `GET /billing/entitlements`, `PUT /billing/entitlements` · **Notify:** `POST /notify/test`

## What is verified (live, real HTTP)

- **Value loop:** login → ingest → normalize (worker) → **enrich (threat-intel)** → EventStore → **detection engine
  (rule catalogue)** → alert → promote → incident → note → close. Low/no-match events correctly do **not** alert.
- **Tenant isolation (RLS):** two tenants each see only their own data — zero cross-tenant leakage (non-owner
  `FORCE ROW LEVEL SECURITY` role, SECURITY DEFINER auth/webhook lookups).
- **Idempotency:** re-ingesting an identical event does **not** create duplicate alerts.
- **Security hardening:** rate limiting returns 429 after burst; audit middleware records mutations; enum CHECK
  constraints reject bad input; per-tenant ingest quota.
- **Breadth modules:** connector webhook source-key auth (401/202) + encrypted creds; SOAR run→pending_approval→
  approve→completed under authority-to-act; AI summary (offline fallback or Claude with a key); threat-intel
  enrichment bumps confidence; reporting/compliance/billing endpoints.
- **Build:** 28 Go packages `go build ./...` + `go vet ./...` clean (5 migrations). Frontend `next build` clean.

## Known local caveat (Windows MAX_PATH)

The frontend `next build`/`dev` **fails from this deeply-nested session directory** because Turbopack's `.next`
chunk paths exceed the Windows 260-char path limit. It builds cleanly at a normal path — which it will have once
the repo is cloned to e.g. `C:\dev\nirvet`. Nothing to fix in the code; just don't run the frontend from the
current deep folder.

## Status

Working scaffold — the backend runs. Foundations (multi-tenancy/RLS, ingestion, event store, audit, credential
vault, blob evidence, rate limiting) **and** all engines (detection, SOAR, AI, threat-intel, connectors,
reporting, compliance, billing, notify) are **implemented and verified live** — not stubs. Cloud-portable
(local → Render/Vercel → GCP, ADR-0005), with unit + integration tests, Dockerfiles and CI. **Not production** —
a security architect reviews the final solution before go-live (see [`build/adr/`](build/adr/)). Remaining
foundational work: MFA/SSO, real Microsoft OAuth pull connectors, syslog listener, ClickHouse at V1; UI dashboards
(designer-provided HTML) come after.
