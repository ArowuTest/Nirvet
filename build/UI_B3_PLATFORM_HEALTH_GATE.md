# Pre-code gate — B3: Platform health dashboard (§6.18 slice B, UI-depth Bucket B)

**Owner directive:** build backend+UI *gated* for backend-missing items; honest states where a single sovereign
operator makes fleet concepts N/A — **never fabricated nodes/metrics**. This note precedes code per the gated
approach ([[feedback_nirvet_gated_approach]]).

## Problem / SRS grounding
§6.18 (platform administration) asks for a platform-health/infrastructure view. Today only unauthenticated
`GET /healthz` (liveness) and `GET /readyz` (db + event_store dependency probe) and `GET /metrics` (Prometheus
scrape) exist. There is **no authenticated aggregated health read** an operator can render in the console. The
mockups imagine a multi-node fleet (147-tenant cluster, SSH nodes) — that model is the deferred multi-operator
SaaS, **not** the real single sovereign instance. So the honest scope is: *the health of THIS instance and its
dependencies*, not a fictional node fleet.

## Design (what to build)
A thin, read-only, no-persistence aggregation. No migration, no RLS tables touched, no config records.

- **Route:** `GET /admin/health` — **padmin-gated** (operator-only; the existing `/healthz`/`/readyz` stay public
  for load-balancers). Add to `api/openapi.yaml` (parity CI).
- **Package:** `internal/platformhealth` — `Service` + `Handler`, matching entity→(no repo)→service→handler. No
  repo because there is no stored state; the service holds probe funcs + backend-name strings + a start instant.
- **Response (all real, all honest):**
  ```
  {
    "status": "ok" | "degraded",          // degraded if any hard dep (db/event_store) is unavailable
    "checked_at": RFC3339,
    "instance": "single-sovereign",       // explicit: one instance, no fleet — never fake nodes
    "dependencies": [
      {"name":"database",    "status":"ok|unavailable", "detail":""},           // live: db.Health(ctx)
      {"name":"event_store", "status":"ok|unavailable", "detail":"<backend>"},  // live: events.Ping(ctx)
      {"name":"queue",       "status":"configured",     "detail":"<backend>"},  // name only (no ping API)
      {"name":"blobstore",   "status":"configured",     "detail":"<backend>"},  // name only
      {"name":"cache",       "status":"configured|in-memory", "detail":"redis|in-process"}
    ],
    "runtime": {                            // real Go runtime — genuine single-instance operational signal
      "uptime_seconds": int, "goroutines": int, "heap_alloc_bytes": int,
      "num_gc": int, "num_cpu": int, "go_version": string
    }
  }
  ```
- **Honesty rules:** queue/blob have no ping API surfaced → reported as `configured` with the backend name, NOT a
  fabricated `healthy`. `cache` reflects whether Redis is wired (`configured`) or the in-process limiter is used
  (`in-memory`). `instance:"single-sovereign"` is stated so the UI never implies a cluster.

## Invariants / guardrails
1. **No new secrets / no tenant data.** The endpoint reads only process + dependency liveness. It must never
   enumerate tenants or leak per-tenant counts (that is oversight's job, already built + audience-fenced).
2. **padmin only.** Same tier as the other `/admin/*` config reads. A non-padmin 403s → UI shows an access note.
3. **No hardcoding of a "healthy" lie.** A dependency with no live probe is `configured` (truthful), not `ok`.
4. **Cheap + safe.** `db.Health` and `events.Ping` are already used by `/readyz`; reuse them. Runtime stats via
   `runtime.ReadMemStats` / `runtime.NumGoroutine` — no allocation storms (guard with a single ReadMemStats).
5. **OpenAPI parity** (`go test ./api/`) + **gofmt/vet/build** green; no schemacheck/RLS impact (no tables).

## Tests
- `platformhealth_test.go`: (a) status=ok when both probes succeed; (b) status=degraded + dependency
  `unavailable` when a probe returns error (inject stub probes); (c) runtime block is populated (goroutines>0).

## UI (after backend green)
`console/admin/health` (nav: Administration > Platform health): status banner (ok/degraded), dependency table
(name/status/detail with tone), runtime KPI strip (uptime, goroutines, heap, GC), and an explicit
"single sovereign instance — fleet view N/A on this deployment" honest note. Poll/refresh button.

## Out of scope (deferred, honest)
Multi-node fleet, SSH/host infra, cluster autoscaling, per-node CPU — all belong to the deferred multi-operator
model. The UI states this rather than faking it.
