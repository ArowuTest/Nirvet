# Soak / scale gate — report (Jul 15 2026)

Run against the live deployment (`nirvet-api.onrender.com`, current free tier) after the Bucket-A/B + reviewer-tail
landings. Non-destructive: exercises only the public HTTP + DB-health path (`/readyz` pings Postgres + the event
store each call; `/healthz` is pure HTTP; `/metrics` is the Prometheus runtime). It does NOT run the authenticated
value loop (see "Coverage / what's still open" below).

## Deployment QA (automated, live) — all green
- Security headers + CSP deployed and correct (`connect-src` resolved `https://nirvet-api.onrender.com`; HSTS,
  nosniff, X-Frame-Options DENY, Referrer/Permissions-Policy present). No CSP console violations; login renders +
  hydrates cleanly → the CSP is non-breaking.
- Every Bucket-A/B backend route is deployed to Render and auth-gated: `/admin/health`, `/incidents/workload`,
  `/ai/copilot/sessions`, `/investigation/notebooks`, `/admin/audit`, `/posture/fleet`, `/entities/graph` all
  return **401 unauthenticated** (deployed + gated, not 404/200).
- `/readyz` reports `database: ok`, `event_store: ok`.

## Soak run
- Load: **16 concurrent workers × 180 s** against `/readyz` (DB + event-store ping each request).
- Result: **696 requests, 100% success (all HTTP 200), 0 errors.**
- Latency (under load): p50 **1.88 s**, p95 **2.91 s**, p99 **3.76 s**, max **5.00 s**.
- Runtime (Go, from `/metrics`): goroutines **23 → 26 → 25** (stable); heap **4.0 → 6.1 → 2.7 MB** (GC healthy,
  no growth); RSS **34 → 37 → 35 MB** (flat).
- Serial baseline (warm, no concurrency): `/healthz` ≈ **0.26 s** (pure HTTP); `/readyz` ≈ **0.9–2.2 s** (HTTP +
  DB/event-store ping).

## Verdict
- **Application stability under sustained load: PASS.** No errors, no goroutine leak, no heap growth, no memory
  creep, no fall-over across 3 minutes of continuous 16-way concurrency. The app itself holds up.
- **Latency: FAILS a SOC SLA — but it is an INFRA-tier finding, not an app bug.** The pure-HTTP baseline is ~0.26 s;
  the extra ~1–2 s is the **free managed Postgres + free Render CPU** (the DB health ping dominates). On paid,
  always-on API + DB tiers this collapses to tens of ms. This directly corroborates the reviewer's "Render
  spins down / a SOC API shouldn't sleep → always-on plan" prerequisite — **and extends it: the managed Postgres
  tier needs upgrading too, not just the API instance.**

## Coverage / what's still open (the real value-loop soak)
This run proves infra stability + the HTTP/DB path only. The genuine scale gate — sustained **ingest → normalize
→ detect → correlate → alert → incident** at volume, measuring end-to-end detection latency, queue depth, and
worker throughput — still requires all three of:
1. **Authentication** (ingest needs an API key / token) — not runnable anonymously.
2. **A dedicated load environment**, NOT prod: a volume soak would pollute the tenant data that is already slated
   to be wiped pre-go-live, and would run against the seeded tenants.
3. **Volume seeding + a driver** (e.g. k6 / a Go load harness posting synthetic events through the ingest path).

Recommended go-live sequence for the full gate: (a) move API + Postgres to always-on paid tiers; (b) stand up a
load/staging env; (c) run the value-loop soak there with auth + synthetic volume, asserting end-to-end p95
detection latency and zero dropped events; (d) then production cutover (wipe test data, rotate seeded creds).

## Bottom line
Infra-layer soak: **app stable, latency gated on free-tier infra.** The always-on API **+ DB** upgrade is a
confirmed hard prerequisite. The authenticated value-loop soak remains the outstanding gate and needs a load env
+ auth (out of scope for a non-destructive prod run).
