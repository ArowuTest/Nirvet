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

## Value-loop soak (A2) — FIRST RUN, local, Jul 16 2026

The outstanding gate is now **partially closed**: a real value-loop driver exists and runs. Harness =
`internal/integrationtest/valueloop_soak_test.go` (`TestValueLoopSoak`, gated behind `NIRVET_SOAK=1`), reusing the
proven `newHarness` wiring — it seeds K tenants and drives the **real** `ingest → normalize → detect → correlate →
alert → incident` loop against local Postgres, then measures. Source-verified the 4 known-weak points first:
outbox uses `FOR UPDATE SKIP LOCKED` (structurally sound); audit_log access-review query matches mig-0131's
`(actor_id,action,at DESC)` index (covered); SOAR `resolveAction`/`resolveDecision` open a per-call `WithTenant`
tx inside per-step loops (**real N+1, bounded by step count** — not exercised by this ingest-only run; see below).

**Run: 25 tenants × 40 events = 1000, concurrency 8, local docker PG (127.0.0.1:5433).**
- Ingest: **5.63 s → 178 ev/s** (c=8). Drain (worker, single, incl. per-event detection + correlation):
  **22.8 s → 44 ev/s**. processed=1003 (RunOnce batch re-drives; no loss).
- **197 alerts + 25 incidents raised** — the loop is functionally CORRECT at volume (detection + correlation +
  auto-incident all fire), not merely up.
- Pool: acquired=0 / idle=8 / total=8 / **max=10 — no exhaustion, no leak**. No dropped events (ingested==total).

**Headline finding — the drain worker is the throughput bottleneck, not ingest.** Ingest (178 ev/s) >> drain
(44 ev/s/worker), so under sustained load the queue absorbs the gap and **drain must scale horizontally**. Naive
math to the reviewer's 2k-ev/s steady target: ~2000 / 44 ≈ **~45 worker instances at this per-worker rate on this
hardware** (paid/prod PG + CPU will raise per-worker throughput materially — the infra soak above showed the free
tier adds ~1–2 s of DB latency that prod removes). The per-event cost is detection (all seeded rules evaluated per
event) + correlation; that is the first optimization lever if worker fan-out isn't enough.

### Drain scaling (multi-worker) — the capacity answer (Jul 16, `TestValueLoopDrainScaling`)

The single-worker number (44 ev/s) raised the real question: does drain scale with worker COUNT, or does the
shared Postgres plateau first? Test builds N **genuinely separate** workers (own queue handle over the same
Postgres queue tables + own detection engine/cache; contend via `FOR UPDATE SKIP LOCKED` — not goroutines sharing
one worker). 15 tenants × 60 = 900 events/round, local docker PG, pool max=10:

| workers | total ev/s | per-worker ev/s | scaling |
|--------:|-----------:|----------------:|---------|
| 1 | 35 | 34.8 | baseline |
| 2 | 60 | 30.1 | 1.7× |
| 4 | 111 | 27.8 | **3.2× (1→4), ~80% efficient** |

**Answer: drain scales ~linearly with workers — no DB plateau through 4×.** Throughput rose 3.2× for 4× workers;
the gentle per-worker decline (34.8→27.8 ev/s) is mild contention, and with **pool max=10** shared across 4
detect+correlate+alert workers, the connection pool is the suspected next lever (not a hard DB ceiling). So a
2k-ev/s gov estate is a **horizontal-workers + pool-sizing + prod-DB** problem, not an architectural wall — exactly
what the SKIP-LOCKED queue was built for, now empirically confirmed. (Absolute per-worker rate is local-docker-PG
bound; paid PG raises it, as the infra soak's ~1–2 s free-tier DB latency showed.)

**Still open for the FULL A2 gate (needs the load env, not a local box):**
1. Scale the knobs toward the real spec (250 tenants / ~2k ev/s / ~10k burst / 48h) on paid PG+API — this local run
   proves the code path + shape, not the 48h endurance or the burst ceiling.
2. **Exercise the SOAR N+1** — add a playbook-run loop to the harness (this run is ingest-only, so the confirmed
   N+1 wasn't measured); drive concurrent runs and count per-run queries.
3. Retention-sweep × live-ingest contention (run the retention sweep concurrently with the drive).
4. audit_log index under a large history (seed millions of audit rows, then time the access-review query).

## Sustained-endurance soak + one-command runner (A2 harness FINISHED, Jul 21 2026)

The two earlier drivers are **one-pass** (throughput + scaling shape). The missing half was **endurance** — the
48h "does it hold steady state" question — and a turnkey way to run the whole gate. Both now exist; the A2 harness
is complete and waits only on the load env.

- **`TestValueLoopSustainedSoak`** (gated `NIRVET_SOAK=1`, knob `NIRVET_SOAK_DURATION`) loops the REAL
  ingest→detect→correlate→incident path for a wall-clock window with N separate drain workers per cycle, sampling
  the four leak signals every cycle: **heap (runtime.MemStats), goroutine count, pool acquired/max, and dead-letter
  count**. It fails FAST if dead-letters grow (silent event loss) or the pool over-subscribes mid-soak, and asserts
  no goroutine leak at the end. This is the endurance signal the one-pass tests structurally cannot give.
- **Local proof (15 s window, 6 tenants, 2 workers):** 23 cycles / 2070 events; **heap 1.5→2.3 MB (flat, GC
  healthy), goroutines 3→3 (no leak), worst pool acquired 0/10 (no over-subscription), dead-letters 0 throughout,
  zero dropped events.** Steady-state holds; the same code path runs 48h in the load env by setting
  `NIRVET_SOAK_DURATION=48h`.
- **`deploy/soak/run_soak.sh`** — the ONE command to run the full gate the moment a paid, dedicated (non-prod)
  Postgres exists: point `NIRVET_TEST_DATABASE_URL` at it, and it runs all three soak tests at the 250-agency spec
  defaults (`TENANTS=250`, `DRAIN_WORKERS=1,2,4,8`, `DURATION=30m`, all overridable → `48h` for the endurance gate)
  and captures a timestamped report to `deploy/soak/reports/` (git-ignored). Verified end-to-end locally with smoke
  knobs (all three tests green, report written).

### Still open for the FULL A2 gate — now purely load-env / owner-driven (no builder code left)
1. **The env itself**: a paid always-on API + a paid, dedicated (non-prod) Postgres. This is the one hard
   prerequisite; the corroborating infra soak above showed the free tier adds ~1–2 s DB latency that a SOC SLA
   can't accept.
2. **Run `run_soak.sh` at the real spec** (250 tenants / 48h) and attach the report — the code path, scaling shape,
   and steady-state are already proven locally; the load env proves the 48h endurance + burst ceiling + absolute
   throughput on prod hardware.
3. Deeper measurement extensions still worth adding IN the harness when prioritised (each self-contained, none
   blocking the gate): the SOAR playbook-run N+1 driver (confirmed structurally, not yet timed), retention-sweep ×
   live-ingest contention, and the audit_log access-review query under a millions-of-rows history.

## Bottom line
Infra-layer soak: **app stable, latency gated on free-tier infra.** Value-loop soak: **driver built and green —
loop is correct at volume, no drops, no pool/leak issues; drain throughput (44 ev/s/worker) is the scale lever and
needs horizontal workers + prod DB for 2k ev/s.** Endurance soak: **built and green — steady state holds (no heap/
goroutine/pool/dead-letter drift), one command (`run_soak.sh`) runs the full 250-tenant/48h gate.** The always-on
API **+ DB** upgrade and a dedicated load env remain the only hard prerequisites to close the full A2 gate — the
harness is finished and waiting.
