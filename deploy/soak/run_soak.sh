#!/usr/bin/env bash
#
# A2 value-loop soak runner — the ONE command to run the full go-live scale gate the moment a load env exists.
# It drives the REAL ingest → normalize → detect → correlate → alert → incident loop (not a synthetic HTTP ping)
# via the gated soak tests in internal/integrationtest, at the 250-agency spec, and captures a timestamped report.
#
# PREREQUISITE (the only thing that isn't code): a dedicated, migrated, PAID-tier Postgres — NOT prod (a volume
# soak pollutes tenant data slated for pre-go-live wipe). Point NIRVET_TEST_DATABASE_URL at it. See
# backend/build/SOAK_GATE_REPORT.md "Coverage / what's still open".
#
# Usage:
#   NIRVET_TEST_DATABASE_URL='postgres://…/nirvet_soak?sslmode=require' bash deploy/soak/run_soak.sh
#
# Every knob has a full-spec default; override any via env. Defaults target the reviewer's spec
# (250 tenants / sustained window). Dial them DOWN for a smoke run, UP (DURATION=48h) for the endurance gate.
set -euo pipefail

if [ -z "${NIRVET_TEST_DATABASE_URL:-}" ]; then
  echo "FATAL: NIRVET_TEST_DATABASE_URL must point at a migrated, dedicated (non-prod) load Postgres." >&2
  echo "       Run migrations first:  NIRVET_MIGRATE_DATABASE_URL=\$DSN go run ./cmd/migrate  (from backend/)" >&2
  exit 1
fi

# ---- full-spec knobs (override any via env) ----
export NIRVET_SOAK=1
export NIRVET_SOAK_TENANTS="${NIRVET_SOAK_TENANTS:-250}"           # the 250-agency estate
export NIRVET_SOAK_EVENTS_PER_TENANT="${NIRVET_SOAK_EVENTS_PER_TENANT:-40}"
export NIRVET_SOAK_CONCURRENCY="${NIRVET_SOAK_CONCURRENCY:-16}"    # ingest burst width
export NIRVET_SOAK_DRAIN_WORKERS="${NIRVET_SOAK_DRAIN_WORKERS:-1,2,4,8}"  # horizontal-scale sweep
export NIRVET_SOAK_DURATION="${NIRVET_SOAK_DURATION:-30m}"         # endurance window — set 48h for the full gate
GO_TIMEOUT="${NIRVET_SOAK_GO_TIMEOUT:-72h}"                        # test binary deadline (must exceed DURATION)

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="$ROOT/backend"
REPORTS="$ROOT/deploy/soak/reports"; mkdir -p "$REPORTS"
STAMP="${SOAK_STAMP:-$(date +%Y%m%dT%H%M%S)}"
REPORT="$REPORTS/soak_${STAMP}.txt"

{
  echo "=== Nirvet A2 value-loop soak — $STAMP ==="
  echo "spec: tenants=$NIRVET_SOAK_TENANTS events/tenant=$NIRVET_SOAK_EVENTS_PER_TENANT concurrency=$NIRVET_SOAK_CONCURRENCY drainWorkers=$NIRVET_SOAK_DRAIN_WORKERS duration=$NIRVET_SOAK_DURATION"
  echo "db: ${NIRVET_TEST_DATABASE_URL%%\?*} (query params hidden)"
  echo
} | tee "$REPORT"

# Run the three soak tests in one binary invocation. -v surfaces the per-cycle/per-worker t.Log lines the
# reviewer verifies; -count=1 defeats the test cache; -p 1 keeps them from sharing the queue table concurrently.
cd "$BACKEND"
set +e
go test -run 'TestValueLoopSoak|TestValueLoopDrainScaling|TestValueLoopSustainedSoak' \
  -v -count=1 -timeout "$GO_TIMEOUT" ./internal/integrationtest/ 2>&1 | tee -a "$REPORT"
RC=${PIPESTATUS[0]}
set -e

echo | tee -a "$REPORT"
if [ "$RC" -eq 0 ]; then
  echo "=== A2 SOAK RESULT: PASS === (report: $REPORT)" | tee -a "$REPORT"
else
  echo "=== A2 SOAK RESULT: FAIL (rc=$RC) === (report: $REPORT)" | tee -a "$REPORT"
fi
exit "$RC"
