#!/usr/bin/env bash
#
# check-posture-no-content-import.sh — the CI teeth behind MA-4's "no code path to content" invariant.
#
# The vendor posture store (internal/posture) is a metadata-only projection: it MUST NOT be able to reach
# incident/alert/detection/telemetry CONTENT from its read path. The strongest form of that guarantee is not a
# test that inspects outputs, but a STRUCTURAL one: internal/posture must not IMPORT any content package —
# transitively. If content is not in its dependency closure, content is unreachable, full stop.
#
# This is the read+store package's guard. The PROJECTOR (internal/postureproj) is the deliberate content→posture
# writer and is allowed to import content — it is NOT checked here. The forbidden direction is posture → content.
#
# Mechanism: `go list -deps` prints the full transitive dependency set of a package. We fail the build if any
# content package appears in internal/posture's closure. Stronger than grepping imports (catches indirect deps).
#
# Run from backend/. Exits non-zero (and prints the offending dependency) on any content dep.
set -euo pipefail

MOD='github.com/ArowuTest/nirvet'

# Content / telemetry-body packages the posture store must never be able to reach.
CONTENT='alert|incident|detection|investigation|correlation|normalization'
forbidden="^${MOD}/internal/(${CONTENT})(/|$)"

deps="$(go list -deps ./internal/posture/... 2>/dev/null || true)"
if [ -z "$deps" ]; then
  echo "check-posture-no-content-import: could not list deps for ./internal/posture/... (build error?)" >&2
  exit 1
fi

offenders="$(echo "$deps" | grep -E "$forbidden" || true)"
if [ -n "$offenders" ]; then
  echo "MA-4 VIOLATION: internal/posture must not import any content package, but its dependency closure includes:" >&2
  echo "$offenders" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "The posture store is metadata-only by construction. If a count needs new content-derived data, compute it" >&2
  echo "in the projector (internal/postureproj) and pass SCALARS into posture.Record — never import content here." >&2
  exit 1
fi

echo "check-posture-no-content-import: OK — internal/posture reaches no content package."
