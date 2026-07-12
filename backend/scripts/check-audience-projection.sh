#!/usr/bin/env bash
# Customer read-side structural fence (mirrors check-session-mint-single-path.sh / check-connector-decrypt-audit.sh).
#
# The audience-projection invariant (reviewer #2): a customer principal must reach ONLY the readmodel projection
# handler, which can emit nothing but *View / *Rollup projection types. If a provider/domain handler were ever
# wired to the customer-audience route chain, it would serialize a raw internal entity (full incident body,
# internal timeline, detection internals) straight to a customer — the exact over-disclosure this layer prevents.
#
# This fence makes that structural: EVERY route on the `customerRead(...)` chain in cmd/api/main.go must be served
# by the readmodel handler instance `custReadH.*`. Any other handler on that chain fails the build.
#
# Run from backend/.
set -euo pipefail
cd "$(dirname "$0")/.."

# Route registrations on the customer-audience chain: `customerRead(<handler>)`. The chain DEFINITION line
# (`customerRead := interactive(...)`) has a space before `:=`, so `customerRead(` does not match it.
offenders="$(grep -nE 'customerRead\(' cmd/api/main.go | grep -v 'custReadH\.' || true)"
if [ -n "$offenders" ]; then
  echo "❌ AUDIENCE-PROJECTION VIOLATION: a non-readmodel handler is wired to the customerRead chain." >&2
  echo "   Customer routes must serve ONLY readmodel projections (custReadH.*), never a raw-entity handler:" >&2
  echo "$offenders" | sed 's/^/     /' >&2
  exit 1
fi

# Belt-and-suspenders: the customer chain must actually be USED (at least one projected route), so the fence
# can't pass vacuously if the wiring is deleted while the chain lingers.
if ! grep -qE 'customerRead\(custReadH\.' cmd/api/main.go; then
  echo "❌ AUDIENCE-PROJECTION: no customerRead(custReadH.*) routes found — the customer read-side wiring is missing." >&2
  exit 1
fi

echo "✓ check-audience-projection: customer chain serves only readmodel projections"
