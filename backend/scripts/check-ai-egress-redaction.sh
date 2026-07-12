#!/usr/bin/env bash
#
# check-ai-egress-redaction.sh — CI teeth behind #188's AI-egress redaction chokepoint.
#
# Customer telemetry may leave the sovereign platform to a third-party LLM ONLY through
# Service.completeExternal (internal/ai/service.go), the single function that redacts (mask-by-default) BEFORE
# calling a Provider's Complete. A new AI feature that calls prov.Complete(...) directly would egress raw
# customer PII/secrets, bypassing the Redactor. Rather than rely on convention, this fence FAILS the build if a
# Provider's Complete method is CALLED anywhere in the ai package except inside completeExternal.
#
# Method DEFINITIONS ") Complete(" (the interface + provider impls) are not calls and are ignored — the fence
# matches the CALL form ".Complete(ctx", which appears only where a resolved Provider is invoked.
#
# Run from backend/. Exits non-zero listing any forbidden egress call.
set -euo pipefail

cd "$(dirname "$0")/.."

# Provider-invocation CALL form (not a definition, which is ") Complete(").
PATTERN='\.Complete\(ctx'

# Every such call in non-test ai code, as "path:line:...".
calls="$(grep -rn -E "$PATTERN" internal/ai --include='*.go' 2>/dev/null | grep -v '_test\.go:' | sed 's#^\./##' || true)"

# The ONLY allowed call site is service.go (the completeExternal chokepoint). Assert (a) every call is in
# service.go and (b) there is exactly ONE — a second call, even in service.go, means a new egress path that must
# instead route through completeExternal.
offenders="$(echo "$calls" | grep -vE '^internal/ai/service\.go:' || true)"
count="$(echo "$calls" | grep -cE '.' || true)"

if [ -n "$offenders" ]; then
  echo "AI-EGRESS VIOLATION (#188): a Provider's Complete is called outside the completeExternal chokepoint:" >&2
  echo "$offenders" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "Route all LLM egress through Service.completeExternal so the Redactor masks customer data first." >&2
  exit 1
fi

if [ "$count" != "1" ]; then
  echo "AI-EGRESS VIOLATION (#188): expected exactly ONE Provider.Complete call (in completeExternal), found ${count}:" >&2
  echo "$calls" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "Every LLM egress must go through the single completeExternal chokepoint (mask-by-default before send)." >&2
  exit 1
fi

echo "check-ai-egress-redaction: OK — LLM egress flows only through the completeExternal redaction chokepoint."
