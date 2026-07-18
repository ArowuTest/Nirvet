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

# --- Coverage (P0), not just routing: what flows THROUGH the chokepoint must be redacted. ---
# The single-call-site checks above prove the door is single; they do NOT prove what goes through it is masked.
# The original P0 was raw untrusted content concatenated INSIDE the sanctioned door (a raw `instruction string`
# param appended past the Redactor). These assertions are STRUCTURAL TYPE FACTS (harder to fool than a body
# regex): untrusted content reaches completeExternal ONLY as []string bags the body redacts.
sig="$(grep -nE 'func \(s \*Service\) completeExternal\(' internal/ai/service.go || true)"
if [ -z "$sig" ]; then
  echo "AI-EGRESS VIOLATION (P0): completeExternal not found in internal/ai/service.go" >&2
  exit 1
fi
# Isolate the PARAM list (between completeExternal( and the ) ( that starts the return tuple) so the `string` in
# the return type doesn't cause a false positive.
params="$(echo "$sig" | sed -E 's/.*completeExternal\((.*)\) \(.*/\1/')"
if ! echo "$params" | grep -q 'in egress'; then
  echo "AI-EGRESS VIOLATION (P0): completeExternal must take the typed egress struct, not a raw untrusted param:" >&2
  echo "  - $sig" >&2
  echo "Untrusted content must arrive as []string bags the body redacts — never a raw string that bypasses the Redactor." >&2
  exit 1
fi
if echo "$params" | grep -qE '\bstring\b'; then
  echo "AI-EGRESS VIOLATION (P0): completeExternal carries a raw string param — untrusted content could be sent unredacted:" >&2
  echo "  - $sig" >&2
  echo "Move any per-call content into the egress []string bags (redacted) or the trusted egress.task field." >&2
  exit 1
fi
# The egress bags themselves must be []string (redactable), so a struct field can't smuggle a raw string.
struct="$(sed -n '/^type egress struct {/,/^}/p' internal/ai/service.go)"
for f in evidence history question; do
  if ! echo "$struct" | grep -qE "^[[:space:]]*$f[[:space:]]+\[\]string"; then
    echo "AI-EGRESS VIOLATION (P0): egress.$f must be a []string redactable bag." >&2
    exit 1
  fi
done
# C2 (the deeper trap): the conversation HISTORY bag is all free text, which has no safe structure to preserve, so
# it MUST be redacted with strict/wholesale semantics regardless of the tenant's evidence policy. Assert the
# load-bearing property directly, not a neighbouring one.
if ! grep -qE 'redactLines\(in\.history, strictPolicy' internal/ai/service.go; then
  echo "AI-EGRESS VIOLATION (P0/C2): the conversation history bag must be redacted with the strict (wholesale) policy" >&2
  echo "so a non-pattern identifier (a bare name / short account number) in prior turns cannot egress in cleartext." >&2
  exit 1
fi
# 2b: raw model output must NOT be stored in the broad-access audit_log (it can echo customer PII).
if grep -qE '"output":' internal/ai/service.go; then
  echo "AI-EGRESS VIOLATION (P0/2b): auditMeta must not store the raw model \"output\" in audit_log (keep output_sha256 + output_chars)." >&2
  exit 1
fi

echo "check-ai-egress-redaction: OK — LLM egress flows only through completeExternal, which redacts every untrusted bag (history strict); audit_log stores no raw output."
