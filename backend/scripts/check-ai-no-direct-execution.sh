#!/usr/bin/env bash
#
# check-ai-no-direct-execution.sh — the crown-jewel fence of S2b: the AI NEVER executes a response action.
#
# The copilot may PROPOSE a response (a data record in ai_response_proposals); a HUMAN promotes an accepted
# proposal into the EXISTING soar RunPendingApproval pipeline, which then runs through the authority gate
# (Allowed(mode,risk)), four-eyes, the D5 crown-jewel guard, and authority_policies. The AI is strictly UPSTREAM of
# those gates and bypasses none. Today this is enforced structurally — internal/ai imports no soar/actioner symbol.
# This fence makes it RECURRENCE-PROOF: a future refactor that wires the copilot to an actioner (directly, or by
# importing the execution packages) breaks CI. Non-negotiable #1 of the S2b gate — a violation = reject.
#
# The AI package may reference the PROPOSAL repo and READ-ONLY readers only. It may NOT reference the soar execution
# surface or import the actioner/execution packages. Structural (grep over internal/ai), matching the sibling
# check-*.sh fences. Run from backend/.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# 1. No reference to the soar EXECUTION surface — the functions that actually run/dispatch a response action.
#    These live in internal/soar (executeRun/RunForTarget/runFor) and the fleet path (FireContainment). The AI may
#    read incident/alert/entity/run-history, but must never call anything that EXECUTES.
EXEC_SYMBOLS='\b(executeRun|RunForTarget|runFor|FireContainment|ApproveForTarget|RunForContainment)\b'
sym="$(grep -rnE "$EXEC_SYMBOLS" internal/ai --include='*.go' 2>/dev/null | grep -v '_test\.go:' | sed 's#^\./##' || true)"
if [ -n "$sym" ]; then
  echo "AI-NO-EXECUTE VIOLATION: internal/ai references the soar EXECUTION surface — the AI must PROPOSE, never run:" >&2
  echo "$sym" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "The copilot writes an ai_response_proposals record; a human accepts it, which creates a RunPendingApproval" >&2
  echo "through the EXISTING soar pipeline (authority gate / four-eyes / D5). The AI must not touch execution." >&2
  fail=1
fi

# 2. No IMPORT of the execution/actioner packages from internal/ai. Importing internal/soar or internal/connector
#    (the actioner registry + vendor actioners) would give the AI a path to execution even without naming the
#    symbols above. The proposal repo + read-only domain readers (incident/alert/entitygraph/…) are allowed.
imp="$(grep -rnE '"github.com/ArowuTest/nirvet/internal/(soar|connector)"' internal/ai --include='*.go' 2>/dev/null | grep -v '_test\.go:' | sed 's#^\./##' || true)"
if [ -n "$imp" ]; then
  echo "AI-NO-EXECUTE VIOLATION: internal/ai imports an execution/actioner package (internal/soar or internal/connector):" >&2
  echo "$imp" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "The AI package may import the proposal repo + read-only readers only — never the soar execution engine or" >&2
  echo "the connector actioners. Promotion of an accepted proposal to a run happens OUTSIDE internal/ai." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-ai-no-direct-execution: OK — internal/ai proposes only; it references no soar execution surface and imports no actioner package."
