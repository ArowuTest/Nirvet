#!/usr/bin/env bash
# §6.12 AI Governance — the eval suite must cover every AI-008 safety category (M-1). A category can be a silent
# gap in three places: the DB CHECK constraint, the seeded golden cases, and the Go EvalCategories set. This fence
# fails the build unless all five categories appear as (a) a SEEDED case in migration 0120 and (b) a Go constant.
# Mirrors scripts/check-playbook-actions-cataloged.sh. Run from backend/.
set -euo pipefail

MIG="migrations/0120_ai_governance.sql"
GO="internal/ai/governance.go"
CATS=(grounding hallucination prompt_injection tenant_leakage unsupported_claim factual)

fail=0
for c in "${CATS[@]}"; do
  # A seeded case has the category as an INSERT VALUES literal: ...,'<name>','<category>',... — require it to
  # appear at least TWICE in the migration (once in the CHECK list, once as a seeded case value).
  n=$(grep -o "'$c'" "$MIG" | wc -l | tr -d ' ')
  if [ "$n" -lt 2 ]; then
    echo "FAIL: AI-008 category '$c' is not seeded as an eval case in $MIG (found $n occurrence(s), need >=2)"
    fail=1
  fi
  # The Go EvalCategories set must define it (as a Capability-style const value).
  if ! grep -q "\"$c\"" "$GO"; then
    echo "FAIL: AI-008 category '$c' has no Go constant in $GO"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "AI-008 eval-category coverage is incomplete — add the missing seed case / constant before shipping."
  exit 1
fi
echo "OK: all ${#CATS[@]} AI-008 eval categories are seeded and defined."
