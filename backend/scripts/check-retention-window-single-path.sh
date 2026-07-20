#!/usr/bin/env bash
#
# check-retention-window-single-path.sh — B3 gate 2d. Retention is the ONLY path that DELETES customer telemetry, and
# the jurisdictional clamp (floor/ceiling + legal-hold) must have exactly ONE producer feeding it. A second place that
# computes a window or a cutoff — or a delete fed from anywhere else — is a path that can skip the floor / the arm /
# the legal-hold, i.e. wrongful or over-deletion. This fence makes that structural (mirrors check-authority-single-path
# and check-session-mint-single-path). Run from backend/.
set -euo pipefail

cd "$(dirname "$0")/.."
F=internal/retention/retention.go
fail=0

# Map every matching line to its enclosing top-level func (strip "func " + any receiver + params).
enclosing_func='
  /^func / { fn=$0; sub(/^func[ \t]+(\([^)]*\)[ \t]+)?/,"",fn); sub(/\(.*/,"",fn) }
'

# 1. The fenced SD delete calls (retention_delete_raw/events) appear ONLY inside deleteRawEvents / deleteEvents.
del_off="$(awk "$enclosing_func"'
  /retention_delete_(raw|events)\(/ { print NR ":" fn }
' "$F" | grep -vE ":(deleteRawEvents|deleteEvents)$" || true)"
if [ -n "$del_off" ]; then
  echo "RETENTION-SINGLE-PATH VIOLATION: retention_delete_* is called outside deleteRawEvents/deleteEvents:" >&2
  echo "$del_off" | sed 's/^/  - retention.go:/' >&2
  fail=1
fi

# 2. The window FORMULA (clampWindow) is invoked in exactly ONE function: resolveWindow (the sole window producer).
clamp_off="$(awk "$enclosing_func"'
  /[^A-Za-z_]clampWindow\(/ && $0 !~ /func clampWindow/ { print NR ":" fn }
' "$F" | grep -vE ":resolveWindow$" || true)"
if [ -n "$clamp_off" ]; then
  echo "RETENTION-SINGLE-PATH VIOLATION: clampWindow (the effective-window formula) is invoked outside resolveWindow:" >&2
  echo "$clamp_off" | sed 's/^/  - retention.go:/' >&2
  echo "  A second window producer can skip the floor/ceiling/arm ordering. Route it through resolveWindow." >&2
  fail=1
fi

# 3. The cutoff-from-duration expression exists ONLY in cutoffFor — no second place turns a raw window into a delete cutoff.
cut_off="$(awk "$enclosing_func"'
  /time\.Now\(\)\.Add\(-time\.Duration\(/ { print NR ":" fn }
' "$F" | grep -vE ":cutoffFor$" || true)"
if [ -n "$cut_off" ]; then
  echo "RETENTION-SINGLE-PATH VIOLATION: a delete cutoff is derived from a duration outside cutoffFor:" >&2
  echo "$cut_off" | sed 's/^/  - retention.go:/' >&2
  fail=1
fi

# 4. Legal-hold short-circuit is present at the TOP of SweepTenant (before any window compute).
if ! grep -A4 'func (s \*Service) SweepTenant' "$F" | grep -q 'heldOrMissing('; then
  echo "RETENTION-SINGLE-PATH VIOLATION: SweepTenant does not short-circuit on heldOrMissing — the legal-hold check" >&2
  echo "  must run BEFORE any window is computed (a held tenant is never swept)." >&2
  fail=1
fi

# 5. Reach not widened (gate test #7): retention issues no DELETE against non-telemetry (alerts/incidents/evidence/audit).
reach="$(grep -rnE 'DELETE[ \t]+FROM[ \t]+(alerts|incidents|evidence|audit_log)\b' internal/retention --include='*.go' | grep -v '_test\.go:' || true)"
if [ -n "$reach" ]; then
  echo "RETENTION-REACH VIOLATION: retention deletes a NON-telemetry table (must only age raw_events/events):" >&2
  echo "$reach" | sed 's/^/  - /' >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-retention-window-single-path: OK — one window producer (resolveWindow→clampWindow→cutoffFor) feeds the SD delete; legal-hold short-circuits first; reach is raw_events/events only."
