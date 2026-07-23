#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
gate="$root/cmd/api/recovery_gate.go"

fail() { echo "recovery serving gate: $*" >&2; exit 1; }

test -f "$gate" || fail "cmd/api/recovery_gate.go is missing"
grep -Eq 'func init\(\)' "$gate" || fail "startup init choke point is missing"
grep -Eq 'recovery\.RequireServingFromEnv\(\)' "$gate" || fail "restored startup does not call RequireServingFromEnv"
grep -Eq 'panic\(' "$gate" || fail "startup gate does not fail closed"

# The production api command must not provide a second listener entry point that
# bypasses package initialization.
main_count=$(grep -R --include='*.go' -Ec '^func main\(\)' "$root/cmd/api" | awk -F: '{s+=$2} END {print s+0}')
test "$main_count" -eq 1 || fail "expected exactly one api main entry point, found $main_count"

echo "recovery serving gate: GREEN"
