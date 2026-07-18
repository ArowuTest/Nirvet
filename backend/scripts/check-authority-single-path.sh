#!/usr/bin/env bash
#
# check-authority-single-path.sh — CI teeth behind the authority-to-act crown-jewel config.
#
# authority_policies gates autonomous containment (soar.Allowed(mode,risk)). The permissive modes
# (pre_authorized / contractual_auto) auto-run destructive actions, so they are guarded: R-3 requires
# platform_admin to set a permissive mode, and L3 restricts the '*' catch-all to restrictive modes. Those guards
# live in ONE usecase, tenant.Service.SetAuthorityPolicy (internal/tenant/governance.go). Both HTTP doors
# (POST /soar/authority padmin, PUT /admin/tenants/{id}/authority-policies ssoAdmin) funnel through it; the only
# other writer is the safe default-'observe' seed in the same file.
#
# A NEW code path that writes authority_policies directly — anywhere else — would bypass the R-3/L3 tighten-only
# guard: a silent way to set a permissive authority mode without the platform_admin check. Rather than rely on
# review catching it, this fence FAILS the build if an INSERT/UPDATE of authority_policies appears in any non-test
# Go file except governance.go. It makes the bypass structurally unrepresentable, not merely absent today.
#
# Run from backend/. Exits non-zero (printing the offending file:line) on any forbidden write.
set -euo pipefail

cd "$(dirname "$0")/.."

# WRITE forms only (reads — SELECT/ResolveAuthority — are fine and expected elsewhere).
PATTERN='(INSERT[[:space:]]+INTO|UPDATE)[[:space:]]+authority_policies'

# The ONLY file allowed to write it: the guarded usecase + the safe 'observe' seed both live here.
ALLOWED='^internal/tenant/governance\.go:'

offenders="$(grep -rn -E "$PATTERN" internal cmd --include='*.go' 2>/dev/null \
  | grep -v '_test\.go:' \
  | sed 's#^\./##' \
  | grep -vE "$ALLOWED" || true)"

if [ -n "$offenders" ]; then
  echo "AUTHORITY-SINGLE-PATH VIOLATION: authority_policies is written outside the guarded usecase" >&2
  echo "(internal/tenant/governance.go — SetAuthorityPolicy, whose R-3/L3 guards require platform_admin for" >&2
  echo "permissive modes and keep the '*' catch-all restrictive). These write it directly:" >&2
  echo "$offenders" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "Route the write through tenant.Service.SetAuthorityPolicy so the permissive-mode/catch-all guards apply." >&2
  echo "A direct write is a silent path to auto-run destructive containment without the platform_admin check." >&2
  exit 1
fi

echo "check-authority-single-path: OK — authority_policies is written only via the guarded governance.go usecase."
