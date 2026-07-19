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

# ── Stage 2: WITHIN governance.go, each write must sit inside one of the two known-safe functions ──
#
# The file-level allowlist above leaves a residual: a NEW function added to governance.go could write
# authority_policies directly without the R-3/L3 guards — same bypass, same file, invisible to stage 1.
# This stage maps every write in governance.go to its enclosing function and requires it to be:
#   - SetAuthorityPolicy  (the R-3/L3-guarded usecase — guards precede the INSERT in-function)
#   - seedGovernanceTx    (the safe default-'observe' seed; cannot set a permissive mode)
# Anything else — including a new helper in this file — fails the build.
in_file_offenders="$(awk '
  /^func / {
    fn = $0
    sub(/^func[ \t]+(\([^)]*\)[ \t]+)?/, "", fn)   # strip "func " and any "(r *Repository) " receiver
    sub(/\(.*/, "", fn)                            # strip params — bare function name remains
  }
  /(INSERT[ \t]+INTO|UPDATE)[ \t]+authority_policies/ { print NR ":" fn }
' internal/tenant/governance.go | grep -vE ":(SetAuthorityPolicy|seedGovernanceTx)$" || true)"

if [ -n "$in_file_offenders" ]; then
  echo "AUTHORITY-SINGLE-PATH VIOLATION (stage 2): authority_policies is written inside governance.go but" >&2
  echo "OUTSIDE the guarded functions (SetAuthorityPolicy / seedGovernanceTx). Offending line:function —" >&2
  echo "$in_file_offenders" | sed 's/^/  - governance.go:/' >&2
  echo "" >&2
  echo "A write in a new/unguarded function bypasses the R-3 (platform_admin for permissive modes) and" >&2
  echo "L3 ('*' catch-all stays restrictive) guards even though it lives in the allowed file. Route it" >&2
  echo "through SetAuthorityPolicy instead." >&2
  exit 1
fi

echo "check-authority-single-path: OK — authority_policies is written only via the guarded governance.go usecase (and each in-file write sits inside SetAuthorityPolicy/seedGovernanceTx)."
