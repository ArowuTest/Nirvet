#!/usr/bin/env bash
# #40 — structural guard (mirrors check-outbound-http.sh). Every SECURITY DEFINER function bypasses RLS (it runs as
# its owner), so it MUST NOT be executable by PUBLIC. This is exactly how migration 0070 silently regressed the
# pattern the 0018+ cohort established. Fail the build if any SECURITY DEFINER function in migrations/ lacks a
# matching `REVOKE ... FROM PUBLIC` (or `REVOKE ALL ON FUNCTION <f>`). Run from backend/.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pair each function with its own SECURITY DEFINER clause: capture the name on a CREATE ... FUNCTION line, emit it
# when SECURITY DEFINER appears before the next CREATE. SQL line-comments are stripped first so a prose mention of
# "SECURITY DEFINER" (e.g. "-- this is NOT security definer") can't cause a false positive. POSIX-awk safe.
names="$(cat migrations/*.sql | sed 's/--.*//' | awk '
  toupper($0) ~ /CREATE .*FUNCTION/ {
    line=$0
    sub(/.*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn][ \t]+/, "", line)
    sub(/[ \t(].*/, "", line)
    name=line; emitted=0
  }
  toupper($0) ~ /SECURITY DEFINER/ && name != "" && emitted == 0 { print name; emitted=1 }
' | sort -u)"

fail=0
for n in $names; do
  if ! grep -rqiE "REVOKE[[:space:]]+ALL[[:space:]]+ON[[:space:]]+FUNCTION[[:space:]]+${n}\b" migrations/*.sql \
     && ! grep -rqiE "REVOKE[[:space:]].*FUNCTION[[:space:]]+${n}\b.*FROM[[:space:]]+PUBLIC" migrations/*.sql; then
    echo "   ✗ SECURITY DEFINER function '${n}' has no matching REVOKE ... FROM PUBLIC"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "SECURITY DEFINER functions bypass RLS — each MUST 'REVOKE ALL ON FUNCTION <f>(<args>) FROM PUBLIC;'"
  echo "and 'GRANT EXECUTE ... TO nirvet_app;' (see migration 0071 for the pattern)."
  exit 1
fi
echo "✓ SECURITY DEFINER: every function revokes PUBLIC (RLS-bypass not exposed to PUBLIC)"
