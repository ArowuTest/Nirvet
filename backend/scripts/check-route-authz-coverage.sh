#!/usr/bin/env bash
#
# check-route-authz-coverage.sh — CI teeth ensuring every state-changing HTTP route is authz-guarded.
#
# Nirvet's authorization is per-route middleware wrappers applied by hand at each mux.Handle in cmd/api/main.go.
# That is correct today, but not recurrence-proof: a future mutating route added WITHOUT a wrapper is a silent
# authz bypass that no test would catch (the classic "legacy door that became a bypass when the model changed").
#
# This fence parses every mutating route — mux.Handle("<POST|PUT|PATCH|DELETE> <path>", <expr>) — and asserts the
# handler expression begins with one of the closed set of known authz guards, OR the path is on the explicit
# PUBLIC_ALLOWLIST below (the complete, justified set of intentionally-non-session routes). A mutating route that
# is neither guard-wrapped nor allowlisted FAILS the build, naming the route. Adding to the allowlist is therefore
# a conscious, reviewed act — the allowlist IS the audit surface.
#
# Structural (grep/sed over main.go), matching the sibling check-*.sh fences. Run from backend/.
set -euo pipefail

cd "$(dirname "$0")/.."

MAIN="cmd/api/main.go"

# Closed set of authz-guard wrappers (each is `interactive(...)`-derived or a role gate in main.go). A route whose
# 2nd arg begins with one of these is guarded. A NEW guard name must be added here deliberately (a reviewed act).
# authedMFAEnroll is the authenticated chain WITHOUT the force-MFA-complete gate — wired ONLY to the MFA
# enroll/activate routes so a forced-enrollment grace session can reach them (S1 §2c). It is still a real authz
# guard (authn + suspension + audit); it just omits the mfaGate. A deliberate, reviewed member of the closed set.
GUARDS=" authed authedMFAEnroll provider aiProvider padmin detEng oversight soarApprover soarAuthor senior manager ssoAdmin customerRead customerWrite "

# PUBLIC_ALLOWLIST — the ONLY mutating routes that legitimately carry no session guard. Each has its own auth:
#   pre-auth session-establishing endpoints (rate-limited via httpx.Chain(..., loginLimit)):
PUBLIC_ALLOWLIST="
POST /auth/login
POST /auth/refresh
POST /auth/logout
POST /auth/invitations/accept
POST /auth/password-reset/confirm
POST /auth/sso/saml/acs
POST /ingest/webhook/{id}
POST /soar/approve-link
"
#   /auth/*            : establish the session (authenticated by credentials/MFA/SAML assertion, not a session).
#   /ingest/webhook/{id}: authenticated by the per-connector webhook key.
#   /soar/approve-link : authenticated by a single-use signed HMAC link token.

in_allowlist() { # $1 = "METHOD /path"
  local route="$1" line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    [ "$line" = "$route" ] && return 0
  done <<< "$PUBLIC_ALLOWLIST"
  return 1
}

fail=0
# Extract each mutating route as: "<METHOD /path>|<wrapper-leading-ident>".
while IFS='|' read -r route wrapper; do
  [ -z "$route" ] && continue
  # Guarded? (wrapper is an exact word in the closed set)
  if [[ "$GUARDS" == *" $wrapper "* ]]; then
    continue
  fi
  # Otherwise it must be an explicitly-allowlisted public route.
  if in_allowlist "$route"; then
    continue
  fi
  echo "ROUTE-AUTHZ VIOLATION: mutating route is neither guard-wrapped nor on the PUBLIC_ALLOWLIST:" >&2
  echo "  - $route   (handler wrapped in: '$wrapper')" >&2
  fail=1
done < <(
  grep -oE 'mux\.Handle\("(POST|PUT|PATCH|DELETE) [^"]+", *[A-Za-z_][A-Za-z0-9_.]*' "$MAIN" \
    | sed -E 's/mux\.Handle\("([A-Z]+ [^"]+)", *([A-Za-z_][A-Za-z0-9_.]*)/\1|\2/'
)

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "Wrap the route in the appropriate authz guard (padmin/ssoAdmin/senior/provider/…), or — if it is" >&2
  echo "genuinely public — add it to PUBLIC_ALLOWLIST in this script with a one-line justification." >&2
  exit 1
fi

echo "check-route-authz-coverage: OK — every mutating route is authz-guarded or explicitly allowlisted."
