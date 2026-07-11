#!/usr/bin/env bash
#
# check-session-mint-single-path.sh — the CI teeth behind MA-SR-9 (session-revocation STAMP completeness).
#
# Every session token MUST be minted through iam.Service.MintSession, the ONE chokepoint that stamps the current
# session generation (gen/tgen). A login path that mints a token by calling the auth Manager's Issue/IssueWithTTL
# directly would produce an UNSTAMPED (gen 0) token — either never-revocable or wrongly-rejected — a silent
# revocation gap. Rather than rely on convention, this fence FAILS the build if the token Manager's mint methods
# are called anywhere except the Manager itself and the single chokepoint.
#
# Run from backend/. Exits non-zero (printing the offending call) on any forbidden mint call.
set -euo pipefail

# Token-mint methods on auth.Manager.
PATTERN='\.(Issue|IssueWithTTL)\('

# The ONLY files allowed to reference them (matched against grep's "path:line:" output, hence the trailing colon):
#   - internal/platform/auth/*   : the Manager defines Issue/IssueWithTTL (and Issue delegates to IssueWithTTL).
#   - internal/iam/session_generation.go : MintSession — the single stamp chokepoint.
ALLOWED='^internal/platform/auth/|^internal/iam/session_generation\.go:'

offenders="$(grep -rn -E "$PATTERN" internal cmd --include='*.go' 2>/dev/null \
  | grep -v '_test\.go:' \
  | sed 's#^\./##' \
  | grep -vE "$ALLOWED" || true)"

if [ -n "$offenders" ]; then
  echo "MA-SR-9 VIOLATION: session tokens must be minted ONLY via iam.Service.MintSession (the single stamp" >&2
  echo "chokepoint that sets the session generation). These call the auth Manager's mint methods directly:" >&2
  echo "$offenders" | sed 's/^/  - /' >&2
  echo "" >&2
  echo "Route the mint through MintSession (or, for SSO, the sso.Directory.MintSession seam) so the token carries" >&2
  echo "the current gen/tgen. An unstamped token is a silent session-revocation gap." >&2
  exit 1
fi

echo "check-session-mint-single-path: OK — session tokens are minted only via the MintSession chokepoint."
