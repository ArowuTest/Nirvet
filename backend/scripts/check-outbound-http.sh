#!/usr/bin/env bash
#
# check-outbound-http.sh — the CI teeth behind the "one un-bypassable outbound HTTP constructor" rule.
#
# Every outbound HTTP client that could reach a tenant-configured URL MUST be built with
# netsafe.SafeClient (dial-time internal-IP guard + redirect refusal), so a hostile issuer/base_url/
# provider_url cannot turn into SSRF (cloud-metadata read, internal port scan). Five review rounds each
# found a plain http.Client that the previous round missed (SMS → ticketing → OIDC discovery); the
# structural fix is to fail the build on ANY plain outbound client unless it is explicitly waived.
#
# A construction is allowed ONLY if:
#   1. it lives in internal/platform/netsafe/ (that IS the sanctioned constructor), or
#   2. it is in a *_test.go file, or
#   3. its line carries an explicit `// netsafe-exempt: <reason>` waiver (e.g. a hardcoded, non-tenant
#      host like api.anthropic.com) — visible in review, greppable, auditable.
#
# Run from backend/. Exits non-zero (and prints offenders) on any un-waived match.
set -euo pipefail

# Plain client construction + the DefaultClient conveniences (http.Get/Post/... all use DefaultClient,
# which has no internal-IP guard) + raw socket dials (net.Dial/DialTimeout/Dialer) — an outbound TCP
# connect to a tenant-configured host:port (e.g. the SMTP sender) is the same SSRF class as a plain
# http.Client and must go through netsafe.SafeDialTCP (post-DNS internal-IP block, DNS-rebinding-proof).
pattern='http\.Client\{|http\.DefaultClient|http\.Get\(|http\.Post\(|http\.PostForm\(|http\.Head\(|net\.Dial\(|net\.DialTimeout\(|net\.Dialer\{'

matches="$(grep -rEn "$pattern" --include='*.go' . 2>/dev/null \
  | grep -v '_test\.go:' \
  | grep -v 'internal/platform/netsafe/' \
  | grep -v 'netsafe-exempt' \
  || true)"

if [ -n "$matches" ]; then
  echo "❌ Forbidden plain outbound HTTP client(s) found."
  echo "   Use netsafe.SafeClient(timeout), or add a '// netsafe-exempt: <reason>' waiver on the line"
  echo "   if the host is hardcoded and NOT tenant-configurable:"
  echo ""
  echo "$matches"
  exit 1
fi

echo "✓ outbound HTTP: every client goes through netsafe.SafeClient (or is explicitly waived)"
