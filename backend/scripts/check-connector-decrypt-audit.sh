#!/usr/bin/env bash
#
# check-connector-decrypt-audit.sh — GC-1 (ADR-0004 §6): EVERY connector-credential decrypt must route
# through the single AUDITED chokepoint connector.Vault.Open (which emits a credential_decrypt audit event).
# The cipher is only reachable via the Vault, so we forbid any *other* .Decrypt( inside internal/connector —
# a new caller decrypting a connector secret without the audit fails the build. Mirrors the session-mint fence.
#
# Run from backend/. The ONLY allowed .Decrypt( in the package is inside connector.go (Vault.Open itself).
set -euo pipefail

matches="$(grep -rEn '\.Decrypt\(' internal/connector --include='*.go' 2>/dev/null \
  | grep -v '_test\.go:' \
  | grep -v '/connector\.go:' \
  || true)"

if [ -n "$matches" ]; then
  echo "❌ Connector credential decrypt OUTSIDE the audited Vault.Open (ADR-0004 §6 / GC-1)."
  echo "   Route it through connector.Vault.Open(ctx, tenantID, connectorID, purpose, ciphertext):"
  echo ""
  echo "$matches"
  exit 1
fi

echo "✓ connector credential decrypts route through the audited Vault.Open"
