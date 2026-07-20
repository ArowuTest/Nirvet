#!/usr/bin/env bash
#
# check-kms-provider-boundary.sh — the CI teeth behind the KMS provider abstraction (gate §3).
#
# Two structural invariants keep a KEK from leaking or a provider from doing its own crypto:
#
#   A. PROVIDER PURITY. Every keyWrapper implementation (a file with a `) Wrap(ctx context.Context, keyName`
#      method) does wrap/unwrap ONLY. It must NOT touch the envelope internals — no DEK generation (rand.Read),
#      no AEAD (aes.NewCipher / cipher.NewGCM / .Seal / .Open), and no DEK zeroize (zero(...)). A provider that
#      does its own crypto or handles a bare key is how a KEK leaks or a DEK gets mis-sealed.
#
#   B. SINGLE CALLER. The wrap/unwrap methods are called from exactly ONE place — envelopeCipher in kms.go
#      (Encrypt / Decrypt / bootProbe). Nothing else in the codebase may call a provider's .Wrap(/.Unwrap(
#      directly, so all plaintext crypto is funnelled through the one cipher that zeroizes and tenant-binds.
#
# Run from backend/. Exits non-zero (and prints offenders) on any violation.
set -euo pipefail

CRYPTO_DIR="internal/platform/crypto"
fail=0

# ── A. provider purity ────────────────────────────────────────────────────────────────────────────────────────
# Provider files = non-test crypto files that declare a keyWrapper Wrap method.
provider_files="$(grep -rl ') Wrap(ctx context.Context, keyName' --include='*.go' "$CRYPTO_DIR" 2>/dev/null \
  | grep -v '_test\.go' || true)"

if [ -z "$provider_files" ]; then
  echo "❌ no keyWrapper provider files found — the boundary fence has nothing to check (did the seam move?)"
  exit 1
fi

# Envelope internals a provider must never reference.
forbidden='rand\.Read|aes\.NewCipher|cipher\.NewGCM|\.Seal\(|\.Open\(|(^|[^[:alnum:]_])zero\('
for f in $provider_files; do
  hits="$(grep -nE "$forbidden" "$f" || true)"
  if [ -n "$hits" ]; then
    echo "❌ provider purity violation in $f — a keyWrapper must do wrap/unwrap ONLY (no DEK gen / AEAD / zeroize):"
    echo "$hits"
    fail=1
  fi
done

# ── B. single caller ──────────────────────────────────────────────────────────────────────────────────────────
# Any dot-prefixed .Wrap( / .Unwrap( CALL site (not a `func (x) Wrap(` declaration) must live in kms.go only.
callers="$(grep -rnE '\.(Wrap|Unwrap)\(' --include='*.go' . 2>/dev/null \
  | grep -v '_test\.go:' \
  | grep -v '/kms\.go:' \
  || true)"

if [ -n "$callers" ]; then
  echo "❌ a provider wrap/unwrap is called outside envelopeCipher (kms.go) — all crypto must funnel through the"
  echo "   one cipher that zeroizes + tenant-binds. Offenders:"
  echo "$callers"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "✓ KMS provider boundary: providers are wrap/unwrap-only; the KEK never leaves the backend, and all"
echo "  plaintext crypto funnels through envelopeCipher (files checked: $(echo "$provider_files" | tr '\n' ' '))"
