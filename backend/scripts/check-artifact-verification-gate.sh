#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AIRGAP="$ROOT/deploy/airgap/verify-and-install.sh"
HELM="$ROOT/deploy/helm/verified-install.sh"
CORE="$ROOT/backend/internal/platform/supplychain/supplychain.go"
CLI="$ROOT/backend/cmd/artifactctl/main.go"
WORKFLOW="$ROOT/.github/workflows/supply-chain.yml"

for file in "$AIRGAP" "$HELM" "$CORE" "$CLI" "$WORKFLOW"; do
  [[ -f "$file" ]] || { echo "artifact verification gate missing: $file" >&2; exit 1; }
done

for installer in "$AIRGAP" "$HELM"; do
  grep -q 'artifactctl verify' "$installer" || { echo "$installer bypasses verifier" >&2; exit 1; }
  verify_line="$(grep -n 'artifactctl verify' "$installer" | head -n1 | cut -d: -f1)"
  install_line="$(grep -nE 'docker load|helm upgrade|helm install|exec ' "$installer" | head -n1 | cut -d: -f1)"
  [[ -n "$verify_line" && -n "$install_line" && "$verify_line" -lt "$install_line" ]] || {
    echo "$installer does not verify before load/install" >&2; exit 1;
  }
done

if grep -RInE --exclude='check-artifact-verification-gate.sh' --exclude='GATE_SUPPLY_CHAIN_SIGNING_SBOM.md' \
  -- '--skip-verify|--insecure|allow[-_ ]unsigned|ALLOW_UNSIGNED|SKIP_VERIFY' \
  "$ROOT/deploy" "$ROOT/backend/cmd/artifactctl"; then
  echo "reachable artifact verification bypass found" >&2
  exit 1
fi

for kind in container-backend container-frontend container-migrate binary-api binary-worker binary-migrate helm-chart airgap-bundle; do
  grep -q "\"$kind\"" "$CORE" || { echo "required artifact kind missing: $kind" >&2; exit 1; }
done

for invariant in 'VerifyDigest' 'verifyDependencyCompleteness' 'verifyClosedTree' 'downgrade release sequence' 'source commit mismatch'; do
  grep -q "$invariant" "$CORE" || { echo "verification invariant missing: $invariant" >&2; exit 1; }
done

grep -q 'network_mode: none' "$WORKFLOW" || { echo "offline verification drill is not network-dropped" >&2; exit 1; }
grep -q 'Mutation — remove install verifier must fail' "$WORKFLOW" || { echo "install-verifier mutation proof missing" >&2; exit 1; }
grep -q 'Mutation — unlisted dependency must fail' "$WORKFLOW" || { echo "SBOM completeness mutation proof missing" >&2; exit 1; }
grep -q 'Mutation — strip signature must fail' "$WORKFLOW" || { echo "signature mutation proof missing" >&2; exit 1; }

echo "artifact verification structural gate: PASS"
