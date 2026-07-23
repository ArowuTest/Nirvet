#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:?usage: verified-install.sh RELEASE_DIR [helm args...]}"
shift
SOURCE_REPO="${NIRVET_EXPECTED_SOURCE_REPO:?set NIRVET_EXPECTED_SOURCE_REPO}"
SOURCE_COMMIT="${NIRVET_EXPECTED_SOURCE_COMMIT:?set NIRVET_EXPECTED_SOURCE_COMMIT}"
MIN_SEQUENCE="${NIRVET_MIN_RELEASE_SEQUENCE:?set NIRVET_MIN_RELEASE_SEQUENCE}"
INSTALLED_SEQUENCE="${NIRVET_INSTALLED_RELEASE_SEQUENCE:-0}"

# Connected mode uses the same local public-key verifier as the air-gap path.
# No registry, Rekor, Fulcio, OIDC, or network identity service is trusted here.
go run ./backend/cmd/artifactctl verify \
  --root "$ROOT" \
  --source-repo "$SOURCE_REPO" \
  --source-commit "$SOURCE_COMMIT" \
  --minimum-sequence "$MIN_SEQUENCE" \
  --installed-sequence "$INSTALLED_SEQUENCE"

CHART="$(find "$ROOT/artifacts" -maxdepth 1 -name '*.tgz' -print -quit)"
[[ -n "$CHART" ]] || { echo "verified release has no Helm chart" >&2; exit 1; }
helm upgrade --install nirvet "$CHART" "$@"
