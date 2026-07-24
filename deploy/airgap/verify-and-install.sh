#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:?usage: verify-and-install.sh RELEASE_DIR [helm args...]}"
shift
SOURCE_REPO="${NIRVET_EXPECTED_SOURCE_REPO:?set NIRVET_EXPECTED_SOURCE_REPO}"
SOURCE_COMMIT="${NIRVET_EXPECTED_SOURCE_COMMIT:?set NIRVET_EXPECTED_SOURCE_COMMIT}"
MIN_SEQUENCE="${NIRVET_MIN_RELEASE_SEQUENCE:?set NIRVET_MIN_RELEASE_SEQUENCE}"
STATE_FILE="${NIRVET_INSTALLED_SEQUENCE_FILE:-/var/lib/nirvet/release-sequence}"
INSTALLED_SEQUENCE=0
if [[ -f "$STATE_FILE" ]]; then
  INSTALLED_SEQUENCE="$(cat "$STATE_FILE")"
fi

# VERIFY-BEFORE-PARSE/EXTRACT/LOAD/INSTALL. This call is the production trust boundary.
go run ./backend/cmd/artifactctl verify \
  --root "$ROOT" \
  --source-repo "$SOURCE_REPO" \
  --source-commit "$SOURCE_COMMIT" \
  --minimum-sequence "$MIN_SEQUENCE" \
  --installed-sequence "$INSTALLED_SEQUENCE"

MANIFEST="$ROOT/release.manifest.json"
SEQUENCE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_sequence"])' "$MANIFEST")"

# Only after full verification may deployables be parsed or loaded.
for image in "$ROOT"/artifacts/*.oci.tar; do
  [[ -e "$image" ]] || continue
  docker load --input "$image"
done

CHART="$(find "$ROOT/artifacts" -maxdepth 1 -name '*.tgz' -print -quit)"
[[ -n "$CHART" ]] || { echo "verified release has no Helm chart" >&2; exit 1; }
helm upgrade --install nirvet "$CHART" "$@"

install -d -m 0750 "$(dirname "$STATE_FILE")"
printf '%s\n' "$SEQUENCE" > "$STATE_FILE"
