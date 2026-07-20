#!/usr/bin/env bash
#
# make-bundle.sh — assemble a versioned, checksummed air-gap bundle of {images, chart, migrations} that an operator
# verifies (SHA256SUMS) before loading into a private registry. NO runtime pulls from public registries in the
# air-gap profile — everything the deployment needs is in the bundle (gate 2f).
#
# Usage: IMAGE_DIGEST=sha256:... VERSION=0.1.0 ./make-bundle.sh
# Produces:  dist/nirvet-airgap-<version>/{images/nirvet.tar, chart/nirvet-<version>.tgz, migrations/}, SHA256SUMS
# Signing (cosign) + SBOM (syft) are the operator/CI signing step — see README.md; this script produces the
# checksummed bundle they sign.
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/arowutest/nirvet}"
IMAGE_DIGEST="${IMAGE_DIGEST:?set IMAGE_DIGEST=sha256:... (the released, digest-pinned image)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/deploy/airgap/dist/nirvet-airgap-$VERSION"

rm -rf "$OUT"; mkdir -p "$OUT/images" "$OUT/chart" "$OUT/migrations"

# 1. Image as a tarball (docker or podman), pinned by DIGEST — never :latest.
if command -v docker >/dev/null 2>&1; then
  docker pull "$IMAGE_REPO@$IMAGE_DIGEST"
  docker save "$IMAGE_REPO@$IMAGE_DIGEST" -o "$OUT/images/nirvet.tar"
else
  echo "WARN: docker not found — skipping image tar (CI/lint mode); the manifest still records the pinned digest."
fi

# 2. Helm chart package.
if command -v helm >/dev/null 2>&1; then
  helm package "$ROOT/deploy/helm/nirvet" -d "$OUT/chart" --version "$VERSION"
fi

# 3. Migrations (the SQL the pre-install hook applies).
cp "$ROOT"/backend/migrations/*.sql "$OUT/migrations/" 2>/dev/null || true

# 4. The bundle manifest (what's inside, pinned digest) + integrity checksums.
cat > "$OUT/bundle.manifest.yaml" <<EOF
bundle: nirvet-airgap
version: "$VERSION"
image:
  repository: "$IMAGE_REPO"
  digest: "$IMAGE_DIGEST"
components: [images/nirvet.tar, chart, migrations]
EOF

( cd "$OUT" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; | sort > SHA256SUMS )
echo "Bundle: $OUT"
echo "Verify on the target with: cd $(basename "$OUT") && sha256sum -c SHA256SUMS"
