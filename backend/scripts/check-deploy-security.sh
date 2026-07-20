#!/usr/bin/env bash
#
# check-deploy-security.sh — the CI teeth behind the deployment-packaging security gate. A deployment package is a
# security artifact: a chart that embeds a secret, runs privileged/root, has no NetworkPolicy, or uses a floating
# image tag turns "self-hostable" into "self-compromising". This fence fails the build on any such regression.
#
# Run from repo root (the CI step cds to repo root). Grep/policy over the chart — no helm/cluster needed.
set -euo pipefail

# Resolve repo root whether invoked from backend/ or the repo root.
if [ -d deploy/helm/nirvet ]; then ROOT="."; elif [ -d ../deploy/helm/nirvet ]; then ROOT=".."; else ROOT="."; fi
CHART="$ROOT/deploy/helm/nirvet"
HELPERS="$CHART/templates/_helpers.tpl"
fail=0

# 0. The chart must exist — an absent chart fails the check (never silently passes).
if [ ! -d "$CHART" ]; then
  echo "❌ helm chart $CHART is absent — the deploy-security fence has nothing to check"
  exit 1
fi

workloads="$CHART/templates/deployment-api.yaml $CHART/templates/deployment-worker.yaml $CHART/templates/migrate-job.yaml"

# nocomment strips grep -n hits whose content is a YAML/prose comment line (# ...), so an explanatory comment that
# mentions ":latest" or "/metrics" is not a false positive — only real settings are checked.
nocomment() { grep -vE ':[0-9]+:[[:space:]]*#' || true; }

# 1. No insecure setting anywhere in the chart (privileged/root/host*/floating tag).
bad="$(grep -rEn 'privileged: *true|hostNetwork: *true|hostPID: *true|hostPath:|runAsNonRoot: *false|allowPrivilegeEscalation: *true|:latest' "$CHART" | nocomment)"
if [ -n "$bad" ]; then echo "❌ insecure setting in chart:"; echo "$bad"; fail=1; fi

# 2. The hardening helpers define every required key (containers inherit these via include).
for key in 'runAsNonRoot: true' 'readOnlyRootFilesystem: true' 'allowPrivilegeEscalation: false' 'drop:.*ALL' 'seccompProfile'; do
  grep -qE "$key" "$HELPERS" || { echo "❌ _helpers.tpl missing hardening: $key"; fail=1; }
done

# 3. Every workload includes BOTH securityContext helpers + resource limits + non-auto-mounted SA token.
for w in $workloads; do
  [ -f "$w" ] || continue
  grep -q 'nirvet.podSecurityContext' "$w"       || { echo "❌ $w: missing podSecurityContext"; fail=1; }
  grep -q 'nirvet.containerSecurityContext' "$w"  || { echo "❌ $w: missing containerSecurityContext"; fail=1; }
  grep -q 'resources:' "$w"                        || { echo "❌ $w: missing resource limits"; fail=1; }
  grep -q 'automountServiceAccountToken' "$w"      || { echo "❌ $w: missing automountServiceAccountToken"; fail=1; }
done

# 4. Image is digest-pinned (helper uses @<digest>; values digest is a sha256).
grep -q '@{{ .Values.image.digest }}' "$HELPERS" || { echo "❌ image not digest-pinned in the image helper"; fail=1; }
grep -qE 'digest: *"?sha256:' "$CHART/values.yaml" || { echo "❌ values.image.digest is not a sha256 digest"; fail=1; }

# 5. A default-deny NetworkPolicy exists.
grep -q 'default-deny' "$CHART/templates/networkpolicy.yaml" 2>/dev/null || { echo "❌ no default-deny NetworkPolicy"; fail=1; }

# 6. No plaintext secret literal in the chart (dev-compose defaults / inline tokens/keys/passwords must never leak).
sec="$(grep -rEn '(POSTGRES_PASSWORD|CLICKHOUSE_PASSWORD|_TOKEN|MASTER_KEY|JWT_SECRET|[Pp]assword): *[^"[:space:]{].*[A-Za-z0-9]' \
  "$CHART"/values*.yaml "$CHART"/templates/configmap.yaml 2>/dev/null \
  | nocomment | grep -viE 'existingSecretName|secretName|secretRef|secretKeyRef' || true)"
if [ -n "$sec" ]; then echo "❌ possible secret literal in the chart (secrets belong in a K8s Secret, not the chart):"; echo "$sec"; fail=1; fi

# 7. /metrics is never routed through an Ingress (real routing, not a comment).
metr="$(grep -rEn '/metrics' "$CHART/templates/" 2>/dev/null | nocomment | grep -iE 'ingress|Ingress' || true)"
if [ -n "$metr" ]; then echo "❌ /metrics routed via ingress (must be monitoring-only):"; echo "$metr"; fail=1; fi

# 8. The air-gap bundle is integrity-checksummed.
grep -q 'SHA256SUMS' "$ROOT/deploy/airgap/make-bundle.sh" 2>/dev/null || { echo "❌ air-gap bundle tooling lacks SHA256SUMS integrity"; fail=1; }

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "✓ deploy-security: chart hardened (nonroot/readonly/drop-all/no-privesc), default-deny NetworkPolicy,"
echo "  digest-pinned image, no secret literals, /metrics monitoring-only, air-gap bundle checksummed"
