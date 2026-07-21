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

# 9. Self-hosted LLM egress (GATE_SELF_HOSTED_LLM.md §2) must be NARROW — a specific host/CIDR + a single port, never
# a wide/all-ports allow that re-opens the default-deny egress. The ONLY scalar `cidr:` key in values is
# ai.selfHostedLLM.egress.cidr (networkPolicy.dependencyCIDRs is a list), so a bare `cidr:` line is that value.
for vf in "$CHART/values.yaml" "$CHART/values-sovereign.yaml"; do
  [ -f "$vf" ] || continue
  llm_cidr="$(grep -E '^[[:space:]]*cidr:' "$vf" | head -1 | sed -E "s/.*cidr:[[:space:]]*//; s/[\"']//g; s/[[:space:]]*(#.*)?$//" || true)"
  [ -n "$llm_cidr" ] || continue
  mask="${llm_cidr##*/}"
  if [ "$llm_cidr" = "0.0.0.0/0" ] || ! printf '%s' "$llm_cidr" | grep -qE '^[0-9.]+/[0-9]+$' || { [ "$mask" -lt 24 ] 2>/dev/null; }; then
    echo "❌ $vf: ai.selfHostedLLM.egress.cidr '$llm_cidr' is too wide — must be a specific host/CIDR (mask >= /24), never 0.0.0.0/0"; fail=1
  fi
  llm_port="$(grep -E '^[[:space:]]*port:' "$vf" | head -1 | sed -E "s/.*port:[[:space:]]*//; s/[\"']//g; s/[[:space:]]*(#.*)?$//" || true)"
  if [ -z "$llm_port" ] || [ "$llm_port" = "0" ]; then
    echo "❌ $vf: ai.selfHostedLLM.egress.cidr is set but egress.port is unset/0 — the LLM egress needs a single specific port"; fail=1
  fi
done
# The NetworkPolicy template must keep the render-time reject of a 0.0.0.0/0 LLM egress (belt-and-suspenders vs. a -f override).
grep -q '0.0.0.0/0' "$CHART/templates/networkpolicy.yaml" 2>/dev/null || { echo "❌ networkpolicy.yaml lost the 0.0.0.0/0 LLM-egress reject guard"; fail=1; }

# 10. The in-cluster self-hosted LLM must default OFF and NEVER be Ingress-exposed (the model sees every prompt — an
# Ingress/broadly-reachable LLM is a data-exfil surface).
grep -A3 'selfHostedLLM:' "$CHART/values.yaml" 2>/dev/null | grep -qE 'enabled:[[:space:]]*false' \
  || { echo "❌ ai.selfHostedLLM.enabled must default to false"; fail=1; }
llm_ing="$(grep -rlE 'kind:[[:space:]]*Ingress' "$CHART/templates/" 2>/dev/null | xargs grep -l 'component: llm' 2>/dev/null || true)"
if [ -n "$llm_ing" ]; then echo "❌ self-hosted LLM referenced by an Ingress (must be app-only, never Ingress-exposed):"; echo "$llm_ing"; fail=1; fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "✓ deploy-security: chart hardened (nonroot/readonly/drop-all/no-privesc), default-deny NetworkPolicy,"
echo "  digest-pinned image, no secret literals, /metrics monitoring-only, air-gap bundle checksummed,"
echo "  self-hosted LLM egress narrow (specific host/CIDR+port, no 0.0.0.0/0) + LLM app-only (not Ingress-exposed)"
