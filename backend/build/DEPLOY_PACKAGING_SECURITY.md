# Deployment packaging security — build note

Implements `build/GATE_DEPLOYMENT_PACKAGING_SECURITY.md`. A sovereign-deployable Helm chart + an air-gap bundle, with
a blocking CI policy fence so packaging can't silently regress into "self-compromising".

## Built
- **Helm chart `deploy/helm/nirvet/`**: api + worker Deployments, Service (ClusterIP, no /metrics ingress),
  ServiceAccount (`automountServiceAccountToken: false`, no Role/ClusterRole), ConfigMap (non-secret only),
  migration Job as a **pre-install/pre-upgrade hook** (fail-closed — the release fails if migrations fail),
  default-deny NetworkPolicy + explicit data-plane egress + monitoring-only `/metrics`, PodDisruptionBudget.
- **Container hardening in `_helpers.tpl`** (included by every workload — proven present by the fence): `runAsNonRoot`,
  `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop:[ALL]`,
  `seccompProfile: RuntimeDefault`, non-zero UID. Preserves the already-distroless/nonroot image (gate 2b).
- **No secrets in the chart** (gate 2a): the chart references an operator-supplied K8s Secret by name
  (`existingSecretName`, `required`) and NEVER templates a secret value. Missing secret → render fails (fail-safe).
- **Sovereign profile `values-sovereign.yaml`**: `NIRVET_CRYPTO_REQUIRE_KMS=true` (no boot on the dev master key —
  ties KMS gate 2b) + `networkPolicy.airgap=true` (egress default-deny to the public internet, no phone-home) +
  replicas≥2 + PDB.
- **Digest-pinned image** (gate 2f): the image helper is `repository@{{ .Values.image.digest }}`; the fence rejects
  `:latest`/floating tags.
- **Air-gap bundle `deploy/airgap/make-bundle.sh`**: assembles {image tar (by digest), packaged chart, migrations}
  and writes a `SHA256SUMS` the operator verifies before loading into a private registry.
- **Fence `scripts/check-deploy-security.sh`** (blocking in CI, mutation-proven): fails on a secret literal in the
  chart, a container missing hardening / setting privileged/host*/`:latest`/`runAsNonRoot:false`, a missing
  default-deny NetworkPolicy, an un-pinned image, a workload without resource limits, or `/metrics` via ingress.
  Comment-aware (an explanatory comment mentioning `:latest`/`/metrics` is not a false positive). Fails if the chart
  is absent. Four mutations verified RED (privileged, secret literal, no default-deny, dropped securityContext).

## Deferred to ops tooling (gate §5 / partial 2f — flagged, not silently dropped)
- **cosign image signing + syft SBOM** per image — CI-signing/ops tooling that needs the registry + signing keys;
  the chart already requires digest-pinning and the bundle is checksummed (the verifiable substrate signing builds on).
- **HA/DR reference architecture + Sovereign Architecture Guide** (epic item #6 — the docs layer; this is the chart layer).
- **cert-manager wiring specifics / service-mesh mTLS choice** — operator-environment decisions; the chart exposes the
  ingress-TLS + dependency-TLS Secret refs but does not pick a mesh.
