# Pre-code Gate — Deployment packaging security (Helm / K8s / air-gap bundle) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: NIR-AUD-021 epic item #2 (packaging) — what makes on-prem/sovereign actually *deployable* ("helm install nirvet" / "docker compose up -d"). Ref: `outputs/NIRVET_ONPREM_SOVEREIGN_RECONCILIATION.md`, epic tracker task #67.
Scope: **P/B — deployment security.** Lower sensitivity than the crypto gate, but real surface. Falsification bar: "what ships a secret, runs privileged, phones home from an air-gap, or lets a compromised pod reach another tenant's data plane."

## 0. Why this is a security gate, not just DevOps
A deployment package is a security artifact: a chart that embeds a default password, a pod that runs privileged/root, or a namespace with no NetworkPolicy each converts "self-hostable" into "self-compromising." Sovereign/gov buyers audit exactly this. The teeth are a **policy check in CI** (mirrors the `check-*.sh` fences) that fails the build on an insecure manifest — so packaging can't silently regress.

## 1. Current state, verified at source
- **Backend image is already well-hardened** (`backend/Dockerfile`): multi-stage, static (CGO off), `gcr.io/distroless/static-debian12:nonroot` — non-root, no shell, minimal surface. **The K8s pod spec must PRESERVE this, not undo it.**
- **`deploy/docker-compose.yml` is a DEV compose** and ships default creds (`POSTGRES_PASSWORD: postgres`, `CLICKHOUSE_PASSWORD: nirvet`). Acceptable for local dev; **these must NEVER appear in the production package** — this is the #1 packaging trap.
- Deps to wire: PostgreSQL, ClickHouse, NATS, Redis, object storage (S3/MinIO), and (for KMS) Vault. All self-hostable.
- Crypto wiring exists: `NIRVET_CRYPTO_REQUIRE_KMS`, `NIRVET_VAULT_ADDR` (config/non-secret), `NIRVET_VAULT_TOKEN` + master key (secrets).
- `/metrics` is intentionally unauthenticated for the scrape collector (D3) — it MUST be network-restricted, never publicly reachable.

## 2. Requirements — LOCKED

### 2a. No secrets in images or committed charts (the #1 trap)
- No secret value (DB/CH/Redis password, Vault token, master key, KMS creds, API keys) may be baked into an image layer or committed in chart `values.yaml`/templates. Secrets come from **K8s Secrets** (ideally an external secret manager — Vault Agent / External Secrets Operator / CSI driver) mounted at runtime.
- The dev-compose defaults must not be reachable by the prod path. Prod values require the operator to supply secrets (no working default) — a missing secret **fails closed at boot** (require-KMS already does this for crypto; DB/CH must too).

### 2b. Preserve container hardening in the pod securityContext
Every container: `runAsNonRoot: true`, `runAsUser` non-zero, `readOnlyRootFilesystem: true` (writable `emptyDir` only where needed), `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`. **No** `privileged`, `hostNetwork`, `hostPID`, `hostPath`. The image is already nonroot/distroless — the spec must not regress it.

### 2c. Least-privilege K8s RBAC
The app is a plain web service — its ServiceAccount needs **no Kubernetes API access**. `automountServiceAccountToken: false` unless a specific need is justified. No ClusterRole; no use of the `default` SA. If the migration hook needs anything, scope it to the narrowest Role.

### 2d. Network segmentation (default-deny)
- A **default-deny** NetworkPolicy per namespace; explicit allows only: app → {postgres, clickhouse, nats, redis, vault, object-store} on their ports; ingress → app on 8080; DNS.
- **`/metrics` reachable only from the monitoring namespace/scrape source** (D3) — never from ingress. Confirm no metric carries a tenant-identifying label (verified at source earlier — keep it so).
- **Air-gap profile: egress default-deny to the public internet** — no accidental phone-home (telemetry, update checks, public LLM). The self-hosted-model endpoint + internal deps are the only allowed egress.

### 2e. Secrets-vs-config separation + require-KMS profile
- Non-secret config (`NIRVET_VAULT_ADDR`, `NIRVET_CLICKHOUSE_DSN` host, feature flags) → ConfigMap. Secrets (tokens/keys/passwords) → Secret/external.
- Ship a **sovereign/prod values profile** that sets `NIRVET_CRYPTO_REQUIRE_KMS=true` and wires `NIRVET_VAULT_TOKEN` as a Secret — so the sovereign deployment cannot boot on the dev master key (ties the KMS gate 2b).

### 2f. Image provenance + air-gap bundle integrity
- Images pinned by **digest** (not `:latest` / floating tags). Prefer cosign-signed images + an SBOM (syft) per image.
- **Air-gap bundle** = a versioned, **checksummed (and ideally signed) manifest** of {images (as tarballs), the chart, migrations} that an operator verifies before loading into a private registry. No runtime pulls from public registries in the air-gap profile.

### 2g. Migration ordering, fail-closed
Migrations run as a **Helm pre-install/pre-upgrade hook** (or the existing boot-migrate) — idempotent, and the app must not serve traffic until migrations succeed. A failed migration **fails the release** (fail-closed), never a half-migrated serving pod.

### 2h. TLS + resource limits
- Ingress TLS; TLS to Postgres / Vault / ClickHouse (cert refs from Secrets); the syslog listener cert wired. cert-manager or operator-supplied.
- Every container has resource `requests`/`limits`; PodDisruptionBudget + replicas ≥ 2 for the prod/HA profile (HA reference architecture is epic item #6, but don't ship a single-replica-only chart).

## 3. Non-decorative GUARANTEE (the teeth)
`scripts/check-deploy-security.sh` (or conftest/OPA policies) run in CI, **blocking**, over the chart/manifests. Fail the build on any of:
- a secret-like literal (password/token/key/master) present in `values.yaml`/templates/image;
- a container missing `runAsNonRoot`/`readOnlyRootFilesystem`/`drop:[ALL]`/`allowPrivilegeEscalation:false`, or setting `privileged`/`hostNetwork`/`hostPath`;
- a namespace with no default-deny NetworkPolicy;
- an image without a digest / using `:latest`;
- a container without resource limits;
- a Service exposing `/metrics` via ingress.
Mirror the sibling fences: grep/policy over the manifests, mutation-proven (inject a violation → RED, remove → GREEN). If the chart dir is absent the check must fail (not silently pass).

## 4. Falsification checks (each mutation-sensitive)
1. **Secret scan:** planting `POSTGRES_PASSWORD: postgres` in a prod value → RED.
2. **Root/privileged:** a container spec with `runAsNonRoot:false` or `privileged:true` → RED.
3. **Missing NetworkPolicy:** a namespace with no default-deny → RED.
4. **`/metrics` exposed:** an ingress/Service routing `/metrics` publicly → RED.
5. **Unpinned image / `:latest`** → RED.
6. **require-KMS profile:** the sovereign values profile boots with `NIRVET_CRYPTO_REQUIRE_KMS=true` and a Vault-token Secret; removing the KMS provider → boot fails closed (ties KMS gate test #7).
7. **Migration fail-closed:** a failing migration hook fails the release; no serving pod on a half-migrated DB.
8. **Air-gap egress:** with the air-gap profile, a pod attempting public egress is denied by policy.

## 5. Out of scope (adjacent epic items / ops)
Native LDAP/AD federation (epic #3) · Azure Blob provider (#4) · offline threat-feed import (#5) · HA/DR reference architectures + operational runbooks + Sovereign Architecture Guide (#6 — the *docs* layer; this gate is the *chart* layer) · specific service-mesh/mTLS choice · the actual FIPS/CC-certified HSM (KMS incr-2).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a — no secret literal in image/committed chart; missing prod secret fails closed at boot (test #1).
- [ ] 2b — pod securityContext preserves nonroot/readonly/drop-all/no-privesc; no privileged/host* (test #2).
- [ ] 2c — least-priv RBAC, no cluster role, SA token not auto-mounted unless justified.
- [ ] 2d — default-deny NetworkPolicy; `/metrics` monitoring-only; air-gap egress default-deny (tests #3, #4, #8).
- [ ] 2e — secrets/config separated; sovereign profile sets require-KMS + Vault-token Secret (test #6).
- [ ] 2f — images digest-pinned (+ ideally signed/SBOM); air-gap bundle checksummed/verified (test #5).
- [ ] 2g — migrations run pre-serve, fail-closed (test #7). 2h — TLS + resource limits + ≥2 replicas (HA profile).
- [ ] 3 — `check-deploy-security.sh` (or conftest) blocking in CI, mutation-proven.
