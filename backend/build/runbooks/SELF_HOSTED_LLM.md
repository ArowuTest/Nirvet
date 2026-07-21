# Runbook — Self-hosted / local LLM

Satisfies `build/GATE_SELF_HOSTED_LLM.md` §1d. How to run the copilot against a model **inside your own perimeter** —
the sovereign-AI posture. The app code (OpenAI-compatible provider, allowlist egress boundary, per-tenant residency
policy, `completeExternal` redaction chokepoint) is already built and verified; this runbook is the **deployment +
the narrow network path** to reach a local model.

## Safety invariant (what a wrong setup does)
A self-hosted model is still a **separate trust zone that receives the full prompt + context**. Two failure modes:
1. **Opening egress too wide** — the sovereign air-gap NetworkPolicy is default-deny; a `0.0.0.0/0` LLM egress
   re-opens the internet. The chart's LLM egress is ONE host + ONE port, and the fence rejects anything wider.
2. **Exposing the model** — an Ingress-exposed or broadly-reachable LLM is a data-exfil surface (it sees every
   prompt). The in-cluster LLM is reachable **app/worker pods only**, never Ingress, never other namespaces.

Neither the chokepoint, the allowlist, nor the per-tenant policy is bypassed by pointing at a local model — a local
endpoint rides the **same** provider path (`check-ai-egress-redaction` stays green).

## Honest quality-sizing note (read first)
A small local model (7B–13B on one GPU) **materially degrades** triage/summary quality vs. a frontier model — weaker
reasoning, more misses on subtle correlation, blander summaries. Self-hosting buys **data sovereignty**, not quality
parity. Set operator expectations accordingly: use a local model where the data must not leave the perimeter, and size
the GPU to the largest model you can run (a 70B-class model closes much of the gap but needs multi-GPU / more VRAM).
AI-off is always a safe posture — the SOC's deterministic paths work without any model.

## Choose ONE shape

### (a) In-cluster inference server — SOVEREIGN-PREFERRED (no external egress)
The model runs inside the cluster; egress never leaves it.
1. Pick an OpenAI-compatible server: **ollama** (`/v1` OpenAI shim, port 11434) or **vLLM** (port 8000). Pin the image
   by **digest**.
2. Enable it (default OFF):
   ```yaml
   # -f your-values.yaml
   ai:
     selfHostedLLM:
       enabled: true
       image: "ollama/ollama@sha256:<digest>"   # digest-pinned; the chart rejects a floating tag
       modelPort: 11434
       gpu: { enabled: true, count: 1 }          # requests nvidia.com/gpu; needs a GPU nodepool + device plugin
       resources:
         requests: { cpu: "2", memory: "8Gi" }
         limits:   { cpu: "8", memory: "24Gi" }
   ```
   This renders a hardened `-llm` Deployment + a ClusterIP `-llm` Service + two NetworkPolicies (app→LLM egress and
   LLM ingress-from-app-only). The model cache is an `emptyDir` (ephemeral — re-pulls on restart); swap it for a PVC
   if you want the model to persist across restarts.
3. **GPU pod-posture exception (documented, not silent):** the chart default keeps the LLM pod `runAsNonRoot` +
   `readOnlyRootFilesystem` + `drop: ALL` (the model dir is a writable mounted volume). If your chosen GPU image
   *cannot* run under that posture, override `securityContext` for the `-llm` workload **explicitly via `-f`** and
   record why — never switch to `privileged`. The chart never ships a privileged default (the deploy-security fence
   forbids it).
4. Point the tenant's provider at the in-cluster Service: base_url `http://<release>-llm:11434/v1` (keyless — leave
   the API key empty; the provider omits `Authorization`).

### (b) An EXISTING internal GPU box outside the cluster (narrow egress)
When the inference server already runs on a reachable internal host.
1. Leave `enabled: false`. Add ONE narrow egress allow:
   ```yaml
   ai:
     selfHostedLLM:
       egress:
         cidr: "10.20.30.40/32"   # the SPECIFIC host — a /32 is ideal; the fence rejects 0.0.0.0/0 and masks < /24
         port: 11434              # the SINGLE model port
   ```
   This adds exactly one egress rule (app/worker → that host:port). Unset ⇒ no LLM egress at all (default-deny holds).
2. Point the tenant provider base_url at `http://10.20.30.40:11434/v1`.

## Wire the copilot (app side — same for both shapes)
1. **Add the endpoint to the allowlist** (platform-admin): register the local base_url in `ai_provider_allowed_endpoint`
   — a base_url NOT on the allowlist is refused (`endpoint_not_allowlisted`).
2. **Pin the tenant policy**: set `tenant_ai_policy.allowed_kinds` to include `openai_compatible` for tenants that may
   use the local model; a tenant pinned to `disabled` never reaches any model.
3. **Choose the redaction level (operator decision).** Everything to the model still flows through `completeExternal`.
   For a fully air-gapped model you fully control, you MAY select a lighter documented level (e.g. `balanced`) per
   tenant via the existing D2 policy knob — because the data never leaves your perimeter. This is a **config choice
   through the existing mechanism**, not a code bypass; the chokepoint, allowlist, and per-tenant policy stay in force.
   Do not expect a lighter level for a model you do NOT fully control.
4. **Smoke-test:** open the copilot for a test tenant and ask it to summarize a known incident. Confirm you get a
   local-model answer (check the inference server logs show the request), and that a tenant pinned to `disabled` gets
   the deterministic fallback, not a model call.

## Verify (the falsification checks the reviewer runs)
- `helm template` with the knob **unset** → no LLM egress / no `-llm` objects (default-deny preserved; AI still off-safe).
- With shape (b) set → exactly one egress rule to your host:port; `0.0.0.0/0` is rejected at render + by the fence.
- With shape (a) → the `-llm` Service is app-only (the `-llm-ingress` NetworkPolicy has no Ingress/namespace source).
- `check-deploy-security.sh` and `check-ai-egress-redaction` both green.

## Secrets & reversal
No LLM secret is templated into the chart (keyless local models need none; a keyed one uses the operator Secret). To
disable: set `enabled: false` / clear `egress.cidr` and redeploy → the model path closes and default-deny is restored.

## Accreditation mapping
In-country model + no external egress + app-only reachability + unbroken redaction chokepoint satisfies the
data-sovereignty + AI-governance controls; cross-references SOVEREIGN_ARCHITECTURE.md (self-hosted LLM = an air-gap
strength) and the verified `check-ai-egress-redaction` fence.
