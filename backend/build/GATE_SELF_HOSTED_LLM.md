# Pre-code Gate — Self-hosted / local-LLM enablement — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 21 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: capability audit (`outputs/NIRVET_CAPABILITY_AUDIT_2026-07.md` §B) — the config plumbing to point the copilot at a self-hosted OpenAI-compatible model is real, tested, and SSRF-safe, BUT (1) there is no packaged/documented inference-server deployment and (2) **the sovereign `airgap:true` NetworkPolicy has no LLM-egress rule, so the sovereign profile would BLOCK the self-hosted model the architecture doc promises.** This gate turns "we claim self-hosted AI" into "we ship it," honestly.
Scope: **security-sensitive** — it modifies the default-deny egress verified in `GATE_DEPLOYMENT_PACKAGING_SECURITY.md`. Falsification bar: "what opens egress wider than one operator-chosen LLM, exposes the model to ingress/other tenants, or lets the local-LLM path skip redaction."

## 0. What is DONE (do NOT rebuild) — verified by the audit
- `KindOpenAICompatible` provider (`internal/ai/openai.go`, `provider.go`): configurable `base_url`, **keyless local models supported** (empty apiKey omits Authorization).
- **Allowlist egress boundary** (`ai_provider_allowed_endpoint`): base_url validated at save + fail-closed in the resolver; URL rebuilt from the validated origin; redirects refused → SSRF-contained.
- **Deliberately netsafe-exempt** so an internal GPU-box address is reachable (internal ≠ blocked).
- **Per-tenant residency pinning** (`tenant_ai_policy.allowed_kinds` → `['openai_compatible','disabled']`).
- **Redaction chokepoint** `completeExternal` + the `check-ai-egress-redaction` fence — everything to a provider is redacted.
- **AI-off = SOC still works** (deterministic fallbacks).
This gate is the **deployment/packaging + the air-gap egress fix**, NOT the AI app code (which is ready).

## 1. Requirements — LOCKED

### 1a. Air-gap NetworkPolicy LLM-egress — a NARROW, explicit, off-by-default allow (default-deny preserved)
- Add a values knob (e.g. `ai.selfHostedLLM.endpoint` / `.cidr` + `.port`, or a small `llmEgress:` list). When set, the NetworkPolicy adds **one egress rule** to exactly that endpoint/port from the app+worker pods.
- **Default-deny is preserved.** Unset ⇒ **no LLM egress** (the current behavior) — and that is fail-safe: no LLM = AI-off, and the audit confirmed the SOC still works. **Never** open egress to `0.0.0.0/0` or a wide range; the allow must be a specific host/CIDR + port.
- The in-cluster-LLM case (1b) is the preferred sovereign shape — egress stays *inside* the cluster to the LLM pod, so no external egress is opened at all.

### 1b. In-cluster inference server (the sovereign-preferred deployment)
- Ship a **reference manifest or optional Helm subchart** for a self-hosted inference server (ollama or vLLM), operator-enabled (`ai.selfHostedLLM.enabled=false` default). Include **GPU nodepool + resource sizing** guidance.
- **Segmentation:** the LLM Service is reachable **only from the app/worker pods** (a NetworkPolicy allowing app→LLM on the model port) — it is **NOT** exposed via Ingress and **NOT** reachable from other namespaces/tenants. The model sees every prompt+context, so an ingress-exposed or broadly-reachable LLM is a data-exfil surface — forbid it.
- Preserve the hardened pod posture (nonroot/readonly/drop-ALL where the image allows; GPU images may need a documented exception — flag it, don't silently privileged-run).

### 1c. The local-LLM path does NOT bypass any control (the crux)
- A self-hosted model is still a **separate trust zone** that receives the egress payload. The copilot's local-LLM path MUST remain the **same `completeExternal` chokepoint** + allowlist + per-tenant policy — **no new code door.** The `check-ai-egress-redaction` fence must still pass (the local endpoint rides the existing provider path, not a bypass).
- **Redaction LEVEL is an operator decision, not a code bypass.** For a fully-controlled, air-gapped local model, a sovereign operator MAY choose `balanced` (or a documented lighter level) per tenant via the existing D2 mechanism — because the data never leaves their perimeter. That is a *config* choice through the existing knob; the chokepoint, allowlist, and per-tenant policy stay in force. Document this trade-off honestly; do not hard-code a weaker default.

### 1d. Runbook (honest)
`build/runbooks/SELF_HOSTED_LLM.md`: model choice, keyless-vs-keyed, deploy the inference server (1b) or point at an existing internal one (1a), add the allowlist entry, pin the tenant policy, **smoke-test the copilot answers against the local model**, and choose the redaction level. Include an **honest quality-sizing note** — small local models materially degrade triage/summary quality vs. a frontier model; state it plainly so the operator sets expectations.

## 2. GUARANTEE (teeth) — extend `check-deploy-security.sh`
- The LLM-egress allow, if present, must be a **specific host/CIDR + port** — the fence FAILS on `0.0.0.0/0`, a wide CIDR, or an all-ports egress in the LLM rule.
- The self-hosted-LLM Service (1b) must **not** be referenced by any Ingress and must be default-off (`enabled=false`).
- `check-ai-egress-redaction` must still be green (the local path did not add a bypass).
- Mutation-proven: a blanket `0.0.0.0/0` LLM egress → RED; an Ingress-exposed LLM Service → RED.

## 3. Falsification tests (each mutation-sensitive)
1. **Default-deny preserved:** with the LLM knob unset, the rendered NetworkPolicy has **no** LLM/external egress (AI-off; SOC works).
2. **Narrow allow only:** setting the knob adds egress to exactly the configured endpoint/port and nothing wider; `0.0.0.0/0` is rejected by the fence.
3. **LLM app-only:** the in-cluster LLM is reachable from app/worker pods only — not Ingress, not other namespaces (NetworkPolicy proves it).
4. **No redaction bypass:** the copilot pointed at the local model still routes through `completeExternal` (egress payload masked at the tenant's configured level); the egress fence stays green. A local endpoint that skipped redaction → RED.
5. **AI-off fallback intact:** with no LLM configured, copilot endpoints return the deterministic fallback, no egress attempted.
6. **Allowlist + residency still gate it:** a local base_url not on the allowlist is refused (`endpoint_not_allowlisted`); a tenant pinned to `disabled` never reaches the local model.

## 4. Out of scope (follow-ons)
The copilot FEATURE completion (RAG/agentic/AI-authored proposals — a separate gate) · model procurement + GPU capacity (ops) · multi-model routing per task · fine-tuning/model-mgmt. This gate makes self-hosted LLM *deployable and non-self-contradicting*; it does not make the copilot *mature* (that's the next AI gate).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 1a — narrow off-by-default LLM-egress knob; default-deny preserved; unset ⇒ no egress (tests #1, #2).
- [ ] 1b — in-cluster inference reference/subchart, app→LLM-only, not Ingress-exposed, default-off (test #3); GPU pod-posture exception documented if needed.
- [ ] 1c — local path uses the existing `completeExternal` chokepoint + allowlist + per-tenant policy; no new bypass door; redaction level is a documented operator choice (tests #4, #6).
- [ ] 1d — runbook with stand-up steps + honest quality-sizing note.
- [ ] 2 — `check-deploy-security.sh` extended (reject wide/all-ports LLM egress + Ingress-exposed LLM), `check-ai-egress-redaction` still green, mutation-proven.
