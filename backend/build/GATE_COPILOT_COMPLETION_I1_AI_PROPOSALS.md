# Pre-code Gate — Copilot completion, increment 1: AI-authored response proposals — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 21 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: capability audit (`outputs/NIRVET_CAPABILITY_AUDIT_2026-07.md` §A) — the copilot is PARTIAL; one of the three missing mature-copilot pieces is **true AI-authored proposals** (today the LLM does NOT author recommendations — `CreateProposal` consumes an *analyst-supplied* `ProposalInput` and merely tags `proposed_by="ai"`; "AI proposes" is nominal). This increment makes it real. Increments 2 (agentic investigation) + 3 (RAG/#180) follow under their own gates.
Scope: **security-sensitive** — it puts an LLM in the response-recommendation loop. Falsification bar: "what lets the AI execute, escape the action vocabulary, lower the authority gate, auto-promote without a human, or leak un-redacted data."

## 0. The non-negotiable this protects (unchanged from S2b)
**AI NEVER executes — directly or indirectly.** The LLM produces a **proposal (data record)**; a human `soc_manager+` promotes it into the EXISTING `airesponse.Accept → soar.Run` pipeline, which then runs the verified authority gates (`Allowed(mode,risk)` from the catalog + four-eyes + D5 + `authority_policies`). This increment adds an LLM *upstream* of gates that already exist and were reviewer-verified; it removes none, and adds no new promotion door.

## 1. Current state, verified at source (the foundation is already there)
- `ai/proposal.go` `CreateProposal(p, ProposalInput{RecommendedAction, ConnectorKey, Rationale, EvidenceCitations, RiskClass})` — **already validates `RecommendedAction` ∈ the tenant action catalog, fail-closed** (unknown/unwired → rejected). The AI cannot propose an action the catalog+authority model doesn't govern.
- `airesponse.Accept` (S2b i3, verified): the ONLY promotion door — `soc_manager+`, tenant-scoped `GetProposal`, `playbookHasAction(pb, RecommendedAction)` match, `soar.Run` → the full gate, atomic `WHERE status='pending'`.
- **The proposal's `RiskClass` is ADVISORY** — `soar/service.go:277` resolves the gating risk from the **catalog (§9.5), NOT the proposal**; an off-catalog action fails closed to `business_critical`. So a mis-stated LLM risk cannot lower the gate.
- `ai/contextassembler.go` (verified): 5-source, tenant-scoped, cited grounding, rides the `completeExternal` redaction chokepoint. `internal/ai` is soar-exec-free (`check-ai-no-direct-execution` fence green).

## 2. Design — LOCKED

### 2a. The LLM drafts a `ProposalInput` — in `internal/ai` (soar-free)
A new `DraftProposal(ctx, p, incidentID) → ProposalInput` in `internal/ai`: it assembles the incident's **redacted** context (reuse `AssembleContext`), gives the model the tenant's **catalog `action_key` list** as the closed vocabulary, and returns `{RecommendedAction (∈ catalog), Rationale, EvidenceCitations (assembler ids), RiskClass (advisory)}`. It calls `CreateProposal` — which re-validates the action ∈ catalog fail-closed. **The drafting emits DATA; it references no soar/connector symbol** (the `check-ai-no-direct-execution` fence stays green — this is the load-bearing structural guard).

### 2b. Action vocabulary is closed + fail-closed (no free-form command)
The model is prompted with ONLY the tenant's enabled catalog `action_key`s and instructed to choose one or decline. Its output is re-validated ∈ catalog by `CreateProposal` (existing fail-closed path). A hallucinated/off-catalog action → **rejected, no proposal created** — never coerced to the nearest match.

### 2c. Grounding rides the redaction chokepoint (no new egress door)
The drafting LLM call goes through `completeExternal` with the assembled evidence as the redacted bag — same as the copilot. **No raw customer data reaches the model**; `check-ai-egress-redaction` stays green. Citations in the rationale are assembler-provided; `dropInventedCitations` strips any the model invents.

### 2d. Risk stays authoritative-from-catalog (LLM cannot lower the gate)
The LLM's `RiskClass` is **display/advisory only**. Do NOT let it feed the authority decision — `soar.Run`/`runFor` continues to resolve risk from the catalog §9.5. A proposal the LLM labels `low` for an action the catalog rates `business_critical` still requires `business_critical` approval. (Surface the LLM's risk as "AI-assessed risk (advisory)" distinct from the enforced catalog risk.)

### 2e. No auto-accept — the single human-promotion door is unchanged
An AI-drafted proposal is `status='pending'` DATA. It reaches a run ONLY via a human `soc_manager+` through the EXISTING `airesponse.Accept`. **No path auto-promotes a draft**; no new promotion door is added. Two gates remain between AI-draft and execution: (a) the senior accepts, (b) the run's authority gate. `proposed_by='ai'` becomes truthful (the AI really authored it), which makes the human review MORE important, not less — the accept UI must show the AI-authored rationale + citations so the senior reviews a real recommendation.

### 2f. First slice = analyst-triggered, per-incident (bounded)
The draft is **analyst-initiated** ("recommend a response for this incident"), one incident at a time — NOT an autonomous auto-proposer firing on every incident (that's a follow-on with its own rate/abuse gate). Bounds egress volume and keeps a human in the trigger loop. Deterministic offline fallback (AI-off → the endpoint declines cleanly, no egress).

### 2g. Insufficient-evidence honesty
When the assembled context is thin, the draft returns "insufficient evidence to recommend a response" rather than fabricating one — same honesty floor as the copilot. A low-confidence draft is labelled, not hidden.

## 3. GUARANTEE (teeth — mostly the existing fences must STAY green)
- **`check-ai-no-direct-execution`** stays green — `internal/ai` (incl. `DraftProposal`) references no soar-exec symbol / no soar/connector import. This is THE structural guarantee the AI can't execute; a violation = build red.
- **`check-ai-egress-redaction`** stays green — the drafting call is a `completeExternal` consumer, not a raw provider call.
- **`check-authority-single-path`** unaffected — no new writer to `authority_policies`; the LLM draft touches only `ai_response_proposals` (existing RLS'd table).
- No new promotion door: `airesponse.Accept` remains the sole caller of the run-from-proposal path.

## 4. Falsification tests (each mutation-sensitive)
1. **Off-catalog action rejected:** the LLM proposes an action not in the tenant catalog → `CreateProposal` fail-closed rejects it; no proposal row.
2. **No auto-promote:** an AI-drafted proposal is `pending` and cannot reach a run without a human `soc_manager+` `Accept` — no code path promotes a draft. Mutation: any auto-accept call → RED.
3. **Risk can't lower the gate:** an AI proposal with `RiskClass=low` for a catalog-`business_critical` action still requires `business_critical` approval (gate uses catalog risk, not the proposal's).
4. **Redaction holds:** the drafting call routes through `completeExternal` (context redacted); a customer identifier in the incident context egresses masked. `check-ai-egress-redaction` green.
5. **Citations grounded:** a hallucinated evidence id in the rationale is dropped (assembler-provided only).
6. **AI stays soar-free:** the fence proves `internal/ai` (incl. the new drafting) references no execution symbol.
7. **Insufficient-evidence:** thin context → the draft declines to recommend rather than fabricate.

## 5. Out of scope (later increments / follow-ons)
Autonomous auto-proposal on every incident (needs a rate/abuse + human-oversight gate) · agentic investigation — the copilot running hunts/pivoting (increment 2) · RAG over case history / #180 (increment 3) · report-drafting/root-cause narrative · multi-model routing.

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a — `DraftProposal` in `internal/ai`, emits a `ProposalInput`, references no soar/connector symbol (fence green, test #6).
- [ ] 2b — action re-validated ∈ catalog fail-closed; off-catalog rejected, never coerced (test #1).
- [ ] 2c — drafting rides `completeExternal`; citations assembler-provided/`dropInventedCitations` (tests #4, #5).
- [ ] 2d — `RiskClass` advisory only; catalog §9.5 risk still gates (test #3).
- [ ] 2e — no auto-accept; `airesponse.Accept` remains the sole promotion door; accept UI shows AI rationale+citations (test #2).
- [ ] 2f/2g — analyst-triggered, bounded; AI-off declines cleanly; insufficient-evidence honesty (test #7).
