# Pre-code Gate — Copilot completion, increment 2: agentic investigation — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 21 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies.
Origin: capability audit §A — the copilot reasons over one pre-assembled evidence blob; it cannot pull more data, run a hunt, or pivot mid-conversation. This increment gives it **read agency** — the ability to *investigate*, not just summarize. (Increment 1 = AI-authored proposals ✅. Increment 3 = RAG/#180.)
Scope: **security-sensitive** — the LLM gains the ability to *initiate queries*. Falsification bar: "what lets the copilot see beyond the analyst's own permissions, run a raw/unbounded query, leak un-redacted results, loop without bound, or gain execute (not just read) agency."

## 0. The non-negotiable — READ agency only, never EXECUTE
This increment lets the copilot **read** (run bounded hunts / pivot). It does NOT let the copilot **act** — response actions stay the increment-1 proposal path (LLM drafts → human `soc_manager+` accepts → the verified soar gate). `internal/ai` stays soar-exec-free (`check-ai-no-direct-execution` green). The copilot can investigate; it cannot contain.

## 1. Current state, verified at source (the safe primitives already exist)
- **`RunHunt`** (verified, saved-views review): allow-list → bound-params compiler, field registry, cost ceiling, read-audit, and it **re-validates for the RUNNING actor** (field-visibility). A hunt grants no capability the caller lacks — the escalation-safety property proven in #64.
- **`completeExternal`** (verified): the redaction chokepoint every LLM egress rides.
- **`AssembleContext`** (verified): bounded, cited, tenant-scoped grounding.
- `check-ai-no-direct-execution` + `check-ai-egress-redaction` fences green.

## 2. Design — LOCKED

### 2a. The copilot acts AS the conversing analyst (no escalation — the crux)
Every agentic hunt runs through **`RunHunt` with the conversing analyst's principal `p`** — so it is re-validated for that analyst's field-visibility, tenant, cost ceiling, and read-audit. The copilot can NEVER surface data the analyst couldn't query directly. This is the saved-views property applied to the agent loop: the tool runs *as the user*, bound by the user's permissions — not as a privileged service identity.

### 2b. Structured tool calls only — no raw query, no free-form
The LLM does NOT emit SQL or a free-form query. It emits a **structured hunt request** (All/Any predicates over the **field-registry vocabulary** + a bounded window), which the backend **re-compiles through the same allow-list → bound-params path** as `RunHunt`. An off-registry field, a raw clause, or an unparseable tool call is **rejected** (the compiler is the gate — the LLM fills a bounded template, it does not author SQL). Same discipline as increment-1's catalog-bound action and the saved-views compiler.

### 2c. Results ride the redaction chokepoint
Hunt results fed back to the model go through **`completeExternal`** — redacted per the acting analyst's field-visibility, same as all other AI egress. No raw customer telemetry reaches the LLM. `check-ai-egress-redaction` stays green. Cited results keep the assembler/hunt-provided ids; invented ids dropped.

### 2d. Bounded iteration — no runaway loop
The agent loop is **hard-capped** (max K tool-calls per turn, K small, config-seeded). On hitting the cap the copilot **stops and answers with what it gathered** (or declines) — it never loops unbounded. Each hunt is additionally bounded by the existing cost ceiling. Total egress per turn is bounded (the token budget + the hunt cap). Fail-closed: an over-cap or over-cost request stops the loop, it does not silently widen.

### 2e. Tool calls are validated + executed by the BACKEND, not the LLM
The LLM *requests* a hunt; the **backend validates and runs it** and returns the redacted result. The LLM never executes anything itself — no code path lets an LLM tool call reach a mutation, a soar action, a connector, or a raw DB call. The available tools are a **closed set** (run-hunt, pivot-entity, get-timeline — all read-only, all `RunHunt`/verified-reader backed). Adding a tool is a code change that re-enters this gate.

### 2f. Scope + audit
Agentic hunts are **tenant-scoped** (the analyst's tenant — no cross-tenant, RLS + the principal enforce it) and each hunt is **audited** (read-audit, like `RunHunt`, plus the copilot turn records which tools it invoked — accountability for what the AI queried). Optionally incident-scoped when the session is incident-bound.

## 3. GUARANTEE (teeth — the existing fences must STAY green + one addition)
- **`check-ai-no-direct-execution`** stays green — the agentic tools are read-only (`RunHunt`/readers); `internal/ai` references no soar/connector/mutation symbol. The tool registry contains **no** write/execute tool. This is the load-bearing structural guarantee (read agency ≠ execute agency).
- **`check-ai-egress-redaction`** stays green — every tool result to the model rides `completeExternal`.
- **Tool-registry fence (new, optional but recommended):** assert the copilot's tool set is a closed allowlist of read-only tools, so a future tool that mutates/executes can't be added without tripping CI. Mirror the sibling `check-*.sh`.

## 4. Falsification tests (each mutation-sensitive)
1. **No escalation:** a hunt the copilot runs for a junior analyst re-masks a field the analyst can't see (RunHunt re-validates for `p`); the copilot never surfaces beyond the analyst's field-visibility. Mutation: run the tool as a service/elevated principal → RED.
2. **No raw query:** an off-registry field or raw clause in a tool call is rejected by the compiler; only structured registry predicates run.
3. **Redaction holds:** a customer identifier in a hunt result egresses to the model masked (`completeExternal`); the egress fence stays green.
4. **Bounded loop:** the agent stops at K tool-calls (no unbounded iteration); an over-cap request ends the loop, doesn't widen.
5. **Read-only / soar-free:** the tool registry contains no execute/mutate tool; `internal/ai` references no soar symbol; the copilot can hunt but not contain. Fence green.
6. **Cost ceiling:** each hunt is bounded by the cost ceiling; a runaway query is capped.
7. **Tenant-scoped:** agentic hunts never cross the analyst's tenant (RLS + principal).
8. **Audit:** each agentic hunt + the tools invoked in a turn are audited.

## 5. Out of scope (later / follow-ons)
RAG over case history / #180 (increment 3) · the copilot executing response actions (stays the increment-1 proposal path, human-accepted) · autonomous/unattended investigation (this is analyst-in-the-loop, per-conversation) · multi-model routing · tools that write/mutate anything.

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a — every agentic hunt runs through `RunHunt` with the conversing analyst's principal; re-validated for field-visibility (test #1).
- [ ] 2b — structured tool calls only, re-compiled via allow-list→bound-params; off-registry/raw rejected (test #2).
- [ ] 2c — results ride `completeExternal`; redaction + citation-integrity hold (test #3).
- [ ] 2d — hard tool-call cap per turn + cost ceiling; fail-closed on cap (tests #4, #6).
- [ ] 2e — closed read-only tool set; backend validates+runs, LLM never executes; no write/mutate/soar tool (test #5).
- [ ] 2f/3 — tenant-scoped + audited; fences (`check-ai-no-direct-execution`, `check-ai-egress-redaction`, tool-registry) green (tests #7, #8).
