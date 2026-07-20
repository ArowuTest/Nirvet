# S2b i3 — AI response-proposals build notes (two calls the gate left implicit)

Built against `GOLIVE_COPILOT_S2B_INVESTIGATION_WORKSPACE_GATE.md` §3/§5. Both non-negotiables preserved:
NN#1 (AI never executes) — the proposal is a DATA record in `internal/ai`; the accept path that reaches `soar`
lives OUTSIDE `internal/ai` (`internal/airesponse`), so `check-ai-no-direct-execution.sh` stays green. NN#2
(redaction) — untouched; i3 adds no new `prov.Complete` egress (proposals are DB records, not LLM egress).

The gate locked the proposal SHAPE (action-centric: `recommended_action`, `connector_key`, …; **no** `playbook_id`)
and said "ACCEPT creates a RunPendingApproval via the EXISTING soar entry." Two mechanics were left implicit;
here are the calls and why each is the SAFE reading. Flagged explicitly for the falsification pass.

## Call 1 — how a single proposed action becomes a run (the accept→run mechanic)

**Fact at source:** the SOAR engine's only runnable unit is a **playbook**. `runFor` (soar/service.go:247) loads a
playbook and resolves each step against the catalog + authority. There is deliberately **no single-action execution
entry** — the comment at soar/service.go:281-283 states the auto-eligibility line is "the ONLY auto-eligibility
computation in the codebase … there is no second decision point to bypass it."

**Call:** ACCEPT requires the promoting senior to supply the **enacting `playbook_id`**
(`POST /ai/proposals/{id}/accept` body `{playbook_id}`). The accept usecase validates the playbook belongs to the
tenant AND its steps **contain the proposal's `recommended_action`** (so a senior cannot accept proposal X but run an
unrelated playbook Y), then calls the EXISTING `soar.Service.Run(seniorPrincipal, playbookID, &incidentRef)`.

**Why this is the safe reading (not a new single-action runner):** inventing a "run this one action" path would add a
**second** auto-eligibility decision point — exactly what soar/service.go:281-283 forbids. Reusing `Run` routes through
the single existing decision point, so `Allowed(mode,risk)` + `!FleetWide` + four-eyes + D5 + `authority_policies` all
apply unchanged. The senior selecting the enacting playbook IS the gate's "analyst reviews/edits/accepts" step.
`recommended_action ∈ catalog` is still enforced at CREATE (fail-closed); the enacting playbook's own steps are
catalog-resolved by `runFor`. Two human gates preserved: **(a) senior accepts** (+ picks the playbook), **(b)** the
run's approval gate (four-eyes: the accepting senior becomes `RequestedBy`, so a DIFFERENT approver must clear any
pending step).

**Run disposition is the authority model's, not forced-pending.** The gate says accept "creates a RunPendingApproval";
mechanically the run lands `pending_approval` for anything not pre-authorized, but a tenant whose OWN authority policy
pre-authorizes a low-risk, non-fleet action may auto-run it — identical to a human running that playbook directly. The
AI removed no gate; forcing-pending would diverge from the existing entry and create a special path. Documented, not
special-cased.

**Double-promotion guard:** `MarkProposalAccepted` transitions `pending→accepted` with `WHERE status='pending'` (checks
RowsAffected); two concurrent accepts both hit `soar.Run` (idempotent per (playbook, incident) → ONE run) but only one
`MarkAccepted` wins — no double execution.

## Call 2 — origin of the `recommended_action` string (first slice)

**Scope (gate §5/§6):** first slice is **analyst-initiated only**; auto-proposal (AI proposing unprompted) is
out-of-scope. **Call:** `CreateProposal` takes `recommended_action` as input and validates it **∈ the tenant's action
catalog** (via an injected `ActionCatalogReader`; fail-closed if the action is unknown or the reader is unwired). The
"AI" nature is that this surfaces in the AI copilot workspace as the AI-assisted recommendation.

**Why not an LLM→action-key path now:** trusting raw LLM free-text as an executable action key is a hallucination risk,
and the gate's non-negotiables are about the proposal→run PIPELINE, not how the string is produced. Structured
LLM-authored action selection is a follow-on that changes **nothing** about the security pipeline (same catalog
validation, same human accept, same existing run gates) — only the origin of the string. Kept out to avoid a risky new
egress/parse surface in the security-sensitive slice.

## Files
- mig `0137_ai_response_proposals.sql` — tenant-scoped, FORCE-RLS + `tenant_isolation` + `owner_bypass`; no DELETE grant.
- `internal/ai/proposal.go` — entity + repo ops + `CreateProposal` (data only) + `ActionCatalogReader` + status transitions.
- `internal/ai/proposal_handler.go` — `POST /ai/proposals` (propose), `GET /ai/proposals` (list), `POST /ai/proposals/{id}/reject` (aiProvider).
- `internal/soar/authoring.go` — public read `GetPlaybook` (accept action-match validation only; read-only, no execution).
- `internal/airesponse/` — the OUTSIDE-`internal/ai` accept usecase + handler (imports soar); `POST /ai/proposals/{id}/accept` (soarApprover + in-service manager assert).
- `cmd/api/main.go` — `actionCatalogReader` adapter (`WithActionCatalog`), airesponse handler, route mounts.
