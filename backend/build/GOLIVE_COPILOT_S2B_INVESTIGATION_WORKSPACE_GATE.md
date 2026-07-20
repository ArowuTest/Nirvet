# Pre-code Gate — S2b: Copilot investigation-workspace depth (context assembler + response-proposals-through-SOAR)

Status: **CLEARED TO BUILD — reviewer-authored + owner-confirmed (Jul 19 2026).** Loop: ~~reviewer writes → owner confirms decisions~~ ✅ → builder implements → CI-green → reviewer source-verifies. All §5 decisions LOCKED.
Scope: **P/B** (product-differentiator depth; not go-live-gating, but the security half is HEAVY). External-review origin: `outputs/NIRVET_AI_COPILOT_EGRESS_REVIEW.md` §2 (grounding too shallow) + §10 (AI response-proposals must route through SOAR, never direct execution).

## 0. The TWO non-negotiables (this whole gate exists to protect them)

1. **AI NEVER executes a response action — directly or indirectly.** Verified at source TODAY: `internal/ai/*.go` has **zero** references to `soar`/`actioner`/`executeRun`/`FireContainment` — the boundary is currently *structural* (the AI package cannot reach execution). S2b MUST preserve this: the AI produces a **proposal (data)**; a human promotes it into the **existing** `RunPendingApproval` pipeline (`soar/service.go:357`), which then runs through the authority gate (`Allowed(mode,risk)`), four-eyes, D5 crown-jewel guard, `authority_policies` — all reviewer-verified. The AI is strictly *upstream* of gates that already exist; it bypasses none.
2. **A richer context assembler egresses MORE customer telemetry to the third-party LLM** — so it MUST flow through the redaction chokepoint (`completeExternal`, the P0 fix). Assembled context is UNTRUSTED customer data, not a trusted instruction. No assembler output may reach `prov.Complete` except as a redactable bag.

If either is weakened, the slice is rejected regardless of feature completeness.

## 1. Current state, verified at source
- Copilot grounding is **3 fields** (`copilot.go:212-216`: incident_title/severity/stage) — too shallow for a real investigation (external review §2).
- Egress goes through `completeExternal(egress{task, evidence[], history[], question[]})` — evidence redacted on tenant policy, history strict, question balanced-floor (P0). The assembler plugs into `evidence`.
- `internal/ai` imports NO soar-execution symbol (grep-clean). The AI-cannot-execute invariant holds structurally today.
- Tenant-scoped readers exist to cite: `alert`, `incident`, `correlation`/timeline, `entitygraph`, threat-intel, SOAR run history, investigation notebook cells — all called with `p.TenantID`.

## 2. Part 1 — Investigation Context Assembler (bounded · cited · tenant-scoped · redacted-at-egress · honest)

A new component `internal/ai/contextassembler.go` (`AssembleContext(ctx, p, incidentID, opts) → ([]CitedFact, error)`) that, for an incident, gathers a **bounded** evidence package and tags each fact with a **stable citation id**:

| Source | Cite prefix | Notes |
|---|---|---|
| Incident summary | `INC` | title/severity/stage/owner (today's 3 fields + a few) |
| Associated alerts | `ALERT-n` | via `alert.Service.List` scoped to the incident |
| Event timeline facts | `EVT-n` | key events, tenant-scoped |
| Affected entities / assets | `ENT-n` / `ASSET-n` | from entitygraph / asset |
| MITRE techniques | `MITRE-n` | from the detection/correlation mapping |
| Threat-intel matches | `TI-n` | STIX indicator hits |
| SOAR actions already taken | `SOAR-n` | run history for the incident (read-only) |
| Analyst-selected notebook cells | `NB-n` | ONLY cells the analyst explicitly selected (not the whole notebook) |

**Hard requirements:**
- **REDACTION (non-negotiable #2):** the assembled facts are passed as the `evidence []string` bag into `completeExternal` — every fact flows through `redactLines`. **No assembler output may be concatenated into `task`/`question` raw.** A test proves a customer identifier inside an assembled fact egresses masked, mutation-sensitive (skip assembler redaction → RED) — same pattern as the P0 tests.
- **TENANT-SCOPING (B4 discipline):** every reader is called with `p.TenantID`; the assembler can NEVER read another tenant's incident/alerts/entities. A two-tenant test: assembling tenant A's incident context as a tenant-A principal never surfaces tenant B data.
- **CITATIONS ARE ASSEMBLER-PROVIDED, NOT AI-FABRICATED:** the assembler owns the `id → fact` map; the system prompt instructs the model to cite ONLY those ids; on the way back, **the backend validates every cited id resolves to an assembler-provided fact and drops/flags any id the model invented** (an AI can't cite evidence it wasn't given). The FE resolves ids to the real fact on display.
- **BOUNDED + "insufficient evidence" honesty:** token-budget the package (folds in the deferred P2 token-budget item); when the package is thin, the prompt lets the copilot answer "insufficient evidence" rather than fill gaps (external review §2).

## 3. Part 2 — AI response-proposals routed through SOAR (the HEAVY security half)

The copilot may **propose** a response; it may never **run** one.

- **Proposal = a DATA record**, NOT a run. New `ai_response_proposals` (tenant-scoped, RLS'd): `{id, tenant_id, incident_ref, proposed_by=ai, recommended_action, connector_key, rationale, evidence_citations[], risk_class, reversible, expected_impact, status}`. The AI writes a proposal; it does not touch `soar` execution.
- **Human promotes proposal → pending run.** An analyst reviews/edits/accepts a proposal; ACCEPT creates a `RunPendingApproval` via the EXISTING soar entry — which then goes through `Allowed(mode,risk)` + four-eyes + D5 + `authority_policies`. So there are **two** human/authority gates between AI-proposes and action-executes: (a) analyst accepts the proposal, (b) the run's authority/approval gate. The AI adds a recommendation upstream; it removes no gate.
- **Recommended-action vocabulary is constrained** to the existing catalog action keys (no free-form command); an unknown action → the proposal is invalid. The AI cannot propose an action the catalog + authority model doesn't already govern.

## 4. Non-decorative GUARANTEE (the teeth — mirrors the egress/authz fences)

- **Structural fence `scripts/check-ai-no-direct-execution.sh`** (the crown-jewel of this gate): assert `internal/ai/**` contains NO reference to the soar execution surface — `executeRun`, `RunForTarget`, `FireContainment`, `runFor`, the actioner registry, or an import of the connector actioner packages. The AI package may reference the **proposal repo** and read-only readers ONLY. This makes "AI never executes" recurrence-proof — a future refactor that wires the copilot to an actioner breaks CI. Mutation-proven: add a call to `executeRun` in an ai file → RED.
- **Egress coverage** — the existing `check-ai-egress-redaction.sh` already asserts everything through `completeExternal` is redacted; the assembler output rides the `evidence` bag, so it's covered. Add an assertion (or test) that `AssembleContext` output is passed to `completeExternal` as `evidence`, never appended to the prompt raw.
- **Proposal ≠ execution test:** creating/accepting a proposal never calls an actioner; mutation-sensitive.
- **Citation-integrity test:** a model response citing a non-assembler id is dropped/flagged (no hallucinated authority).

## 5. DECISIONS LOCKED (owner-confirmed, Jul 19 2026)
- **Proposal model = SEPARATE `ai_response_proposals` record**, human-promoted. The AI writes a proposal; it does NOT create a `RunPendingApproval` directly. A human ACCEPT is what creates the pending run → the existing authority pipeline. (Cleaner audit + one more step removed from execution.)
- **Accept authority = senior / SOC-manager role** (NOT any analyst). The `POST /.../proposals/{id}/accept` route is guarded by `senior`/`soarApprover` (Fence B enforces it) and audited.
- **Citations: backend HARD-DROPS invented ids.** A model response citing an id not in the assembler's `id→fact` map has that citation stripped (not merely flagged) before display/persist — an AI cannot surface a citation to evidence it wasn't given.
- **First-slice assembler sources = INC + ALERT + EVT + ENT + SOAR-history** (5 sources). MITRE / threat-intel / notebook-cells land in a second pass. Bounds the initial build.

## 6. Out of scope (follow-ons)
Auto-proposal (AI proposing without an analyst asking) — first slice is analyst-initiated only · proposal→run auto-promotion (always human) · multi-incident correlation context · the structured-multi-message-roles refactor (separate copilot SHOULD).

---
### Reviewer sign-off (owner confirms §5 decisions; I source-verify after CI-green)
- [ ] Non-negotiable #1 preserved: `check-ai-no-direct-execution.sh` fence exists + mutation-proven; AI writes a proposal, human promotes to the existing `RunPendingApproval` pipeline; no gate bypassed.
- [ ] Non-negotiable #2 preserved: assembler output flows through `completeExternal` as the redacted `evidence` bag; PII-in-assembled-fact masks (mutation-sensitive).
- [ ] Context assembler is tenant-scoped (two-tenant test — never crosses tenants).
- [ ] Citations are assembler-provided; invented ids dropped/flagged (citation-integrity test).
- [ ] Recommended-action vocabulary constrained to the existing catalog (no free-form command).
- [ ] Proposal accept step is authz-guarded (senior/manager) and audited.
