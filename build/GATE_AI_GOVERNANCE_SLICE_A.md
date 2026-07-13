# Pre-code gate — §6.12 AI Governance (slice A): Prompt Registry + Eval Harness + Feedback

Status: GATE (written before code, per the gated-approach doctrine). Grounds every table/endpoint in the SRS.
Scope owner: builder (champion dev) under standing sign-off; interim security reviewer to pass at landing.

## Why now (owner decision, 2026-07-13)
Backend-first: the AI-governance **surfaces** (prompt versions, eval runs, feedback, hallucination metrics) each
have an admin/observability UI. They must exist in the backend BEFORE the AI console is designed (design pass
#183), or the UI is retrofitted — the exact drift the external auditor flagged. The **eval content itself** is
buildable now (curated golden set, like the seed detections/playbooks); only threshold *calibration* against real
customer traffic waits. So slice A builds the surfaces AND a seed eval suite + a hermetic runner.

## SRS grounding (§6.12 + §11)
- **AI-002** — outputs grounded in retrieved evidence + **cite** underlying alerts/events/entities/notes/steps.
- **AI-003** — distinguish facts / inferences / assumptions / recommended actions.
- **AI-005** — log prompts, context packages, outputs, edits, approvals, rejections, feedback **for audit and
  model evaluation**. (Prompt registry = the versioned prompt half; feedback labels = the feedback half.)
- **AI-007** — model selection (private/hosted/customer-managed/no-AI). Provider config already landed (#117);
  this slice adds the **prompt+model version pin** so a prompt names the model it was validated against.
- **AI-008** — safety tests for **hallucination, unsafe recommendation, cross-tenant leakage, prompt injection,
  unsupported claims**. This is the eval harness's category set — 1:1.
- **§11** — feedback labels {useful, incorrect, unsafe, hallucinated, insufficient_evidence, accepted, edited};
  periodically evaluate AI outputs against analyst-reviewed ground truth.

## What slice A builds (and what it does NOT)
IN: prompt registry (versioned, model-pinned, admin-managed, seeded); eval golden set (seeded, 6 AI-008
categories); eval runner with a **deterministic hermetic Judge** (CI-safe, no live LLM) + a pluggable
LLM-judge interface (DORMANT); eval-run + per-case results; feedback labels on AI outputs; metrics; admin +
tenant endpoints; OpenAPI + CI guard; seed content.
OUT (deferred, tracked): calibrating pass thresholds to real traffic; expanding the corpus from real failure
modes; RAG-over-case-history; wiring the live copilot to auto-log every interaction to AI-005 (governance log is
schema-ready here; the copilot write-path is a follow-on). LLM-as-judge stays dormant until a provider is set.

## Data model (migration 0120; all RLS + owner_bypass + FORCE, mirroring 0118/0119)
Prompt registry + eval suite/cases are **platform-global content** (tenant_id NULL, padmin-managed) exactly like
detection seed content and the global provider row. Feedback is **tenant-scoped** (RLS own-tenant).

1. `ai_prompt` — logical prompt key (unique): key, title, description, purpose (triage_summary|incident_narrative|
   root_cause|next_steps|report_draft|timeline_explain), created_at.
2. `ai_prompt_version` — (prompt_id, version int, body text, model text (the pinned model it was validated on),
   status (draft|active|archived), notes, created_by, created_at). At most ONE active version per prompt
   (partial unique index WHERE status='active'). Immutable body once not-draft (guard in service).
3. `ai_eval_case` — golden case: suite, name, category (grounding|hallucination|prompt_injection|tenant_leakage|
   unsupported_claim|factual — the AI-008 set), context_json (the retrieved-evidence package), question,
   expected_json (graded criteria: must_cite[], must_not_contain[], must_refuse bool, canary strings…), enabled.
4. `ai_eval_run` — (id, prompt_id, prompt_version, judge (deterministic|llm), started_at, finished_at,
   total, passed, failed, pass_rate numeric). Records who ran it (created_by).
5. `ai_eval_result` — (run_id, case_id, category, passed bool, score numeric, rationale text) — per-case detail.
6. `ai_output_feedback` — tenant-scoped: (id, tenant_id, output_ref text, label (§11 enum), note, created_by,
   created_at). output_ref is a soft reference (interaction/output id string), not an FK — decouples from the
   copilot's storage so feedback works before the AI-005 write-path lands.

## Must-adds (the guardrails, decided up front)
- **M-1 Injection-class fence:** the Judge and seed cases MUST cover all five AI-008 classes; a CI test asserts
  every category has ≥1 seed case and the runner has a check for each (no silent gap — the recurring theme from
  R2–R6 reviews). Mirrors scripts/check-playbook-actions-cataloged.sh.
- **M-2 Hermetic by default:** slice-A Judge is deterministic (string/structced checks over context+criteria) so
  eval runs in CI with NO network + NO provider. LLM-judge is behind an interface and DORMANT (returns
  "unavailable" until a provider is configured) — never a hidden live call.
- **M-3 Tenant-leakage case is structural:** the tenant_leakage category asserts the output contains none of a
  planted OTHER-tenant canary — proving retrieval scoping, aligned with SRS §6.9/§2259.
- **M-4 Grounding = citation presence + no-unsupported-claim:** grounding/unsupported_claim judges check the
  answer's atomic claims against the provided context (must_cite present; must_not_contain absent) — deterministic.
- **M-5 Audit + fail-safe:** prompt activate/archive, eval-run start, and feedback submit all write immutable
  audit events (ADR-0004 class). Activating a new prompt version is four-eyes-free but audited; the OLD active
  version is archived atomically (one active per key). Feedback label 'unsafe'/'hallucinated' increments a metric.
- **M-6 No content egress:** eval context_json is platform-authored synthetic data (no real tenant content in the
  global golden set) — a CI check forbids importing tenant tables into the eval package (mirror
  check-posture-no-content-import.sh intent).

## Metrics
`nirvet_ai_eval_pass_rate` (gauge, per last run), `nirvet_ai_eval_runs_total` (counter),
`nirvet_ai_feedback_total{label}` (counter), `nirvet_ai_grounding_failures_total` (counter).

## Endpoints (padmin unless noted; tenant routes are role-gated interactive)
- padmin: `GET/POST /admin/ai/prompts`, `POST /admin/ai/prompts/{key}/versions`,
  `POST /admin/ai/prompts/{key}/versions/{v}/activate`, `GET /admin/ai/eval/cases`,
  `POST /admin/ai/eval/runs` (run a prompt's active version against the suite), `GET /admin/ai/eval/runs`,
  `GET /admin/ai/eval/runs/{id}`.
- tenant (analyst): `POST /ai/outputs/{ref}/feedback`, `GET /ai/outputs/{ref}/feedback`.

## Definition of done
Build+vet clean; migration applies from-zero AND incrementally; schemacheck green (new tables have
tenant_isolation+owner_bypass+FORCE where tenant-scoped; global tables GRANT+owner_bypass); runner passes the
seed suite deterministically; M-1..M-6 tests green; OpenAPI parity test green; CI guard added; committed as
ArowuTest; CI green. Reviewer landing pass queued.
