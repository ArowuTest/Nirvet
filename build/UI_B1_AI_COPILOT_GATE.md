# Pre-code gate — B1: AI copilot investigation workspace (§6.12 AI-001, UI-depth Bucket B)

**Highest-consequence Bucket-B slice.** New LLM egress path → must not weaken the #188 redaction chokepoint.
Gate precedes code ([[feedback_nirvet_gated_approach]], [[feedback_nirvet_no_hardcoding]]).

## Problem / SRS grounding
§6.12 AI-001 envisions an analyst copilot. Today the AI package exposes only single-shot `SummariseAlert` /
`TriageIncident`. There is **no multi-turn conversational endpoint** and no persisted workspace. Analysts need a
chat surface that (a) keeps history, (b) can be grounded in a case, and (c) never leaks raw customer telemetry to
a third-party LLM.

## The one invariant that dominates this slice — the egress fence
`scripts/check-ai-egress-redaction.sh` FAILS the build unless there is **exactly one** `.Complete(ctx` call in
the whole `internal/ai` package, inside `Service.completeExternal`. That function redacts (mask-by-default) the
fenced `evidence []string` BEFORE calling the provider. **The copilot MUST reuse `completeExternal` and MUST NOT
call `prov.Complete` itself.** Concretely:
- **Case context** (incident/alert telemetry — customer data) → passed as `evidence []string` → gets **redacted**
  and wrapped in the injection-defense fence (`fenceBlock` sentinel).
- **Conversation** (the analyst's own prior turns + new question) → passed as the `instruction` string (lives
  OUTSIDE the fence, raw). This matches the existing trust model: the analyst is a trusted internal user typing
  their own words; only monitored-system telemetry is treated as untrusted and redacted.
- `systemPrompt` ("You are Nirvet's SOC analyst copilot… you never take actions") is already copilot-appropriate.
Result: one turn = one `completeExternal` call = fence stays green.

## Design
### Persistence (real workspace, not stateless) — mig 0123, RLS FORCE + owner_bypass
- `ai_copilot_sessions`: `id` PK, `tenant_id` DEFAULT app_current_tenant(), `user_id` uuid (owner — sessions are
  private to the creating analyst), `title` text, `incident_ref` uuid NULL (optional grounding), `created_at`,
  `updated_at`.
- `ai_copilot_turns`: `id` PK, `tenant_id` DEFAULT, `session_id` uuid FK→sessions ON DELETE CASCADE, `role` text
  CHECK IN ('user','assistant'), `content` text, `model` text, `redaction` jsonb (audit-only counts, no
  cleartext), `created_at`.
- Both: `ENABLE`+`FORCE ROW LEVEL SECURITY`, `tenant_isolation` (tenant_id = app_current_tenant()) policy,
  `owner_bypass` policy (else `schemacheck.TestOwnerBypassPolicy` reds on managed PG), `GRANT … TO nirvet_app`.

### Service (`internal/ai/copilot.go`)
- `StartSession(ctx,p,title,incidentRef)`, `ListSessions(ctx,p)` (own only), `GetSession(ctx,p,id)`
  (session+turns; RLS + user_id ownership → 404 otherwise).
- `Ask(ctx,p,sessionID,message)`:
  1. Load session (own+tenant) → 404 if not. Reject empty/over-long message (bounded).
  2. Load prior turns (bounded to the last N for context/cost).
  3. Build **evidence** from `session.incident_ref` if set (incident title/severity/stage via existing
     `s.incidents.Get`) — customer telemetry → redacted at the chokepoint.
  4. Build **instruction** = flattened history (`Analyst: … / Copilot: …`) + the new question + `Copilot:`.
  5. `resolve` the tenant provider; if `Available()` → `completeExternal(evidence, instruction)`; else a truthful
     fallback assistant message ("AI provider is not configured for this tenant") — no egress, no fake answer.
  6. Persist the user turn + the assistant turn (model + redaction counts). Bump session.updated_at.
  7. `audit.Record` `ai.copilot_message` with model + provider + redaction meta (reuse withProviderMeta/withRedactionMeta).
  8. Return the assistant turn.

### Routes (`cmd/api/main.go`) — analyst-usable, AI-rate-limited
- `POST /ai/copilot/sessions` (aiProvider), `GET /ai/copilot/sessions` (aiProvider),
  `GET /ai/copilot/sessions/{id}` (aiProvider), `POST /ai/copilot/sessions/{id}/messages` (aiProvider, aiLimit).
- Add all to `api/openapi.yaml` (parity CI).

## Invariants / guardrails
1. **Fence green** — no new `.Complete(ctx`; only `completeExternal`. Verify by running the fence script.
2. **RLS + ownership** — sessions/turns tenant-scoped AND user-owned; a peer or another tenant cannot read a
   session. New RLS tables get `owner_bypass` (mig).
3. **Redaction preserved** — case telemetry only ever egresses via `evidence` (redacted); the analyst's free text
   is their own. Assistant turns store redaction **counts** only, never cleartext placeholders.
4. **No-hardcoding / honest** — provider disabled → truthful "not configured" fallback, never a fabricated answer.
   History window + message length bounds are constants-as-limits (safety caps), not policy — acceptable; no
   business threshold is hardcoded.
5. **Assistive-only** — the copilot never takes actions (systemPrompt enforces; no tool calls, no SOAR reach).
6. CI: gofmt/vet/build, egress fence, owner_bypass, OpenAPI parity, from-zero migration.

## Tests
- Unit: `buildInstruction` flattens history in order + appends the new question + trailing `Copilot:`.
- DB-gated integration: StartSession → Ask (provider disabled path) persists a user + assistant turn with the
  fallback content; GetSession returns them in order; a second tenant's GetSession on the id returns not-found
  (isolation). Guard with `testsupport.RequireDSN`.

## UI (after backend green)
`console/copilot` (nav: Operations > AI Copilot): left = session list (+ New), right = chat transcript
(user/assistant bubbles) + composer; optional "ground in incident" field when starting a session; a persistent
note that responses are assistive-only and customer data is redacted before egress. 403/disabled → honest state.

## Out of scope (deferred)
RAG over historical cases, tool-use/agentic actions, streaming tokens — not in this slice; the copilot stays
single-request-per-turn and assistive-only.
