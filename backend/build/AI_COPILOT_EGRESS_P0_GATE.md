# Pre-code Gate — P0: AI Copilot conversation-content redaction bypass (+ audit-output relocation + guard coverage)

Status: **DRAFT — awaiting reviewer pass.** Loop: this note → reviewer pass → build → CI-green → reviewer source-verification.
Severity: **P0 — must land before any external AI call on real customer data.** Confirmed at source by builder + reviewer + external review ([outputs/NIRVET_AI_COPILOT_EGRESS_REVIEW.md](../../outputs/NIRVET_AI_COPILOT_EGRESS_REVIEW.md)).

## 1. The bug, verified at source

`internal/ai/service.go:130` `completeExternal(ctx, tenantID, prov, lines []string, instruction string)`:
```go
redacted, rr := redactLines(lines, policy, patterns)   // ONLY the case-evidence `lines` are masked
user := fenceBlock(redacted) + instruction             // `instruction` is appended RAW
text, err := prov.Complete(ctx, systemPrompt, user)    // → egress to the third-party LLM
```
`instruction` is built by `copilot.go:buildCopilotInstruction(history, message)` = a trusted preamble **+ every prior turn's `Content` (analyst and assistant) + the new analyst `message`**, all concatenated raw. So **analyst-typed PII (IPs, Ghana Card, tokens, raw log lines) and any identifier echoed in a prior assistant turn egress to the LLM UNREDACTED.** Only the 3-line incident evidence (`title/severity/stage`) is masked.

**Why CI is green today:** `scripts/check-ai-egress-redaction.sh` enforces that `.Complete(ctx` is called **exactly once, inside completeExternal** — i.e. *routing* (one chokepoint), not *coverage* (that everything reaching `Complete` is masked). A raw string concatenated inside the chokepoint sails straight through. This is the "a check that passes without checking" family: the guard proves the door is single, not that what goes through it is clean.

Bundled same-class finding — `service.go:65` `auditMeta`: stores the model **output** (≤8000 chars, raw) in the AI-call audit record. `audit_log` is broad-access; model output can echo customer PII. It already computes `output_sha256` + `output_chars` — the raw `output` field is the leak.

## 2. Required fix (P0)

### 2a. Redact ALL untrusted content before egress — three content classes
- **Trusted system prompt** (fixed `systemPrompt` + the chat preamble) → NOT redacted (it is ours, no customer data).
- **Untrusted conversation** (the analyst's new `message` + every prior turn's `Content`) → **redacted + fenced**, same policy/patterns as evidence.
- **Case evidence** (`lines`) → redacted (as today).

**Structural refactor so raw content CANNOT reach `Complete`:** change `completeExternal` to take a single **untrusted bag** and redact all of it:
```go
completeExternal(ctx, tenantID, prov, untrusted []string) (string, RedactionResult, error)
// user = fenceBlock(redactLines(untrusted, policy, patterns)); no raw concatenation exists.
```
- Move the trusted chat preamble out of `buildCopilotInstruction` into `systemPrompt` (trusted).
- `Ask` builds `untrusted` = evidence lines **+** one line per prior turn (`who + ": " + Content`) **+** `"Analyst: " + message`. Every element flows through `redactLines`. There is no longer an `instruction string` param, so there is nowhere to append raw text — the bug becomes unrepresentable, not just fixed.
- **SHOULD (recommended, not required for P0):** move to the provider's structured multi-message roles instead of one flattened `user` string (shrinks the prompt-injection surface). That touches `Provider.Complete` + every impl (openai/anthropic/gateway) → a follow-on; the P0 minimum is redaction coverage above, keeping the existing fenced-string transport.

### 2b. Relocate raw model output out of `audit_log`
`auditMeta`: **drop the `"output"` field.** Keep `model`, `output_chars`, `output_sha256`. The full assistant text already persists in the transcript `ai_copilot_turns.content` (RLS + `user_id` scoped) — that is the restricted home for it. Audit keeps the hash + length for integrity/forensics without the cleartext.

### 2c. Extend the egress guard from routing → coverage
`scripts/check-ai-egress-redaction.sh` keeps its single-call-site assertion AND adds a coverage assertion so a future raw concat can't silently reappear:
- Assert `completeExternal` no longer accepts a raw untrusted `string` param (its untrusted input is `[]string`, which the body passes through `redactLines`).
- Assert the `user` argument to the one `.Complete(ctx` call is built **only** from `fenceBlock(redactLines(...))` — fail if any `+ <ident>` raw concatenation feeds `user`.
Structural (grep/AST-lite in bash, matching the repo's other `check-*.sh` fences), not a runtime check.

## 3. Tests (must fail on the bug; mutation-checked)

- **Conversation PII never egresses** — a capturing fake `Provider` records the `user` string. `Ask` with an analyst message containing an email / IP / API token / Ghana Card number → assert the captured `user` contains the redaction placeholder, NOT the cleartext. **Mutation: skip conversation redaction (restore the raw `+ instruction`) → RED.**
- **Prior-turn PII** — seed a prior assistant turn whose `Content` holds a secret; on the next `Ask`, assert the captured `user` has it masked (proves history, not just the new message, is covered).
- **Trusted preamble intact** — the system prompt / chat framing is NOT mangled by redaction (assert it still reaches `Complete` as the system arg).
- **Audit has no cleartext** — after `Ask`, the `ai.copilot_message` audit metadata has `output_sha256` + `output_chars` and NO `output` field; the transcript row still has the full reply.

## 4. Out of scope (separate follow-ons, reviewer-listed — NOT this gate)
P1: context assembler with citations · `MoveCell` `FOR UPDATE` lock (match `AddCell`) · validate `incident_ref` by tenant at creation · notebook↔copilot with AI **response proposals routed through SOAR** (never direct execution — non-negotiable). P2: persist-user-turn-first + turn `sequence_number`/idempotency · version history · token-budgeted context · rename/archive. **SOAR "AI cannot execute actions directly" invariant is untouched by this gate.**

---
### Reviewer sign-off
- [ ] 2a — the three-class split + `[]string` untrusted-bag refactor (bug becomes unrepresentable) — right shape?
- [ ] 2a SHOULD — structured multi-message roles as a follow-on (not P0) — agree?
- [ ] 2b — drop `output` from audit, keep hash+count, raw stays in the RLS-scoped transcript — sufficient?
- [ ] 2c — guard coverage assertion (no raw string param; `user` only from redactLines) — the right structural check?
- [ ] Test set proves an analyst-typed PII string never leaves cleartext, mutation-sensitive?
