# Pre-code Gate — Okta Identity Actioner (Response-coverage G1, vendor #3)

**Date:** Jul 16 2026. **Track #3, first slice** (owner: Okta first → CrowdStrike second — prove the actioner
harness on the lightest-reversibility vendor before the heavy EDR one). **Pattern reference:** `entra_actioner.go`
(identity, terminal-state fail-safe) — Okta is its closest analog. **This gate is written BEFORE code**, per the
gated-approach directive; it must clear a reviewer pass before the build starts.

---

## 1. Design vs SRS

- **SRS §6.11 (SOAR real execution):** a playbook step routes through the two-phase supervisor → Actioner registry.
  Today only Defender + Entra are registered; every other vendor **simulates** (empty-registry fallback,
  `main.go:338-341`, verified). This slice adds the first **non-Microsoft** actioner → closes G1 for identity on
  Okta stacks (clients C2, C4 per `NIRVET_RESPONSE_COVERAGE_BUILDOUT.md`).
- **Ingestion already exists:** `RegisterMapper("okta","okta",1,normalizeOkta)` (`ingestion/normalize.go:40`) —
  Okta events are normalized and detections already fire. This slice builds only the **outbound act side** (a new
  vendor API client), reusing all generic gated machinery.

## 2. The Actioner contract (mirror `soar.Actioner`, VERIFIED shape at `actioner.go:37-54`)

Each entry: `{ConnectorKey, Action, Idempotent bool, PreCheck bool, Reversible bool, Inverse string, Fn, Confirm}`.
`Fn` returns `(ref string, priorState map[string]any, err error)` — **NOT `(actionID, resultMeta)`**. The engine's
`canAutoRun` (`actioner.go:91-103`) REFUSES to auto-run any action where `!Idempotent && !PreCheck` (falls to
human-confirm), and any Class-High+ action that is not `Reversible` with an `Inverse`. So both flags are
load-bearing, not documentation.

| Action | Verb | Okta API | `Idempotent` | `PreCheck` | `Reversible` | `Inverse` | Risk | Notes |
|--------|------|----------|:---:|:---:|:---:|---------|------|-------|
| `suspend_user` | disable user | `POST /api/v1/users/{id}/lifecycle/suspend` | false | **true** | **true** | `unsuspend_user` | High | Terminal-state PreCheck on `status`; multi-state fail-safe (OQ#4). |
| `unsuspend_user` | re-enable | `POST /api/v1/users/{id}/lifecycle/unsuspend` | false | true | true | `suspend_user` | — | The inverse; invoked by ReverseRun. Valid only from SUSPENDED. |
| `revoke_sessions` | clear sessions | `DELETE /api/v1/users/{id}/sessions?oauthTokens=true` | **true** | false | false | — | Medium | Naturally idempotent (re-login just works); cannot be undone. **`Idempotent:true` is REQUIRED** — without it `canAutoRun` refuses it ("not declared idempotent or pre-checking"). `Reversible:false`, no Inverse. |

**MA-1 (reviewer):** the `Idempotent` column above is the field the first draft dropped. A builder MUST set
`Idempotent:true` on `revoke_sessions` or the engine will never auto-run it.

**Deliberately deferred to a follow-up:** `reset_password` (`POST /api/v1/users/{id}/lifecycle/reset_password`) —
it emails a reset link / expires the password (side-effecting on the end user); size it separately once suspend +
revoke are proven. Name the deferral in the slice, don't silently drop it.

## 3. Terminal-state fail-safe (the invariant Entra proves, Okta must copy)

Okta users have a `status` field, not a per-action correlator — so attribution is **terminal-state (D2)**, exactly
like Entra's `accountEnabled` (which deliberately does NOT use `ActionCorrelatorParam` for the same reason):
- PreCheck reads `status`. If already at the target state (SUSPENDED for suspend), **no call, `changed=false`** —
  reverse never re-does a state we can't prove we caused, and a crash-resume that finds the account already
  suspended does **not** wrongly re-suspend/re-activate a *foreign* change. This is the fail-SAFE resolution of
  ambiguity. **Reference impl to copy line-for-line in spirit:** `entra_actioner.go:57-81`.
- **MA-2 (reviewer) — `priorState["action_id"]` is mandatory.** `Fn` returns `(ref, priorState, err)`; a PreCheck
  actioner MUST set `priorState["action_id"]` to the **bare Okta user id** (never `"user:"+id` or any display
  prefix) — it is the completion reconciler's poll key (`actioner.go:45-47`, the G-1 rule). Entra does exactly
  this (`action_id: user.ID`). Also set `changed` (true when we made the call, false on already-at-target).
- Synchronous lifecycle calls (200/204 = done) → **Confirm=nil** (the reconciler confirms on sight, no async poll).

## 4. Wiring + guardrails (all generic — already built, just connect)

- **Register** in `main.go` alongside Defender/Entra: `for _, a := range connector.NewOktaActioner(...).Actioners() { soarReg.Register(a) }`. Ships **dormant** — only fires when a tenant configures an Okta connector with creds AND authorizes the action class (same dormant-until-configured posture as Entra/Defender).
- **D5 protected-identity guard** runs at the supervisor seam BEFORE the actioner (generic) — a protected target never reaches Okta. Confirm the guard keys on the normalized identity ref, not vendor-specific casing (see the D5 casing-bypass fix, [[project_nirvet_deeper_audit]]).
- **Authority-to-act / four-eyes / rate-cap / reversal** — all generic in the supervisor; `Reversible:true` on suspend satisfies `canAutoRun` for Class-3 auto-execution; `revoke_sessions` is Class-2.
- **Credentials:** Okta API token (SSWS) or OAuth2 — resolved through the vault (`crypto.go`), never logged. Client MUST use `netsafe.SafeClient` (SSRF fence; CI `net.Dial` guard will fail a raw client). Per-tenant Okta org URL (`https://{org}.okta.com`) validated as the API base.

## 5. Open design questions for the builder to resolve (don't hardcode)

1. **`ConnectorKey`** — Okta is currently only an *ingestion* mapper key (`"okta"`), not a connector `Kind` const. Add a `KindOkta` connector kind + seed the catalog actions (`suspend_user`, `revoke_sessions`) with `connector_key='okta'` so playbooks can reference them. Confirm the catalog seed migration pattern (how Entra's `disable_user` is seeded) and mirror it.
2. **Target ref format** — normalize `user:{login|id}` and resolve via `GET /api/v1/users/{login-or-id}` (Okta accepts login or id). Mirror Entra's `resolveUser` trim/prefix handling.
3. **Rate limits** — Okta API is aggressively rate-limited (org-wide buckets); the SafeClient retry/backoff must honor `X-Rate-Limit-*` headers. Confirm the existing connector retry-backoff (#158) covers 429 with `Retry-After`.
4. **MA-3 (reviewer) — Okta `status` is MULTI-STATE, not binary.** Entra's `accountEnabled` is a clean boolean; Okta `status` has ~7 values (STAGED, PROVISIONED, ACTIVE, LOCKED_OUT, PASSWORD_EXPIRED, SUSPENDED, DEPROVISIONED). The suspend lifecycle API **returns 400 on a non-ACTIVE user** — so a naive `if status != SUSPENDED { suspend() }` asked to suspend a DEPROVISIONED/LOCKED_OUT account (already access-denied) would **error and block the playbook** instead of recognizing containment is already met. Define the fail-safe terminal-state map for `suspend_user`:
   - Already-access-denied states (SUSPENDED, DEPROVISIONED, LOCKED_OUT, PASSWORD_EXPIRED) → **goal met: no call, `changed=false`**, `action_id` = user id, no error. (Same D2 fail-safe as Entra's already-at-target, generalized across the multi-state axis.)
   - ACTIVE → suspend, `changed=true`.
   - STAGED / PROVISIONED (never activated) → decide explicitly: treat as goal-met (no active sessions to contain) OR reject as not-applicable; do NOT blindly call suspend (it 400s). Document the choice.
   - `unsuspend_user` (the reverse) is valid ONLY from SUSPENDED → from any other state, `changed=false` (never resurrect a DEPROVISIONED account as a side effect of a reverse).

## 6. Tests (mirror `sliceb_entra_integration_test.go`)

- Unit: suspend when ACTIVE → call made, `changed=true`; suspend when already SUSPENDED → no call, `changed=false` (fail-safe); revoke_sessions idempotent (two calls both succeed, no state error).
- Adversarial/resume: crash after suspend → resume finds SUSPENDED → `changed=false`, reverse does NOT re-activate.
- D5: a protected identity never reaches the actioner (guard at the seam).
- Loopback mock for the Okta API (like the Defender/Entra slice-B tests reaching loopback without weakening the SSRF guard, [[project_nirvet_review_round2]]).
- from-zero migration green (the new catalog seed + any `KindOkta` enum value); schemacheck + OpenAPI parity if a route is added.

## 7. Definition of done

Dormant Okta identity actioner registered; suspend/unsuspend/revoke-sessions with terminal-state fail-safe PreCheck
+ reversal; SafeClient + vault creds; D5 guard proven; catalog actions seeded; full test set + from-zero + CI green;
`NIRVET_RESPONSE_COVERAGE_BUILDOUT.md` matrix updated (C2/C4 identity → ✅). Then **CrowdStrike EDR** inherits this
proven harness as the second slice.

Ties [[project_nirvet_soar_entra]] (the identity reference), [[project_nirvet_soar_slicec]] (first-vendor pattern),
[[project_nirvet_protected_targets]] (D5), [[feedback_reachability_invariant]] (dormant≠unreachable — the register
starts empty but the guard has a floor).

---

## 8. RECORDED REVIEWER PASS — Fable 5, Jul 16 2026 → **PASS with 3 must-adds (all folded in above)**

Verified against source (`actioner.go:37-54`, `entra_actioner.go:57-81`), not rubber-stamped. The Entra
terminal-state reference the gate says to copy is accurate. Three must-adds, all folded into §2/§3/§5:

- **MA-1** — `Idempotent` is a distinct contract field from `PreCheck` (`actioner.go:40`); `canAutoRun` refuses
  `!Idempotent && !PreCheck` (`:96-98`). The first-draft table omitted it, so `revoke_sessions` would ship
  un-auto-runnable. **Fixed:** `Idempotent` column added; `revoke_sessions` set `Idempotent:true`.
- **MA-2** — `Fn` returns `(ref, priorState, err)` (not "resultMeta"), and a PreCheck actioner MUST set
  `priorState["action_id"]` to the **bare** vendor id (`:45-47`, G-1) — the reconciler's poll key. **Fixed** in §2/§3.
- **MA-3** — Okta `status` is ~7-valued, not the boolean Entra assumes; suspend 400s on non-ACTIVE. **Fixed:**
  open-question #4 adds the multi-state fail-safe map (already-access-denied → goal-met `changed=false`, no call).

Everything else passes clean: reversibility classification, D5 casing reference, SafeClient/SSRF requirement,
dormant-until-configured posture, the named `reset_password` deferral, and the test plan. **Cleared to build.**
Builder verifier note: restore any of the 3 must-adds' bugs in code → the corresponding test must go red before the
fix (mutation-check discipline, [[feedback_reviewer_never_weaken_test]]).
