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

## 2. The Actioner contract (mirror `soar.Actioner`, verified shape)

Each entry: `{ConnectorKey, Action, PreCheck bool, Reversible bool, Inverse string, Fn, Confirm}`. `Fn` returns
`(actionID string, resultMeta map[string]any, error)`. Confirm=nil for synchronous vendor calls.

| Action | Verb | Okta API | Reversible? | Inverse | Risk class | Notes |
|--------|------|----------|-------------|---------|-----------|-------|
| `suspend_user` | disable user | `POST /api/v1/users/{id}/lifecycle/suspend` | **yes** | `unsuspend_user` | Class-3 (high, reversible) | Terminal-state PreCheck on `status` (ACTIVE ⇄ SUSPENDED). |
| `unsuspend_user` | re-enable | `POST /api/v1/users/{id}/lifecycle/unsuspend` | yes | `suspend_user` | — | The inverse; invoked by ReverseRun. |
| `revoke_sessions` | clear sessions | `DELETE /api/v1/users/{id}/sessions?oauthTokens=true` | **no** | — | Class-2 (non-destructive, naturally idempotent) | Cannot be "un-revoked"; re-login just works. `Reversible:false`, no Inverse. |

**Deliberately deferred to a follow-up:** `reset_password` (`POST /api/v1/users/{id}/lifecycle/reset_password`) —
it emails a reset link / expires the password (side-effecting on the end user); size it separately once suspend +
revoke are proven. Name the deferral in the slice, don't silently drop it.

## 3. Terminal-state fail-safe (the invariant Entra proves, Okta must copy)

Okta users have a `status` field, not a per-action correlator — so attribution is **terminal-state (D2)**, exactly
like Entra's `accountEnabled`:
- PreCheck reads `status`. If already at the target state (SUSPENDED for suspend), **no call, `changed=false`** —
  reverse never re-does a state we can't prove we caused, and a crash-resume that finds the account already
  suspended does **not** wrongly re-suspend/re-activate a *foreign* change. This is the fail-SAFE resolution of
  ambiguity. **Reference impl to copy line-for-line in spirit:** `entra_actioner.go:57-81`.
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
