# Pre-code Gate — CrowdStrike Falcon EDR Actioner (Response-coverage G1, vendor #2)

**Date:** Jul 16 2026. **Track #3, second vendor** (Okta-first → **CrowdStrike** now — the harness is proven on the
lightest-reversibility vendor; CrowdStrike is the heavier EDR-state one that sequencing was designed to de-risk).
**Pattern refs:** `okta_actioner.go` (multi-state terminal fail-safe, vendor-prefixed keys, MA-1/2/3) +
`defender_actioner.go` (EDR isolate/release, async device action). **Ingestion already exists** (`normalize.go:38`
`RegisterMapper("crowdstrike","crowdstrike-falcon",…)`) — this slice is **actioner-only**. Gate written BEFORE code
per the gated discipline; must clear a reviewer pass before the build.

---

## 1. Design vs SRS
- **SRS §6.11:** playbook step → two-phase supervisor → Actioner registry. Adds the **second non-Microsoft** vendor
  → closes G1 EDR containment for CrowdStrike stacks (clients C2/C4/C5 per `NIRVET_RESPONSE_COVERAGE_BUILDOUT.md`).
- **Dormant-until-configured**, like Defender/Entra/Okta: registered but only fires when a tenant configures
  CrowdStrike creds AND authorizes the action class. D5 guard runs at the supervisor seam before the actioner.

## 2. THE PER-VERB REVERSIBILITY SPLIT (the one genuinely new design question — reviewer flag)
`canAutoRun` (`actioner.go:91-103`) refuses any Class-High+ action that is not `Reversible` with an `Inverse`, and
any action that is neither `Idempotent` nor `PreCheck`. Okta's verbs were uniformly reversible or idempotent;
CrowdStrike's are **not uniform** — each verb is classified deliberately here:

| Action key (vendor-prefixed*) | Verb | CrowdStrike API | `Idempotent` | `PreCheck` | `Reversible` | `Inverse` | Risk | Auto-runnable? |
|---|---|---|:--:|:--:|:--:|---|---|---|
| `cs_isolate_host` | network-contain host | `POST /devices/entities/devices-actions/v2?action_name=contain` | false | **true** | **true** | `cs_release_host` | High | ✅ (reversible + PreCheck) |
| `cs_release_host` | lift containment | `…?action_name=lift_containment` | false | true | true | `cs_isolate_host` | — | ✅ (the inverse; ReverseRun) |
| `cs_block_hash` | block file (IOC prevent) | `POST /iocs/entities/indicators/v1` action=`prevent` | false | **true** | **true** | `cs_allow_hash` | High | ✅ |
| `cs_allow_hash` | remove block / allowlist | `PATCH`/`DELETE /iocs/entities/indicators/v1` (action=`allow` or delete) | false | true | true | `cs_block_hash` | — | ✅ (the inverse) |
| `cs_kill_process` | terminate process (RTR) | RTR session + `kill` command | false | false | **false** | — | High | ❌ **cannot auto-run** |

**`cs_kill_process` decision (named, per reviewer — not discovered in code): DEFER to a follow-up slice.** Two
reasons: (1) it is **not reversible** (you can't un-kill a process), so at Class-High `canAutoRun` correctly refuses
it — it could only ever be approval-gated-manual, never automated; (2) it requires the **Real-Time-Response (RTR)**
subsystem (session init + command queue + async polling), a whole vendor surface heavier than device-actions/IOC.
Shipping isolate/release + block/allow first delivers the #1 EDR response (host isolation) cleanly; `cs_kill_process`
gets its own slice IF a customer needs it. **Do NOT register it in this slice** — an unregistered action simulates
(honest), which is the correct interim, rather than registering a non-auto-runnable stub. (Same discipline as the
Okta `reset_password` deferral.)

*Vendor-prefixed `cs_*` keys are REQUIRED: `isolate_endpoint` already maps to `defender` in the catalog (mig 0036),
so a generic `isolate_endpoint` step would misroute to Defender. Same source-reality catch as Okta's `okta_*`.

## 3. Terminal-state PreCheck (multi-state, like Okta — NOT a boolean)
CrowdStrike device containment `status` is multi-valued: **`normal` · `containment_pending` · `contained` ·
`lift_containment_pending`**. PreCheck reads it and is fail-SAFE:
- `cs_isolate_host`: if `contained` OR `containment_pending` → **goal met, no call, `changed=false`** (D2 fail-safe —
  never re-contain, and a foreign containment we didn't cause is left `changed=false` so ReverseRun won't lift it,
  exactly as the Okta foreign-suspend case composes with `sliceb_reverse.go:52-54`). If `normal` → contain,
  `changed=true`. If `lift_containment_pending` → treat as in-flight-release; **do not** issue a contain over a
  pending lift (decide: goal-not-met-retry-later vs. no-op — document the choice, default no-op `changed=false`).
- `cs_release_host` (reverse): lift ONLY from `contained`/`lift_containment_pending`→ from `normal`/`containment_pending`,
  `changed=false` (never lift a host we didn't contain — the reverse-composition invariant the reviewer verified on Okta).
- **MA-2 analog:** `priorState["action_id"]` = the **bare CrowdStrike `device_id`** (the reconciler's poll key; the
  device action is async, so unlike Okta a **`Confirm` may be needed** — see §4). Never a display-prefixed string.
- `cs_block_hash`: PreCheck by looking up the IOC by hash; if an active `prevent` indicator exists → goal-met
  `changed=false`. `action_id` = the bare **indicator id** (for the reverse to delete exactly what we created).

## 4. Async vs sync — `Confirm` (unlike Okta's synchronous lifecycle)
Defender's machine action is async (submit → poll). CrowdStrike device-actions are **also async** (contain returns a
pending status; the device transitions `containment_pending`→`contained`). So `cs_isolate_host` likely needs a
non-nil **`Confirm`** (poll `GET /devices/entities/devices/v2?ids={device_id}` until `status`=`contained`), mirroring
Defender's reconciler path — NOT Okta's `Confirm=nil`. IOC block is synchronous (indicator created immediately) →
`Confirm=nil`. **Open question O-1:** confirm which CrowdStrike verbs are async and wire `Confirm` only for those.

## 5. Wiring + guardrails (generic — reuse)
- **Register** in `main.go` after Okta: `for _, a := range connector.NewCrowdStrikeActioner(...).Actioners() { soarReg.Register(a) }`. Dormant.
- **Credentials:** OAuth2 client-credentials (`POST {base}/oauth2/token`, client_id+client_secret → bearer, ~30min TTL — mirror `entraClient.accessToken`). **Open question O-2:** the API **base URL is region-specific** (US-1 `api.crowdstrike.com`, US-2, EU-1, GovCloud `api.laggar.gcw.crowdstrike.com`) — add a `CrowdStrikeBaseURL` (or cloud-region enum) to the `Credentials` bundle; GovCloud matters for the Ghana-sovereign posture. `netsafe.SafeClient` (CI `net.Dial` fence); tests inject their own client (loopback, no SSRF weakening).
- **Reuse** `Credentials.ClientID/ClientSecret` for the OAuth pair (per-connector bundle, so no clash with Entra's). Add only `CrowdStrikeBaseURL`.
- Authority-to-act / four-eyes / rate-cap / D5 / reverse — all generic in the supervisor; `Reversible:true`+`Inverse` on isolate/block satisfies `canAutoRun` for Class-High.

## 6. Catalog seed (migration 0133)
Seed global rows (tenant_id NULL): `cs_isolate_host` (high), `cs_block_hash` (high). The **inverses**
(`cs_release_host`, `cs_allow_hash`) are registry-only (invoked by ReverseRun), NOT catalog step actions — mirror
Entra `enable_user` / Okta `okta_unsuspend_user`. `cs_kill_process` is NOT seeded (deferred). `ON CONFLICT (COALESCE
(tenant_id,'000…'::uuid), action_key) DO NOTHING`.

## 7. Open questions for the builder (don't hardcode)
- **O-1:** which verbs are async → wire `Confirm` (poll device status) only for those; IOC is sync.
- **O-2:** region base URL in the credentials bundle (GovCloud for sovereign).
- **O-3:** IOC reverse — is `cs_allow_hash` a DELETE of the indicator, or a PATCH to `action=allow`? Decide so the reverse undoes exactly what block created (delete-what-we-made is cleaner; document).
- **O-4:** device ref format — hostname vs device_id; resolve via `GET /devices/queries/devices/v1?filter=hostname:'…'` then entities. Normalize `host:{id|hostname}`.

## 8. Tests (mirror okta_actioner_test.go + sliceb_defender_integration_test.go)
- Contract flags: isolate/release Reversible+Inverse; block/allow Reversible+Inverse; **assert `cs_kill_process` is NOT registered** (deferred — a test that the registry has no `cs_kill_process` key, so it can't sneak in as auto-runnable).
- Terminal-state fail-safe across all 4 containment statuses: isolate on `normal`→call+changed=true; on `contained`/`containment_pending`→no call+changed=false; release only from `contained`.
- `action_id` = bare device_id / indicator id.
- Async `Confirm` returns done/success on `contained` (if wired).
- Reverse composition: a foreign-`contained` host (our isolate recorded changed=false) is NOT lifted by ReverseRun.
- Loopback mock (injected client); from-zero migration 0133 green; schemacheck + soar `canAutoRun` green.

## 9. Definition of done
Dormant CrowdStrike actioner: isolate/release + block/allow with multi-state terminal fail-safe PreCheck, async
`Confirm` where needed, `action_id` bare ids, D5 guard, reverse-composition safe; `cs_kill_process` explicitly
deferred+unregistered; catalog seeded (0133); full test set + from-zero + CI green; buildout matrix updated
(C2/C4/C5 EDR → ✅). Reviewer verifies at source: honest reversibility flags (kill_process can't auto-run),
terminal-state PreCheck, `action_id`, and the reverse composition (already-contained host not released by our reverse).

Ties [[project_nirvet_soar_slicec]] (Defender async pattern), [[project_nirvet_soar_entra]]/Okta (identity ref),
[[project_nirvet_protected_targets]] (D5), [[feedback_reachability_invariant]], [[feedback_reviewer_never_weaken_test]].
