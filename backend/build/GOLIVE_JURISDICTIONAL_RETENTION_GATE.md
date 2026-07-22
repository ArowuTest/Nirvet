# Pre-code Gate — §6.14 B3: jurisdictional retention → retention-delete (reviewer-authored)

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies. Answers the 4 questions in `GATE_REQUEST_JURISDICTIONAL_RETENTION.md`.
Scope: **the one §6.14 B piece that touches the DELETE path.** Data-destruction machinery — the falsification bar is "what causes wrongful/over-deletion or a legal-hold bypass," not "does deletion work."

## 0. The asymmetry this whole gate turns on

Retention config can push in two directions, and they are NOT symmetric in risk:
- A **FLOOR** (retain ≥ M) only ever **preserves** data → **safe to build AND arm now.**
- A **CEILING** (delete after N) is the ONE direction that makes deletion **more aggressive** → it **destroys evidence earlier**, and it is irreversible. It must be **built + dry-runnable now, but its destructive enforcement stays DORMANT behind an explicit go-live arm** (KMS provisioned + backup drill + retention soak) — the same "built but gated, not armed-but-dead" pattern as the SOAR actioners and the MFA floor.

Never arm an irreversible-destruction path before the safety net exists. The floor is that principle's easy half; the ceiling is the half that waits.

## 1. Current state, verified at source (mig 0116 / 0119)
- `retention_policy` per-tenant (NULL=global), `enabled DEFAULT false` (dry-run/report-only SAFE default). `window_days` is a **tighten-only** override: `effective = min(window_days, entitlement.retention_days)` — a tenant may keep telemetry for LESS, never more.
- Deletes ONLY raw telemetry (`raw_events` + payload blob, `events`); NEVER alerts/incidents/evidence/audit. (Confirm this stays true — the jurisdiction axis must not widen the delete's *reach*, only its *window*.)
- `retention_delete_raw` / `retention_delete_events` (mig 0116, SECURITY DEFINER, immutability-bypass-for-THIS-path-only) **REFUSE when `tenants.legal_hold`** (defense-in-depth over the Go check).
- Append-only `retention_sweep_log` (every sweep incl. dry-runs) + `retention_deletion_ledger` (mig 0119, attribution).

## 2. Design — LOCKED decisions

### 2a. Clamp ordering — floor-beats-ceiling, legal-hold-supreme (the crux; get the NESTING exact)
The effective window MUST be computed as (floor is the **outer** lower bound — this exact nesting is the security property):

```
effective_days = max( floor ,  min( tenant_window , entitlement , ceiling ) )
       where floor   = jurisdiction.min_retain_days   (0 / NULL if none)
             ceiling = jurisdiction.max_retain_days    (+∞ / NULL if none)
```

- **Floor applied LAST as `max(...)`** → it can only LENGTHEN retention. A contradictory config (floor 90 > ceiling 30) resolves to **90 (floor wins → retain longer)**, never 30. This is the whole point: **when rules conflict, resolve toward RETENTION.** The inverted nesting `min(max(x,floor),ceiling)` is WRONG (ceiling would clamp the floor down and destroy mandated-retention evidence) — the gate rejects that ordering.
- **legal_hold is ABOVE the formula entirely** — a held tenant is not swept AT ALL; the window is never computed for it. The SD functions already refuse on hold; the Go reconciliation must short-circuit BEFORE computing any window, and the hold must be re-checked inside the delete tx (see 2c). A jurisdiction ceiling must not be a route around a hold.
- Precedence, top to bottom: **legal_hold (never delete) > jurisdiction floor (retain ≥ M) > {tenant_window, entitlement, jurisdiction ceiling} (shortest of these, but never below floor).**

### 2b. Config axis — padmin-only, seeded, dry-run-default
- `jurisdiction_retention` config `{jurisdiction_key, min_retain_days, max_retain_days}`, seeded global defaults, **platform_admin-managed only** (a sovereign regime is operator-level, never tenant-self-service). Tenant selects its jurisdiction via `tenants.jurisdiction` (reuse an existing country/sector field if one fits).
- Validation at authoring: `min_retain_days ≥ 0`, `max_retain_days ≥ 1` (or NULL), and if BOTH set, they may coexist even when floor>ceiling (2a resolves it toward the floor — do NOT reject the contradiction, resolve it safely). Unknown jurisdiction on a tenant → NO ceiling applied (fail toward retention, never invent a delete window).
- `enabled DEFAULT false` stays — jurisdictional deletion never silently activates.

### 2c. The CEILING's destructive enforcement is DORMANT until the go-live arm
- Build the full unit now: config + reconciliation + sweep wiring + dry-run + ledger. The ceiling participates in the window computation and the **dry-run report** immediately (an operator can SEE what a ceiling would delete).
- But the **actual ceiling-driven deletion** (the case where the jurisdiction ceiling is the binding constraint that shortens the window below what tenant/entitlement alone would give) requires an explicit platform arm — an operator config `jurisdiction_delete_armed` (singleton, seeded **false**), checked at the sweep. Floor-only and tighten-only-tenant deletions are unaffected (they were already safe/live). **This is gated LIVE code, not dead code**: it is reachable, dry-runs, and flips on with one auditable config change at go-live — reachability-invariant satisfied ([[reference_safety_control_zero_config_floor]]).
- Register this as a go-live step: **D-arm-retention — arm jurisdictional-ceiling deletion only after KMS + backup drill + retention soak.**

### 2d. Sole-producer fence + legal-hold short-circuit (the teeth)
`scripts/check-retention-window-single-path.sh` (mirror `check-authority-single-path.sh` / `check-session-mint-single-path.sh`):
- Assert the effective-window computation lives in exactly ONE function, and that `retention_delete_raw`/`retention_delete_events` are fed ONLY by that function's output (no other caller computes a window and calls the delete). A second window producer = a path that can skip the floor/hold = fail the build, naming the file:line.
- Assert the legal-hold short-circuit token is present in that function (a delete path that doesn't reference the hold check fails).

## 3. Non-negotiable falsification requirements (the data-destruction complement — build tests for EACH)
1. **Floor wins on contradiction:** floor 90 + ceiling 30 → effective 90, data at 60 days **RETAINED** (mutation: swap the nesting to `min(max(...),ceiling)` → this test goes RED). THE load-bearing test.
2. **Legal-hold supreme:** held tenant + aggressive ceiling → **zero rows deleted** (dry-run AND armed). Mutation: remove the hold short-circuit → RED.
3. **Hold re-checked inside the delete tx (race):** a hold placed AFTER window-compute but BEFORE the delete still blocks (the SD function refuses at delete-time). Prove the check is not a stale pre-flight.
4. **Tenant-scoping (B4 discipline):** tenant A's jurisdiction ceiling deletes ONLY tenant A's raw telemetry; tenant B's data at the same age is untouched. Two-tenant, RLS-role, DB-gated. Mutation: drop the tenant pairing in the sweep → RED.
5. **Dry-run is fail-safe default:** `enabled=false` (or `jurisdiction_delete_armed=false`) → the ceiling reports what it WOULD delete and deletes **nothing**. Forgetting the flag never deletes.
6. **Ceiling dormant pre-arm:** with `jurisdiction_delete_armed=false`, a ceiling that would shorten the window performs NO destructive delete (only floor/tighten-only proceed). Flip armed=true → the same case now deletes. Proves the arm is load-bearing, not decorative.
7. **Reach not widened:** the jurisdiction axis never causes a delete of anything but `raw_events`/`events` — alerts/incidents/evidence/audit are never in the delete set regardless of jurisdiction. (Assert the delete statement's table set is unchanged.)
8. **Ledger attribution:** every jurisdictional delete writes a `retention_deletion_ledger` row naming the jurisdiction rule that drove it (a wrongful delete must be attributable even though irreversible).

## 4. Out of scope (follow-ons)
Cross-jurisdiction tenants (a tenant under multiple regimes — first slice = one jurisdiction per tenant) · retention for derived artifacts (alerts/incidents have their own lifecycle) · undo/soft-delete of raw telemetry (deletion stays hard; the ledger is the record).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] 2a clamp is `max(floor, min(tenant, entitlement, ceiling))` — floor is the OUTER max; contradiction resolves to the floor (test #1 mutation-proven).
- [ ] 2a legal_hold short-circuits BEFORE window-compute AND is re-checked in the delete tx (tests #2, #3).
- [ ] 2b jurisdiction config is padmin-only, seeded, dry-run-default; unknown jurisdiction → no ceiling (fail toward retention).
- [ ] 2c ceiling destructive enforcement gated behind `jurisdiction_delete_armed` (seeded false); reachable + dry-runnable, not dead (test #6). Registered as go-live step D-arm-retention.
- [ ] 2d sole-producer fence: one window function feeds the delete; legal-hold token present; mutation-proven RED→GREEN.
- [ ] tenant-scoping (test #4) + reach-not-widened (test #7) + ledger attribution (test #8).
