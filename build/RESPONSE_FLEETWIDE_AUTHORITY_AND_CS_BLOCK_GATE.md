# Pre-code Gate — FleetWide authority dimension + CrowdStrike block/allow (IOC) actioner

**Date:** Jul 16 2026. **Owner decision (relayed):** for a fleet-wide reversible action, **Option 1 — approval-
always, human-runnable**: it must NEVER auto-run under any authority mode, but a manager may approve-and-run it.
Rationale (owner): Option 2 (`business_critical`) would make it *unrunnable even by a manager facing confirmed
ransomware* — a phantom control (the J4 anti-pattern). Option 3 is the fail-open CS-FLAG exists to prevent.

**Scope of this gate = TWO things, in order:** (A) a reusable **`FleetWide` authority dimension** (the foundation),
then (B) the **CrowdStrike `cs_block_hash` ⇄ `cs_allow_hash`** IOC actioner as its first consumer.

**(A) also closes a pre-existing hole — precisely characterized as LATENT, NOT LIVE (reviewer-verified):** the
Defender `block_hash`/`block_ip`/`block_domain` catalog rows are seeded `'high'` (mig 0036:60-62) and are genuinely
fleet-wide (a Defender custom-indicator block applies across every endpoint). It is **not live-exploitable today**,
for two INDEPENDENT reasons, both verified at source: (1) `DefenderActioner.Actioners()` registers only
`isolate_endpoint`/`release_endpoint` — there is **no registered Defender block actioner**, so those actions hit the
empty-registry fallback and **simulate**; (2) the seeded playbooks mark those steps `requires_approval:true`. But it
IS a real **structural** hole: nothing in the engine stops a fleet-wide auto-fire — safety rests entirely on the
playbook author remembering `requires_approval` on every such step AND the tenant not being on a permissive mode.
The `fleet_wide` flag closes that structurally and **retroactively hardens the already-cataloged Defender family**,
which is exactly why the dimension must be reusable, not CrowdStrike-only. (Log it as latent so the register isn't
polluted with a live-severity item that isn't one.)

Gate written BEFORE code; must clear a reviewer pass before the build. Reviewer already named the two source checks:
the `FleetWide` check sits **above** mode resolution (a permissive mode can't bypass it), and the flag is applied to
**every** fleet-wide verb, not just `cs_block_hash`.

---

## A. The `FleetWide` authority dimension (the real design change)

**Problem (verified at source):** `Allowed(mode, risk)` (`soar.go:184`) licenses a High reversible action to
auto-run under `pre_authorized`/`contractual_auto`. Reversibility is the ONLY proxy for "safe to automate." But a
*fleet-wide* action (blocks a hash/IP/domain across every endpoint) is reversible yet its blast radius is the whole
tenant — a false-positive auto-fire is a fleet-wide outage. Reversibility ≠ safe-to-automate at fleet scale.

**Design:** `FleetWide` is a **breadth gate axis independent of the risk/reversibility axis.**
1. **Schema:** add `fleet_wide boolean NOT NULL DEFAULT false` to `soar_action_catalog` (mig 0134). Config-izable
   with a seeded default, per the no-hardcoding rule (like `risk_class`). A tenant override may only **raise** it
   `false→true`, **never lower** `true→false` — same "override may only tighten a safety guarantee" clamp as risk
   (`catalog.go` merge: if global.FleetWide then eff.FleetWide=true, mirroring the risk-class clamp).
2. **Struct:** `ActionCatalog.FleetWide bool`; `resolveAction` + `resolveActionCatalogMap` scan + carry it;
   `unknownAction` fail-closed default = `FleetWide:false` (an unknown action is already `business_critical`, which
   never auto-runs anyway, so false is safe there).
3. **The check — ABOVE mode resolution (reviewer constraint #1).** At `service.go:275`:
   ```
   autoEligible := !st.RequiresApproval && !act.FleetWide && Allowed(mode, act.RiskClass)
   ```
   `!act.FleetWide` short-circuits BEFORE the mode-dependent `Allowed(...)`, so a FleetWide step is never
   auto-eligible under ANY mode — `contractual_auto`/`emergency` included. It routes to `awaiting_approval` (not
   skipped): a manager can still approve-and-run it via the normal approval path (executeRun), so the control stays
   REACHABLE (Option 1, not the Option-2 phantom). Note it in the step's approval reason ("fleet-wide: approval
   required regardless of authority mode").
4. **Reusable, not one-off (reviewer constraint #2).** Seed `fleet_wide=true` for EVERY genuinely-tenant-wide verb:
   - `cs_block_hash` (crowdstrike, new — §B),
   - `block_hash`, `block_ip`, `block_domain` (defender — **closes the latent fail-open**; they were `'high'` only),
   - `network_block_all` (already `business_critical` = stricter; set `fleet_wide=true` too for belt-and-braces/
     documentation so the axis is complete, though it can never auto-run anyway).
   Single-target verbs (`isolate_endpoint`, `cs_isolate_host`, `disable_user`, `okta_suspend_user`, `revoke_sessions`)
   stay `fleet_wide=false` — they hit one host/user.
5. **CI guard — REQUIRED (upgraded from "optional" on the reviewer's pass).** A schemacheck-style test asserting
   every catalog row in the **block/quarantine-all family carries `fleet_wide=true`**. Rationale (reviewer): this is
   the exact fence that would have caught the Defender latent fail-open we just found sitting in the catalog — a
   future block verb seeded `'high'` without the flag is precisely the recurrence it prevents. Same reasoning as the
   J5 proof-fence: **don't rely on the author remembering; make CI enforce it.** Because we found this bug class
   latent in-tree, the fence is non-optional.
   - **Must genuinely enumerate the family, not assert vacuously** (reviewer will check for an empty assertion):
     enumerate by action_key/name pattern (`block_*`, `*_block_hash`, `*_block_ip`, `*_block_domain`,
     `network_block_all`, `quarantine_all*`) over the seeded catalog, and fail if any matched row has
     `fleet_wide=false`. The test must fail if the family list is empty (guard against a pattern that matches nothing).

## B. CrowdStrike `cs_block_hash` ⇄ `cs_allow_hash` (IOC actioner — the first FleetWide consumer)

| Action key | Verb | CrowdStrike API | `FleetWide` | `PreCheck` | `Reversible` | `Inverse` | Risk | Confirm |
|---|---|---|:--:|:--:|:--:|---|---|---|
| `cs_block_hash` | block file (IOC prevent) | `POST /iocs/entities/indicators/v1` action=`prevent` | **true** | true | true | `cs_allow_hash` | High | nil (sync) |
| `cs_allow_hash` | remove our block | `DELETE /iocs/entities/indicators/v1?ids=…` | true | true | true | `cs_block_hash` | High | nil |

- **PreCheck (terminal-state on IOC existence):** `cs_block_hash` finds the IOC by (type=sha256, value=hash) via
  `GET /iocs/queries/indicators/v1?filter=…` → if an active `prevent` indicator already exists → **goal-met,
  changed=false**, `action_id` = the existing **bare indicator id**. Else create → changed=true, `action_id` = the
  new bare indicator id. **O-3 resolved: `cs_allow_hash` = DELETE the indicator we created** (delete-what-we-made,
  the cleanest reverse), keyed on the `action_id` indicator id from prior_state; if it's already gone → changed=false.
- **MA-2:** `action_id` = bare indicator id (not display-prefixed) — the reverse's delete key + reconciler key.
- **Reverse composition:** a FOREIGN pre-existing `prevent` indicator (not ours) → our block records changed=false
  → ReverseRun (gates changed=true) never deletes an allowlist/block we didn't create. Same invariant as Okta/CS-host.
- **Vendor-prefixed** `cs_block_hash`/`cs_allow_hash` (Defender already owns `block_hash`). Sync (indicator created
  immediately) → `Confirm=nil`. `cs_allow_hash` is the registry-only inverse (not a catalog step) — not seeded.
- Reuse `Credentials.CrowdStrikeBaseURL` + OAuth client-creds (already added). SafeClient; tests inject a client.

## C. Migration 0134
- `ALTER TABLE soar_action_catalog ADD COLUMN fleet_wide boolean NOT NULL DEFAULT false;`
- `UPDATE` the existing rows: set `fleet_wide=true` for `block_hash`,`block_ip`,`block_domain`,`network_block_all`.
- `INSERT` `cs_block_hash` (high, connector=crowdstrike, `fleet_wide=true`) — `ON CONFLICT … DO NOTHING`.
- Idempotent; from-zero safe (table exists by 0036). No RLS/grant change (column on an existing table) → schemacheck neutral.

## D. Tests
- **FleetWide auth (the core new invariant):** a step whose action is `fleet_wide=true` is `awaiting_approval` even
  under `contractual_auto` AND `emergency` (mode can't bypass) — and IS approvable-and-runnable by a manager
  (executeRun proceeds). Restore the bug (drop `!act.FleetWide`) → a `contractual_auto` fleet-wide step auto-runs → RED.
- **Override-only-tightens:** a tenant override with `fleet_wide=false` on a globally-fleet_wide action does NOT
  lower it (still requires approval).
- **IOC actioner:** block when no indicator → create+changed=true+bare action_id; block when indicator exists →
  goal-met changed=false; allow (reverse) deletes our indicator (changed=true), no-ops on a foreign/absent one.
- Loopback mock (injected client); from-zero mig 0134; full soar suite (canAutoRun/registration) green.

## E. Open questions for the builder
- O-A: exact Falcon IOC filter syntax for find-by-hash (`type:'sha256'+value:'…'`) and the create body shape
  (severity/platforms/action fields) — confirm at build against the current Falcon IOC Management API.
- O-B: `network_block_all` has connector_key='' (no vendor) — leave it business_critical + fleet_wide; do NOT wire
  an actioner (there is no "block the whole network" vendor call — it's an incident-commander concept).

## F. Definition of done
`fleet_wide` dimension (schema + struct + resolve + the `!act.FleetWide` gate ABOVE mode resolution + override-clamp)
LANDED and seeded for all fleet-wide verbs (closing the Defender latent fail-open); `cs_block_hash`⇄`cs_allow_hash`
IOC actioner DORMANT with terminal-state PreCheck + delete-what-we-made reverse + bare `action_id`; tests incl. the
"fleet-wide never auto-runs under any mode, still manager-approvable" invariant (mutation-checked); from-zero + CI
green. Reviewer verifies at source: the `!act.FleetWide` check is above `Allowed(mode,...)`, the flag is on the whole
block family (not just cs_block_hash), and the reverse composition on foreign indicators.

Ties [[feedback_reachability_invariant]] (a permissive/empty config must never license a fleet-wide effect — same as
the D5 floor), [[feedback_reviewer_never_weaken_test]], [[project_nirvet_soar_slicec]], [[verify_semantics_not_names]].

---

## G. RECORDED REVIEWER PASS — Fable 5, Jul 17 2026 → **PASS, no must-adds** (1 strengthening, folded)

**The load-bearing property was PRE-VERIFIED at source by the reviewer — the single-chokepoint claim holds:**
- `service.go:275` is the **only** auto-eligibility computation in the entire codebase (no other `autoEligible` /
  `!st.RequiresApproval` / `Allowed(mode` anywhere; the sole other `Allowed(` hit is the function definition).
- **Both** run-creation paths funnel through it: direct `Run` (service.go:222) → `runFor`, and the fleet cross-tenant
  `FireContainment` → `RunForTarget` (service.go:235) → `runFor`. Layer 2 (`canAutoRun`/`evaluateGate`) is
  execution-time and correctly runs already-approved actions.
- ⇒ Placing `!act.FleetWide` at :275, short-circuiting **before** the mode-dependent `Allowed(mode, ...)`,
  structurally prevents a fleet-wide auto-fire **under any authority mode, via any path**. There is no second
  decision point to bypass it.

**Also verified:** the Defender fail-open is real but **latent not live** (folded into the scope note above — no
registered Defender block actioner ⇒ simulates; seeded playbooks set `requires_approval`); the dimension is applied
to the whole block family + `network_block_all` with single-target verbs correctly `false`; the override-only-tightens
clamp mirrors the risk clamp; `unknownAction` fail-closed `FleetWide:false` is sound (unknown → `business_critical`
→ never auto-runs anyway); the IOC reverse is delete-what-we-made with a bare `action_id` and is foreign-indicator safe.

**Strengthening folded:** §A.5 CI guard **upgraded optional → REQUIRED**, and it must genuinely enumerate the
fleet-wide family (fail on an empty family list — no vacuous assertion).

**Cleared to build.** Reviewer will verify at source on landing: (1) the `!act.FleetWide` edit actually landed above
`Allowed()` at the single chokepoint; (2) the flag is on the whole block family, not just `cs_block_hash`; (3) the
reverse composition on foreign indicators; (4) the mutation-check test genuinely goes RED when the guard is dropped;
(5) the CI guard enumerates a non-empty family.
