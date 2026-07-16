# Gate — J4: feature flags have a writer and no reader

**Status:** pre-code gate → BUILT in the same pass (see §5 for why this needed no design decision)
**Raised by:** reviewer, applying the D5 invariant to its other end
**Touches:** §6.18 platform admin. SRS-mandated subsystem (line 1459), so deletion of the subsystem is not on the table.

---

## 1. The finding, verified

The reviewer's claim holds. Verified independently:

- `NewFlagResolver` — the only occurrence in the repo is its own definition. **Never constructed**, including in `main.go`.
- `.Enabled(` — **zero** non-test callers.
- `PUT /admin/flags` is live, padmin-gated, audited, and `/console/admin/flags` renders a Set control.
- The registry declares `"soar.destructive_enabled": {ClassProtected, false, "SOAR real-containment master gate"}`.

So a platform admin can set the flag described as the containment master gate, with full four-eyes ceremony and an
audit trail, and change **nothing**. The real gates are `soar_settings.DestructiveEnabled` and `plat.KillSwitch`,
read at `sliceb_supervisor.go:115-116`.

This is `protected_hosts` inverted, and the reviewer's framing is the right one:

| | writer | reader | failure |
|---|---|---|---|
| `protected_hosts` (D5) | ✗ | ✓ | empty → **silently allows** |
| feature flags (J4) | ✓ | ✗ | set → **silently reassures** |

No bypass — the genuine gates work. But a kill switch that lies in the reassuring direction costs exactly the
minutes that matter, and it lies to the one person with the authority to stop a fleet-wide containment.

## 2. Where the reviewer's summary is imprecise (and it changes the fix)

**Not all eight flags are the same bug.** The registry has four classes, and `ClassImmutable` is *designed* to be
inert: *"never settable via config; resolved from code ONLY (a DB row is inert)"*. So `mfa.enforce`,
`rls.enforce` and `audit.immutable` having no flag-reader is **correct** — that is redaction.go's pattern (code
owns the control), stated as a class. Those three are a true, auditable claim: "config cannot disable this."

The defect is the five **settable** entries, and they split again:

| Flag | Class | Real control elsewhere? | Verdict |
|---|---|---|---|
| `soar.destructive_enabled` | Protected | **Yes** — `soar_settings` + `plat.KillSwitch` | **delete** (see §3) |
| `ai.egress_restricted` | Protected | **Yes** — #117 allowlist + redaction floor | **delete** |
| `notify.delivery_enabled` | Protected | **No** — flag is the only trace in the repo | **delete** (unbuilt promise) |
| `connector.host_telemetry` | Guarded | **No** — telemetry ships (#118), nothing gates it | **delete** (unbuilt promise) |
| `ui.new_dashboard_beta` | Open | **No** | **delete** (unbuilt promise) |

## 3. Why "wire the resolver" is the WRONG fix for the two that matter

The reviewer offered wire-or-delete and called the middle dangerous. Agreed on the middle. But wiring
`soar.destructive_enabled` would make it a **third** source of truth for "is containment armed", alongside
`plat.KillSwitch` (global) and `soar_settings.DestructiveEnabled` (per-tenant). A global flag that disables
containment fleet-wide **is** `plat.KillSwitch`, under a second name.

That is the divergence defect — BUG-10, J3, criticality-vs-`protected_*` — deliberately re-introduced inside the
fix for its twin. Two names for one control is how every one of those started. Same argument for
`ai.egress_restricted` vs the #117 allowlist.

The remaining three promise controls **nothing implements**. Wiring those means *building three new features*
because a registry string implied them. That is the tail wagging the dog.

So: delete all five. The danger is the claim, not the absence.

## 4. A second, smaller lie found while verifying

`SetFlag` rejects **immutable** keys but **not unregistered** ones — while the registry's own comment states
*"Admins CANNOT edit it. Adding a flag = a code change + review."* An admin can therefore invent
`soar.destructive_enabled` (or any string) at runtime; it stores, it audits, it reads as a control, and nothing
reads it. Deleting registry entries without fixing this would leave the lie reachable by typing.

Fix: `SetFlag` refuses unregistered keys — enforcing the contract the registry already documents.

## 5. Why this was built without waiting for a pass

Nothing here is a design decision. Deleting a claim that nothing implements cannot change behaviour (no reader
exists, by definition). Making `SetFlag` honour the registry's own documented contract is not a new policy. The
SRS mandate (line 1459) is on the *capability*, which stays — the subsystem, the classes, the resolver, the
tighten-only semantics and the audit are all retained and correct; only the false entries go.

The one judgement call — delete rather than wire — is argued in §3 and is reversible: adding a flag back is a
code change plus a reader, which is now what the fence requires.

## 6. The fence is the actual deliverable

The reviewer's sharpest line: *"neither of us is immune to it, which is why the detector matters more than the
diligence."* They logged "Feature Flags = empty, dead-end until seeded" as by-design and never asked whether
anything read it; I found `protected_hosts` only because the reviewer's registry question sent me looking. Both
of us have now missed one end of this invariant.

So `flags_reachability_test.go` asserts, structurally:

1. Every **non-immutable** registry entry must be referenced by production code outside `flags.go` — a declared
   settable control with no reader is the J4 bug, and CI now says so by name.
2. If any non-immutable entry exists, `NewFlagResolver` **must** be constructed in `cmd/api/main.go` — the exact
   structural fact whose absence made every flag inert.

Add a flag without wiring it and the build fails with the reason. That is what makes this retired rather than
merely fixed.

## 7. Ask

- **(a)** Delete-not-wire for `soar.destructive_enabled` / `ai.egress_restricted` (§3). This is the one real
  judgement call, and it turns on whether a third arming name is worse than a missing one. I think clearly yes.
- **(b)** The three unbuilt-promise flags are deleted rather than implemented. If `notify.delivery_enabled` is a
  control the SOC actually wants (a "stop all notifications" switch is a reasonable thing to want), it is a
  feature request with a real design, not a registry string — say so and it gets a slice.
- **(c)** The immutable trio stays as an assurance surface. For CSA accreditation, "MFA enforcement is
  code-owned and cannot be disabled by configuration — here is the screen that says so" is worth having.
