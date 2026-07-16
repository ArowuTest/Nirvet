# Gate — Protected-target reachability + asset-criticality coherence (D5)

**Status:** §4.1 (reachability) BUILT — §4.2 (asset-criticality derivation) awaiting reviewer/owner pass
**Raised by:** reviewer (registry divergence) → builder verification widened it
**Touches:** SOAR blast-radius safety guard (HEAVY).

**Why §4.1 was built before the pass, and §4.2 was not.** §4.1 decides nothing: 0098 already declares the intent
("the tenant/operator designates its crown jewels"), and the table, the RLS policies, the grants (0117) and the
reader all exist. Building the write path finishes a design that was already reviewed and shipped incomplete — it
cannot change response behaviour, because today the list is empty and an empty list allows everything. §4.2 is the
opposite: deriving protection from `assets.criticality` would change which containments get withheld, on live
estates, based on a field operators populated for triage rather than for response. That is a decision, so it waits.

---

## 1. The finding, verified

The D5 protected-target guard is real, correct, and tested. Its deny-list is **empty and unpopulatable**.

| Layer | Table | Reader | Writer | Production state |
|---|---|---|---|---|
| L2 directory roles | `protected_directory_roles` | `ProtectedRoles()` | migration 0066 seeds 4 global rows | ✅ **functioning** |
| L1 identities | `protected_identities` | `ProtectedIdentities()` | **none** (one *test* does a raw INSERT) | ❌ **empty** |
| M3 hosts | `protected_hosts` | `ProtectedHosts()` | **none at all** | ❌ **empty** |

Verified: `grep -rniE "insert into|delete from|update protected_"` across the whole repo returns exactly one hit —
`sliceb_entra_integration_test.go:236`. No route in `cmd/api/main.go`. No reference anywhere in `frontend/`.
No seed in 0098 or 0117.

**The decisive mechanism — an empty deny-list ALLOWS, it does not withhold.** `connector/host_guard.go:70`:

```go
patterns, err := g.cfg.ProtectedHosts(ctx, tenantID)
if err != nil {
    return false, "", err     // → supervisor fails CLOSED (cannot verify blast radius → refuse)
}
if len(patterns) == 0 {
    return false, "", nil     // nothing designated protected → nothing to resolve, ALLOW
}
```

The fail-closed-on-error path is correct and deliberate. But the empty-list path — the one that is actually live
in production — returns **allow**. So the guard is not a stuck brake; it is a **silent no-op**. Every
`isolate_endpoint` sails through the crown-jewel net, and the code, the audit trail and the tests all look healthy
while it happens. There is no error, no log line, no withheld run: nothing to notice.

**Near-miss worth recording.** Migration `0117_protected_tables_grant_parity.sql` fixed a real bug in this exact
table — 0098 created four RLS policies and zero grants, so `nirvet_app` would have hit `permission denied` — and a
schemacheck CI fence now retires that whole class. Good work. But 0117 granted `INSERT, UPDATE, DELETE` on
`protected_hosts` **to a role that has never written to it, from code that does not exist**. A pass reading this
table closely enough to fix its privilege model still did not notice that nothing is connected to the other end.
Grant parity is checked by CI; *reachability* is checked by nothing. That is the gap this gate is about.

`0098_protected_hosts.sql` states the design intent plainly:

> "protected_hosts is the per-tenant config (no hardcoding) … Empty by default (same posture as
> protected_identities — **the tenant/operator designates its crown jewels**)"

The designation surface was never built. So the promise — "refusal for a crown-jewel host (a domain controller,
the host running the Nirvet collector, a life-critical server)" — is unkeepable today for hosts and identities.

**Why it survived review:** the integration test inserts its own rows via raw SQL. It proves the guard works
*given data*; it cannot notice that no data path exists. This is J1's shape one layer down — built, tested,
unreachable. J1 was "no UI calls POST /playbooks/{id}/run"; this is "no UI writes the deny-list".

**Blast radius (Ghana):** ~250 agencies, none able to designate a crown jewel. Only the 4 seeded Entra roles
protect anything. Latent while `destructive_enabled` is off per tenant — the same arming condition as J3.

## 2. The coherence half (the reviewer's original point)

`assets.criticality ∈ (low|medium|high|critical)` is where an operator ALREADY declares what matters, and it is
manager-gated, in the UI, and used for triage/SLA. The guard never reads it. So marking the payroll server
`critical` buys **zero** SOAR protection while the UI says it is critical — the operator's mental model and the
enforcement path disagree silently.

This is the same shape as BUG-10 (two definitions of "open incidents") and J3 (two views of what a customer may
see). Three instances ⇒ propose naming the invariant (§5).

## 3. Options considered

| Option | Verdict |
|---|---|
| **A. Auto-derive protected targets from `criticality='critical'`** | **Rejected as the sole fix.** `protected_hosts.pattern` is a case-insensitive **substring** match. Deriving patterns from asset refs silently over-matches: an asset named `db1` would protect `db10`, `db11`, `db-legacy`. Over-protection is the fail-safe direction, but silent over-matching is still a surprise, and it makes the deny-list unauditable ("why was this withheld?"). |
| **B. Build the management surface only (API + UI)** | Necessary but insufficient — leaves the operator maintaining the same fact in two places, which is how the divergence started. |
| **C. B + explicit, audited derivation with EXACT matching** | **Proposed.** Build the surface; additionally offer criticality-derived entries as **exact-ref** matches (not substrings), clearly labelled as derived, and surfaced in the UI so the operator can see and audit them. |
| **D. Surface the divergence only (warn)** | Minimum honest step; keep as fallback if C is judged too large for the launch line. |

## 4. Proposal (C) — scope

1. **Reachability (the J1-shaped fix).**
   - `GET/POST/DELETE /soar/protected-hosts`, `/soar/protected-identities`, sitting with the other SOAR safety
     config (`/soar/settings`, `/soar/authority`).
   - **Authority is asymmetric, and deliberately so.** My first draft said "padmin for global rows, manager for
     tenant rows" — that is *wrong*: RLS `WITH CHECK (tenant_id = app_current_tenant())` means the app role can
     never write a global row at all (globals are superuser-seeded by migration). The real axis is not who owns
     the row, it is **which direction the change moves the net**:
     | Verb | Effect on blast radius | Gate |
     |---|---|---|
     | `GET` | none — explains *why* a run was withheld | `provider` |
     | `POST` | **tightens** (more targets refused) | `manager` |
     | `DELETE` | **weakens** (a crown jewel becomes auto-isolatable) | `padmin` |
     This is not a new principle — it is the codebase's existing "config overrides may only tighten" guardrail
     (the M1/L1/L2/L3 cluster) applied to the one config that had no write path to guard.
   - Console UI under the Policies hub (it already answers "what governs this tenant?").
   - Audit every write. Removing a protection is the consequential act and must be at least as visible as adding one.
2. **Coherence.** Assets at `criticality='critical'` are offered as protected targets, matched **exactly** on the
   asset ref, marked `derived_from_asset`, and shown alongside manual rows. Never a substring.
3. **Honest state.** Until a tenant designates anything, the UI must say the deny-list is empty and what that
   means — not imply protection that does not exist.

**Explicitly NOT in scope:** auto-enabling derivation by default (that is an ROE decision — see
`project_nirvet_j2_j3_authority`), and the ROE tiering itself.

## 5. Proposed invariant (for the reviewer)

> **A declaration the product invites an operator to make MUST be the same record the enforcement path reads.**
> If enforcement reads a parallel store, either (a) wire the declaration to it, or (b) do not offer the
> declaration. A surface that says "critical" while the engine reads another table is a lie with a latency.

Known instances: **BUG-10** (posture vs incident list), **J3** (customer prose vs read-model), **this**
(criticality vs protected_*). Suggested follow-up: a sweep for a fourth — candidates are suppression rules,
maintenance windows, and connector `enabled` vs what the poller actually reads.

## 6. Risk of the change itself

- Adding rows to a deny-list only ever **withholds** more; it cannot cause an unwanted action. Fail-safe direction.
- Over-protection has a real operational cost (withheld containment → escalation at 2am). Exact matching bounds it.
- The guard is on the destructive path but **dormant** until `destructive_enabled` — so this lands cold, like
  slices B/C did.

## 7. What shipped in §4.1

`soar/protected_targets.go` (repo + service + validation + audit), `protected_targets_handler.go`, three routes,
migration 0128 (uniqueness parity with 0066), `protected_targets_test.go`, and the console screen
`/console/protected-targets`. OpenAPI documented (the parity fence caught the three routes — as designed).

Two things worth the reviewer's eye:

- **The validation is the feature.** Both guards fail OPEN on an unmatchable value: a wildcard, or a partial UPN
  against an exact-match list, silently protects nothing while the UI shows a populated deny-list. That is the same
  class as the original bug, one level up, so it is refused at the door with an error that explains the matching
  semantics. My first cut of that check tested whether a value was *entirely* wildcards, which waved `*.corp.*`
  straight through — the likelier and more dangerous input, because it reads like a considered rule. The unit test
  caught it. The glob set is exactly `*?%`; `.`, `_` and `-` are legal in real hostnames and must be accepted.
- **The empty state is deliberately blunt.** "No hosts are protected — nothing is exempt from automated response"
  rather than a neutral "no results". A reassuring empty state is precisely what let this survive review.

Not built, deliberately: nothing seeds a tenant's deny-list at onboarding. A fresh agency starts with zero
protected hosts, and the screen now says so. Whether F3 onboarding should *require* designating the crown jewels
before `destructive_enabled` can ever be turned on is an ROE question, in §8.

## 8. Ask

Reviewer/owner pass on:

- **(a)** Option C vs D for §4.2 (derivation from `assets.criticality`) on the launch line.
- **(b)** The direction-based gate split — read `provider`, add `manager`, remove `padmin`. Note this corrects my
  own first draft, which proposed splitting on global-vs-tenant rows; RLS already makes global rows unwritable by
  the app role, so that split was meaningless.
- **(c)** The invariant in §5, and whether the fourth-instance sweep is worth a slice. Two candidates already
  surfaced while building this: `/soar/settings`, `/soar/platform` and `/soar/authority` have **no frontend
  consumer either** — the whole SOAR safety-config family is API-only. Same shape, lower stakes.
- **(d)** Should a tenant be blocked from enabling `destructive_enabled` until it has designated at least one
  protected target (or explicitly recorded that it has none)? That converts this from a screen someone must
  remember to visit into a step the dangerous toggle depends on. It is an ROE call, not an engineering one.
