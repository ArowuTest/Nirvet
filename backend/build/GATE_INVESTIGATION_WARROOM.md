# Pre-code Gate — §6.9 Investigation war-room (collaborative investigation space) — reviewer-authored

Status: **CLEARED TO BUILD — reviewer-authored (Fable 5, Jul 20 2026), decisions LOCKED.** Loop: reviewer writes → builder implements → CI-green → reviewer source-verifies. Answers `GATE_REQUEST_INVESTIGATION_WARROOM.md`.
Scope: **P/B** — product depth, not go-live-gating, but it INVERTS the private-per-analyst model, so the security half is heavy. Falsification bar: "what leaks a case to someone who shouldn't see it, or lets a lower-role member see field data masking would hide."

## 0. The inversion, and the one rule that governs it

Every §6.9 surface today is PRIVATE per analyst (notebooks mig 0125, saved views mig 0139 — `user_id`-owned). A war-room is SHARED: cross-*analyst* data flow inside a tenant. The governing rule, from which everything else follows: **the shared store holds REFERENCES and re-runnable queries, never rendered/unmasked answers.** Store the question, re-mask for whoever reads — exactly the saved-views property, applied to a shared surface. Two attacks the builder's request under-specifies get first-class treatment below: the **self-join** (D4) and the **stale-member side-channel** (D2).

## 1. Locked decisions

### D1 — Membership = explicit invite (least-privilege)
A room has an owner + an explicit member set; only members read/write. **NOT open-to-tenant** (that broadcasts a possibly-sensitive case to the whole SOC). Confirmed.

### D2 — Incident-scoped; membership ⊆ incident-access, enforced at invite AND read (revocation-aware)
The room binds to an `incident_ref`. **Two enforcement points, both required:**
- **At invite:** the owner may only add a member who *independently* has access to that incident (an invite must not become a back-door grant to an incident the invitee otherwise can't see). Room *creation* likewise requires the creator to have incident access.
- **At read (the one the builder's request misses):** war-room content access = **is-member AND can-access-incident, evaluated LIVE.** If a member's incident access is later revoked, they lose war-room content access immediately — membership is NOT a durable side-channel that outlives the incident grant. Do not check incident-access only at invite and then trust membership forever. (If enforcing this per-read is costly, the acceptable alternative is: incident-access revocation *cascades* to war-room membership removal, audited — but the read-time invariant is the requirement; the cascade is one way to satisfy it.)

### D3 — Per-viewer masking (the crux) — and the HONEST note boundary
- **Structured content (`query_ref`, `timeline_pin`) is stored as a REFERENCE and re-run through `RunHunt` per viewer** → re-masked for the reader's role at read time. NEVER store rendered/unmasked result rows in the shared store. This is escalation-safe by the saved-views property (a junior running a senior's ref is bounded by the junior's own field-visibility).
- **`note` entries are author-authored free text (prose) and are shared AS-AUTHORED to all members.** Be honest about the boundary this creates: references-not-rows prevents the *system* from ever rendering an unmasked row into the shared store — it does NOT stop an author from *typing* a value they saw into a note. So within a war-room, strict per-field masking holds for structured refs but **not** for content a member deliberately pastes into prose. That is an insider-trust matter (the author is an incident collaborator who already has incident access), not a system-masking failure — name it, do not pretend the masking model covers it. **If a deployment needs field-masking to hold even against deliberate paste, the control is a membership role-floor** (only members at/above the field's role) — flag this as a config option; for slice 1, document the prose boundary rather than build the floor.

### D4 — Membership-based RLS on ALL THREE tables + the self-join lock
`investigation_war_rooms`, `investigation_war_room_members`, `investigation_war_room_entries` each get FORCE-RLS + `tenant_isolation` + `owner_bypass` + a **membership policy** `EXISTS(member row WHERE room = this.room AND user_id = app_current_user() AND tenant = app_current_tenant())`. Guard the CHILD tables (members, entries), not just the parent — a common bug is a locked room table with a leaky entries table.
- **THE critical write-policy point — no self-join:** INSERT into `investigation_war_room_members` must be restricted to the **room owner** (or a delegated moderator per D5). A member — let alone a non-member — must **not** be able to insert their own member row and thereby join a room. The RLS write policy on the members table is the structural lock; the handler's owner-check is defense-in-depth. This is the escalation this whole surface must prevent, and it gets its own test.

### D5 — Entries append-only; owner archives the room
Entries are **immutable once posted** (append-only — preserves the investigative record like audit). No member edits or deletes another member's entry. The owner may **archive the room** (soft) and manage membership; the owner does not rewrite entries. (Author-deletes-own-entry within a short window is an acceptable refinement; cross-member deletion is not.)

### D6 — Audit + lifecycle
Membership changes (invite/remove) are a **data-sharing grant** — audit each with actor + target + room. Entry posts audited. Lifecycle: archive on incident close; retention follows the incident's retention (do not let war-room content outlive the incident it belongs to).

## 2. First slice (accepted, lightly trimmed)
Tables + membership-RLS + explicit-invite + references-only content + routes (create room, invite/remove member [owner-only], list/add entries, run a referenced query via existing `RunHunt`). **Trim for slice 1:** `kind ∈ note | query_ref` is enough; `timeline_pin` can follow. Out of scope stays as the builder listed (real-time presence, @-mentions, cross-incident rooms, external participants).

## 3. Load-bearing falsification tests (each mutation-sensitive; the DB ones on the two-analyst harness)
1. **Membership read isolation:** member reads room + entries; **non-member → not-found**; cross-tenant → not-found. Mutation: drop the `EXISTS(member)` clause → non-member reads → RED.
2. **Self-join blocked (D4):** a non-owner member — and a non-member — **cannot INSERT a member row** (cannot add themselves or anyone). Only the owner invites. This is the escalation test; RLS write-policy + handler both enforce.
3. **Per-viewer masking (D3):** a shared `query_ref`, run by a junior member, **re-masks a field the senior author could see** — the junior never sees the senior's unmasked field via the shared ref. Mutation: store rendered rows instead of the ref → junior sees it → RED.
4. **Incident-access gate (D2):** cannot create a room for, or be invited to, an incident you can't access; **a member who loses incident access loses war-room content access** (revocation-aware read) — the stale-member side-channel is closed.
5. **Append-only (D5):** a member cannot edit or delete another member's entry.
6. **Audit (D6):** invite/remove writes an audit row naming actor + target + room.

## 4. Out of scope (follow-ons)
Real-time presence/websockets · @-mentions/notifications · cross-incident rooms · external (customer) participants · membership role-floor for paste-proof masking (D3, config option).

---
### Reviewer sign-off (I source-verify after CI-green)
- [ ] D1 explicit-invite, owner + member set; not open-to-tenant.
- [ ] D2 incident-scoped; incident-access verified at invite AND re-checked at read (revocation-aware) — test #4.
- [ ] D3 structured content = references re-masked per viewer (test #3); note-prose boundary documented, not misrepresented.
- [ ] D4 membership-RLS on all three tables + **members INSERT owner-only (no self-join)** — test #2 is the escalation proof.
- [ ] D5 entries append-only; owner archives room; no cross-member entry mutation — test #5.
- [ ] D6 membership changes audited (data-sharing grant) — test #6; lifecycle ties to incident retention.
