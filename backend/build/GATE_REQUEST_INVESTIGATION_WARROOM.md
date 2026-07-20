# Pre-code GATE REQUEST — §6.9 Investigation war-room (collaborative investigation space)

Status: **DESIGN — awaiting reviewer pre-code gate. NOT built.** The rest of #172 (notebooks, hunt-query engine,
saved views) shipped; war-room is held back because it INVERTS the security model everything else in §6.9 relies on.

## Why this needs a gate (the model inversion)

Every §6.9 surface today is **PRIVATE per analyst** — notebooks (mig 0125) and saved views (mig 0139) are `user_id`-owned,
RLS-scoped so no peer ever reads them. A war-room is the opposite: a **SHARED** space where multiple analysts in a
tenant see and edit the same case material together. That inversion is the whole security surface — it introduces
cross-*analyst* (not cross-tenant) data flow inside a tenant, and it must not become a way to (a) leak a case to an
analyst who shouldn't see it, or (b) let a lower-role analyst see field data the per-actor masking would hide.

## The load-bearing questions for the gate to lock

1. **Membership model — explicit-invite vs open-to-tenant.** Recommend **explicit membership** (least-privilege): a
   war-room has an owner + an explicit member set; only members read/write. Open-to-every-analyst-in-the-tenant is
   simpler but broadcasts a possibly-sensitive case to the whole SOC. Which?
2. **Incident scoping.** A war-room should be bound to an incident/case; membership ⊆ those who can access that
   incident (don't let war-room membership become a side-channel around incident access). Confirm.
3. **Per-viewer field masking (THE crux).** If a war-room surfaces hunt-query results / entity data, the per-actor
   masking (query must-add #3: a field above your role is masked) MUST re-apply **per viewer at read time** — a junior
   member must never see a senior member's unmasked field via the shared space. So the shared store must hold
   **references / re-runnable queries**, NOT pre-rendered unmasked result rows. (Mirrors saved-views: store the query,
   re-validate + re-mask for whoever runs it — never store the answer.) This is the single most important rule.
4. **RLS shape.** A shared table can't use the `user_id = owner` policy; it needs a **membership-based** policy
   (tenant_isolation + `EXISTS(member row for app_current_user)`). That is a different, more error-prone RLS shape —
   the gate should require a two-analyst test: member reads, non-member gets not-found, cross-tenant blocked.
5. **Write authority + moderation.** Who can post/edit/remove content — all members, or owner-moderated? Can a member
   remove another's contribution? Recommend append-mostly + owner-can-archive.
6. **Audit + lifecycle.** War-room actions audited; content lifecycle (archive on incident close; retention).

## Proposed first slice (for the gate to accept/trim)

- `investigation_war_rooms` (tenant, incident_ref, owner, title, status) + `investigation_war_room_members`
  (room, user_id, role) + `investigation_war_room_entries` (room, author, kind ∈ note|query_ref|timeline_pin, body).
- Membership-based RLS (member-only read/write; owner manages membership). Explicit invite.
- Content is **references** (a note's markdown; a saved-view/query REFERENCE that each viewer runs through RunHunt →
  re-masked per viewer). No stored unmasked result rows.
- Routes: create room, invite/remove member, list/add entries, run a referenced query (via existing RunHunt).
- Tests: two-analyst membership (member vs non-member vs cross-tenant); per-viewer masking of a shared query-ref;
  audit on membership change.

## Explicitly out of scope (follow-ons)
Real-time presence/websockets · @-mentions/notifications · cross-incident rooms · external (customer) participants.

On your gate I build it as one reachable unit with the two-analyst + per-viewer-masking tests as the load-bearing pass.
