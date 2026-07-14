# Pre-code gate — B4: Manager team / workload view (UI-depth Bucket B)

**Owner directive:** build backend+UI *gated*; no hardcoding; honest states. This note precedes code.

## Problem / SRS grounding
A soc_manager needs to see who is carrying what — per-analyst open-incident load, how much of it is critical, and
where SLAs are breaching — to balance the team. Today `GET /incidents` lists incidents and `GET /incidents/at-risk`
lists SLA-risk incidents, but there is **no per-owner workload aggregate**. Incidents already carry the data:
`owner_id` (assignee, nullable), `severity`, `closed_at` (open = NULL), and SLA due timestamps
(`ack_due_at`/`resolve_due_at`/`acknowledged_at`) from which breach is **derived on read** (mig 0020 — breach is
not a stored column, so the aggregate must derive it in SQL, matching `sla.go`).

## Design (what to build) — read-only aggregate, no new table, no migration, no RLS change
- **Route:** `GET /incidents/workload` — **manager-gated** (`manager(...)`, same tier as other team-management
  reads). Add to `api/openapi.yaml`.
- **Repo:** `Repository.WorkloadByOwner(ctx, tenantID) ([]WorkloadRow, error)` — one `GROUP BY` over open
  incidents, `LEFT JOIN users u ON u.id = i.owner_id` for the email. Both tables are tenant-RLS-scoped under
  `WithTenant`; a `LEFT JOIN` keeps the `owner_id IS NULL` bucket ("Unassigned"). Breach derived in SQL exactly
  like `sla.go`:
  - ack-breached (open): `ack_due_at IS NOT NULL AND acknowledged_at IS NULL AND ack_due_at < now()`
  - resolve-breached (open): `resolve_due_at IS NOT NULL AND resolve_due_at < now()`
  - at-risk (not yet breached, due within 30m): the `ListAtRisk` window, excluding rows already counted breached.
- **Service:** `Service.Workload(ctx, tenantID)` returns the rows (thin passthrough; ordering by sla_breached
  desc, open_total desc done in SQL).
- **Handler:** `GET` → `{"workload": rows}` (envelope consistent with the module's other list handlers).
- **Shape (`WorkloadRow`):** `owner_id *uuid` (null = unassigned), `owner_email string` ("" when unassigned →
  UI shows "Unassigned"), `open_total`, `open_critical`, `open_high`, `sla_breached`, `sla_at_risk`,
  `oldest_open_at *time`.

## Invariants / guardrails
1. **RLS-scoped only.** The aggregate runs under `WithTenant(tenantID)` — it can never count another tenant's
   incidents, and the user join is same-tenant. No cross-tenant reach.
2. **manager only.** A non-manager 403s → UI shows an access note. (An analyst sees their own queue via the normal
   incident list; the workload roll-up is a lead's tool.)
3. **No hardcoding.** The 30-minute at-risk window mirrors the existing `ListAtRisk` behaviour (kept identical so
   the two surfaces agree); no new magic numbers introduced beyond that shared one.
4. **Honest empty state.** Zero open incidents → empty workload with an honest "no open incidents" message, never
   fabricated rows.
5. CI: gofmt/vet/build, OpenAPI parity, `go test ./internal/incident/` — no schemacheck/migration/RLS-table change.

## Tests
`workload_test.go` (integration, DB-gated like the module's other repo tests): seed incidents across two owners +
one unassigned, some past-due → assert per-owner counts, the unassigned bucket, and derived sla_breached. Guard
with the same build tag / DB-skip the package already uses.

## UI (after backend green)
`console/workload` (nav: Response > Workload; manager-gated view — 403 → access note): totals KPI strip
(analysts with load, total open, total SLA-breached), then a per-owner table (owner/email, open, critical, high,
breached, at-risk, oldest) with the Unassigned row highlighted. Row links to the incident list filtered by owner
where possible. Honest empty state.

## Out of scope
Time-tracking, shift scheduling, capacity forecasting — not backed and not in SRS scope; not faked.
