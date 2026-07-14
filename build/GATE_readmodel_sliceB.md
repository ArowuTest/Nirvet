# Pre-code gate — Customer read-model Slice B (customer portal depth)

**Date:** 2026-07-14 · **Owner decision:** build-now (full Slice B) · **Reviewer/builder:** same principal (interim).
**Trigger:** live QA — the customer portal (`custadmin@nirvet.test`) renders only Overview/Incidents/Alerts. That is
*correct* for Slice A, but the `Customer-Dashboard` mockup (Meridian MDR portal) expects posture, assets, vulns,
compliance, and a customer approvals queue. Those need audience-projected reads that were deferred (task #163).

## Governing invariant (unchanged from Slice A — audience.go)
The presentation boundary IS a security boundary. A customer principal may reach ONLY `readmodel.Handler`
(`custReadH.*`), which may emit ONLY positive-allowlist `*View` structs — never a raw domain entity. Enforced by:
`requireAudience(AudienceCustomer)` in every handler, the `check-audience-projection.sh` CI fence, and reflection
tests. RLS already isolates cross-tenant; this layer isolates cross-AUDIENCE within the tenant's own data.

**Slice B adds NO new table and NO new cross-tenant path.** Every read is the customer's OWN tenant (`p.TenantID`),
composed over existing RLS-scoped services. This is strictly less risky than the regulator path (which is
cross-tenant); it is read-only except the approvals sub-slice (SB3), gated separately below.

## Sub-slices (each independently shippable, CI-green, live-verified)

### SB1 — read projections: Assets, Vulnerabilities, Compliance  ← THIS BATCH
New positive-allowlist projections + 3 `customerRead(custReadH.*)` routes. No migration.

| View | Source (RLS-scoped, own tenant) | EXPOSE (customer-safe) | WITHHELD by construction |
|---|---|---|---|
| `CustomerAssetView` | `asset.Service.List(tenantID)` | ref, name, kind, criticality, created_at | owner (internal assignment), tags (may carry internal labels), tenant_id, internal id |
| `CustomerVulnerabilityView` | `vulnerability.Service.List(tenantID,"","")` | ref (their asset), cve, title, severity, cvss, exploited, status, remediation_due, created_at | tenant_id, internal id |
| `CustomerComplianceView` | `compliance.ListFrameworks` + `Assess(key)` per enabled framework | framework name, key, version, score, controls met/total, summary counts | control-level internal notes, weights, evidence pointers |

Rationale for withholding `owner`/`tags` on assets: an MSSP may tag/own an asset with internal operational
metadata (analyst pod, playbook binding). Fail-closed: absent from the struct, cannot leak. If a customer genuinely
needs a business-owner field later, it becomes a deliberate, reviewed addition — the allowlist makes that explicit.

### SB2 — customer Security Posture / Risk Overview  (next)
Read the tenant's OWN latest posture snapshot (confirm read surface; `postureproj` only writes — the read used by
the console dashboard is the source). Project composite score + sub-scores (endpoint/identity/cloud/network/vuln
coverage) as `CustomerPostureView`. No other tenant, no fleet — the `oversight` fleet read stays regulator-only.

### SB3 — portal SOAR Approvals queue  (next; HIGHER consequence — this is a customer WRITE)
The only write in Slice B. A customer approves/rejects a pending destructive SOAR action their operator routed to
them (customer-approval was built #188 as a single-use out-of-band link; SB3 surfaces it inside the portal).
**Must-adds before SB3 code:**
1. Reuse the EXISTING customer-approval authority + two-principal + single-use + execution-time re-validation
   logic — do NOT create a parallel approval path. The portal action is a thin authenticated front-door to the
   same record + guard.
2. `requireAudience(AudienceCustomer)` + the action must be scoped to a run whose target tenant == `p.TenantID`
   (a customer can never approve another tenant's action). Fail-closed.
3. The approval decision is an append-only audited event (actor = the customer principal), and it must NOT itself
   execute anything destructive inline — it flips the run to approved and lets the existing supervised executor
   pick it up (preserves the dormant-until-configured containment posture).
4. A rejected/expired/already-decided run is a typed 409, never a silent re-approve.

## Definition of done (per sub-slice)
- New `*View` structs in `projections.go` (allowlist, JSON-tagged to what the portal renders).
- New narrow reader interfaces in `handler.go` (satisfied by existing services; keeps the package composing-only).
- Handler methods: `requireAudience(AudienceCustomer)` → own-tenant read → project → JSON. Never a raw entity.
- Routes on the `customerRead(custReadH.*)` chain only → fence stays green.
- Tests: reflection/allowlist test that the new views carry no internal field; handler test for audience 403 +
  own-tenant scoping. `go test ./... ` green; `check-audience-projection.sh` green; from-zero migration green (SB3).
- OpenAPI parity regenerated; gofmt/vet/build green.
- Frontend: portal nav + page per view, wired to `apiGet`, honest empty states, `tsc --noEmit` clean.
- Live-verify on the deploy as `custadmin@nirvet.test`; confirm a provider role does NOT get these customer routes
  (they 403) and the customer does NOT see any withheld field in the network response.

## Non-goals (stay V2)
Customer Identity-risk drilldown, Integration-Health customer view, customer-authored Reports, customer Settings
beyond profile/notification-prefs (already exist). Not fabricated — simply not in this slice.
