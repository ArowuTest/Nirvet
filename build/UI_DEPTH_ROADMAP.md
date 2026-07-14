# Nirvet — UI Depth Roadmap (all personas, all use-cases)

**Owner directive (Jul 14 2026):** every user type and every page must have full best-in-class depth so each
persona can *fully manage their activities* — not just the daily loop, but the architect/operator management
surfaces too. Build backend+UI GATED where backend is missing (no fakes, no hardcoding). Start with the
operator/admin bucket. This file is the durable record — **update the `Done?` column as items land** so a
context compaction never loses the plan.

## Personas & their jobs-to-be-done
- **platform_admin** — operator/instance owner: tenant lifecycle, billing, all config, health, white-label, oversight.
- **soc_manager** — SOC lead: triage assignment, SLA/escalation, authority-to-act, PAM grants, playbooks, reporting.
- **analyst_t1/t2/t3** — daily ops: triage, investigate, hunt, respond, evidence, self-elevate (PAM).
- **detection_engineer** — architect: detection authoring/tuning, coverage, test/simulate.
- **customer_admin** — customer lead: own posture/incidents/alerts/assets/vulns/compliance, approvals, own users.
- **customer_viewer** — read-only customer.
- **org_sub_admin / payer** — regulator/anchor oversight: grant-scoped metadata rollups.

## What's already DONE (baseline — do not rebuild)
- Customer portal 100% depth: overview, posture (risk gauge+breakdown), approvals (queue+modal), incidents
  (detail+timeline), alerts, assets (blast-radius detail), vulns, compliance (control drill-down), all cross-linked.
- Console daily loop: alerts/incidents/detections (list+detail), assets (list+create+detail), compliance (drill+attest),
  threat-intel (add+STIX detail), playbooks (runs+steps+inline approve/reject), events (detail modal), integrations,
  evidence, reports, exec (risk card), notifications, settings + settings/tenant (SLA/correlation/session/escalation/
  authority-to-act), admin (tenants/iam/billing/flags/audit/risk).
- Risk-score full (portal+console+admin), SB3 customer approvals (backend+portal), migration owner_bypass fix (0122).

---
## GAP REGISTER

### Bucket A — BACKED, UI-only (fast, high value). Sequence first.
| ID | Persona | Capability | Backend (exact) | What to build (UI) | Done? |
|----|---------|-----------|-----------------|--------------------|-------|
| A1 | platform_admin / soc_manager | **Customer-approval authority mode** (routes destructive-action approval to the customer). **Unblocks the SB3 queue I shipped** — without this no run ever routes to a customer. | `GET /soar/customer-approval` (provider), `PUT /soar/customer-approval` (soarApprover). Policy: `authority` (platform_analyst\|customer_approver\|both_required), `bc_customer_authorizable`, `link_ttl_seconds` 300..86400, `customer_approver_ref`. | Console admin page (or settings/tenant panel): show + set the mode, TTL, approver ref. Manager-gated. | ✅ (settings/tenant "Customer approval routing" panel; GET/PUT /soar/customer-approval) |
| A2 | analyst (self) + soc_manager (grant) | **PAM elevation + break-glass** (§6.2 IAM-004/006). Full workflow, zero UI. | self: `POST /me/elevations`, `GET /me/elevations`, `POST /me/elevations/break-glass`, `POST /me/elevations/{id}/token`. admin: `GET /admin/elevations` (manager), `POST /admin/elevations/{id}/approve\|reject\|review`. | (a) analyst self-service: request elevation / break-glass, see my elevations, mint elevated token. (b) manager queue: pending elevations → approve/reject/review with reason. | ☐ |
| A3 | platform_admin | **White-label branding** (Ghana operator). | `GET /branding` (public), `PUT /admin/branding` (padmin). | Admin branding page: operator name/logo/colour; live preview; save. Login page already reads `GET /branding`. | ☐ |
| A4 | detection_engineer / soc_manager | **Detection / MITRE ATT&CK coverage** (DET-009). | `GET /detections/coverage` (provider). | Coverage view (matrix/heatmap by technique or a covered/gap breakdown) on the detections page or a new tab. | ☐ |
| A5 | detection_engineer | **Rule test / simulate against sample** (DET-005). | detection test endpoint (confirm exact path; §6.6 slice C test-against-sample). | "Test rule" panel in the detection editor: paste/select sample event → show match/no-match + why. | ☐ |
| A6 | analyst | **Entity / blast-radius graph** (§6.9). | `entityGraphH` handler (confirm route, e.g. `GET /entity-graph?ref=`). Composes alerts/incidents/correlations/assets for an entity. | Entity graph view: given a ref (host/user/ip), show the connected alerts/incidents/assets. Reachable from alert/asset detail. | ☐ |
| A7 | platform_admin | **AI provider / governance config** (ADMIN-001, §6.12). | `GET/PUT /admin/ai/provider`, `GET/POST/DELETE /admin/ai/allowed-endpoints`, `PUT /admin/tenants/{id}/ai-policy`. | Admin AI page: choose provider, manage allowed-endpoint allowlist, per-tenant AI policy. | ☐ |
| A8 | org_sub_admin / payer | **Regulator oversight UI**. | `GET /oversight/incidents-rollup`, `GET /oversight/alerts-rollup` (oversight-gated, metadata-only). | A regulator surface (own shell or role-scoped): grant-scoped metadata rollups only (counts/SLA, never content). | ☐ |
| A9 | platform_admin | **Admin session / user kill-switch** (revoke a user's live sessions). | user-disable / kill-switch (L9) + session generation bump via IAM; `POST /auth/logout-all` (self). | In admin/iam: a "revoke sessions / disable" action per user (may partly exist — verify, then complete). | ☐ |

### Bucket B — needs BACKEND + UI (gated slices; build after A). "Build backend+UI gated" per owner.
| ID | Persona | Capability | Backend status | Approach | Done? |
|----|---------|-----------|----------------|----------|-------|
| B1 | analyst | **AI Copilot investigation workspace** (AI-001 multi-turn, tenant-scoped, redaction-fenced). | AI gateway + governance exist; a CONVERSATIONAL multi-turn endpoint does NOT. Needs backend. | Gate → conversational endpoint through the existing `completeExternal` redaction chokepoint (fence stays green) + session/tenant scope + audit → UI chat workspace with case context. | ☐ |
| B2 | analyst / soc_manager | **Investigation notebooks / saved views / war-room** (§6.9 slice B, deferred). | Investigation slice A only (hunt allow-list). Needs backend (notebook persistence + saved views). | Gate → notebook/saved-view persistence tables + endpoints → UI notebook + saved queries + shared war-room. | ☐ |
| B3 | platform_admin | **Platform health / infrastructure dashboard** (§6.18 slice B, deferred). | `GET /healthz`, `GET /metrics` (Prometheus) exist; no aggregated health read. | Gate → thin `/admin/health` reading Prometheus/deps → UI health board (honest: single-instance where fleet N/A, never fake nodes). | ☐ |
| B4 | soc_manager | **Team / workload view** (who's assigned what, per-analyst load). | No assignment-aggregate endpoint. Needs backend. | Gate → assignment/workload aggregate (by assignee, open counts, SLA at risk) → UI manager board. | ☐ |

## Best-practice build checklist (apply to EVERY item)
1. **Backend-first is source of truth.** Bucket A = adapt UI to the real contract; only touch backend if the UI reveals a genuine gap. Bucket B = write the pre-code **gate note in `build/`** first (design vs SRS + invariants + must-adds), then entity→repo→service→handler.
2. **No-hardcoding:** every threshold/policy is an admin-config DB record with a seeded default (see risk_score_config / disclosure_policy pattern). No TODOs, no fake data — honest empty/"coming" states only where genuinely N/A.
3. **RBAC + isolation:** gate each route to the right role; customer reads go through the `custReadH` readmodel projection (audience fence); customer writes via `customerWrite` (customer_admin only). New RLS tables MUST get the `owner_bypass` policy (see mig 0118/0122) or CI `TestOwnerBypassPolicy` goes red.
4. **Tests:** unit for pure logic; adversarial handler test for authz + over-disclosure; reflection allowlist for any customer `*View`; from-zero migration green.
5. **CI gates:** gofmt/vet/build, all structural guards (audience-projection, SafeClient SSRF, SECURITY-DEFINER REVOKE, owner_bypass, etc.), OpenAPI parity (add routes to `api/openapi.yaml`), schemacheck.
6. **Verify live** on the deploy per role after each slice (drive it, don't assume). Commit as `ArowuTest`, Basic-auth push, watch CI green before the next slice.
7. **Design-token UI only** (`components/ui` + `globals.css`); modals for consequential actions (confirm before destructive/authorising).

## Sequence (owner: operator/admin first)
**Phase 1 (Bucket A, operator+architect):** A1 (customer-approval config — unblocks SB3) → A2 (PAM) → A3 (branding)
→ A7 (AI config) → A9 (session/user kill) → A4 (coverage) → A5 (rule test) → A6 (entity graph) → A8 (regulator).
**Phase 2 (Bucket B, gated):** B3 (platform health) → B4 (workload) → B1 (AI copilot) → B2 (investigation notebooks).
Checkpoint after each item; update `Done?` here. Ties [[feedback_nirvet_ui_depth]], [[feedback_nirvet_no_hardcoding]],
[[feedback_nirvet_gated_approach]], [[project_nirvet_customer_readmodel]], [[project_nirvet_riskscore]].
