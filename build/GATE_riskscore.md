# Pre-code gate — Per-tenant Composite Risk Score

**Date:** 2026-07-14 · **Owner decision:** build now, "best-in-class" (raised during single-client discussion —
a direct client's primary surface is the portal, and the composite score is the headline "how are we doing").
**Reviewer/builder:** same principal (interim). Ties [[feedback_nirvet_ui_depth]], [[feedback_nirvet_no_hardcoding]].

## The gap this closes (verified real)
No backend computes a per-tenant composite risk score. `posture` pkg = regulator/fleet oversight only. The
Customer-Dashboard mockup's "Risk Posture 70 · Endpoint 68 · Identity 81 · Cloud 45" sub-scores are a **design
fiction** — nothing measures identity/cloud/network as discrete quantified dimensions. Building those would be
fabrication. This gap matters MORE for single/direct clients (portal = their whole experience) than for the
MSSP-operator-first model.

## Honest model (only real inputs; signal-based, not domain-based)
Composite RISK 0–100 (higher = worse, matches the "Risk Posture 70 Elevated" framing), from three components each
computed transparently and shown to the user (explainable, never a black box):

| Component | Real source (per-tenant, RLS-scoped) | Risk formula |
|---|---|---|
| **Exposure** | `vulnerability.ExposureSummary` (by-severity, exploited_open, past_due) | `points = Σ sevWeight·count + exploitedPenalty·exploited + overduePenalty·pastDue`; `risk = 100·(1−e^(−points/halflife))` (saturating, monotonic — diminishing returns past saturation) |
| **Compliance** | `compliance.ListFrameworks`+`Assess` → avg coverage% | `risk = 100 − avgCoverage%`. Excluded (not 0) when no framework enabled → renormalize |
| **Operational** | `reporting.Summary` → SLA (ack/resolve breaching, open incidents) + open alerts | `points = openIncW·open + breachW·(ackBr+resolveBr) + lateW·resolvedLate`; saturating as above |

**Composite** = weighted mean over PRESENT components (renormalize weights when compliance absent — never fabricate
a value for missing data). **Band** = first threshold ≥ composite → {label, tone}. Default bands:
[0,20)=Low, [20,40)=Guarded, [40,60)=Moderate, [60,80)=Elevated, [80,100]=High.

## No-hardcoding (mig 0121 `risk_score_config`, seeded default row, tenant-overridable)
- **Operator-facing policy (DB, tunable):** the 3 component weights + the band thresholds/labels.
- **Model internals (DB jsonb `model_params`, seeded, tunable but rarely touched):** severity point-weights,
  exploited/overdue penalties, half-lives, operational weights. All in data, not code constants.
- Resolution: tenant row → else global-default row → else code fail-safe default (defence in depth). Mirrors
  `disclosure_policy`/`authority_policies`. RLS FORCE, tenant-scoped; padmin/customer_admin manage own tenant.
- **Validation:** weights ≥ 0 and not all zero; bands ascending, cover 0..100, valid tones. Reject otherwise
  (config that would divide-by-zero or mislabel is a 400, never silently applied).

## Surfaces
- `GET /risk-score` (provider/senior — own tenant): full `Score{composite, band, tone, components[], generated_at}`
  where each component carries its Risk + weight + the driving numbers (drivers map) so the UI explains it.
- `GET/PUT /admin/risk-config` (padmin; customer_admin own tenant): read/tune weights + bands.
- `GET /customer/risk-score` (customerRead → readmodel projection): the score is aggregate-safe (only counts about
  the customer's OWN estate), but still goes through `custReadH` as a `CustomerRiskScoreView` so the audience fence
  stays green and the boundary is uniform. No internal field exists on the view by construction.

## DoD
- `internal/riskscore`: `riskscore.go` (PURE math — Score/Component types + Compute from inputs+config; unit-tested
  DB-free with table-driven cases incl. saturation, renormalization-when-compliance-absent, band edges,
  monotonicity), `config.go`+`repo.go` (config resolve/validate/set), `service.go` (Compute pulls the 3 inputs via
  injected reader interfaces), `handler.go`.
- Migration 0121 + seed; from-zero migrate green. RLS FORCE + schemacheck allowlist if needed.
- readmodel: `CustomerRiskScoreView` (allowlist) + `GET /customer/risk-score`; reflection test; fence green.
- OpenAPI parity; gofmt/vet/build; `go test ./...`.
- **RS2 (next):** UI — portal "Security Posture" page (composite gauge + component breakdown, each linking to its
  detail: exposure→vulns, compliance→compliance, operational→incidents) + console exec card + admin config screen.

## Non-goals (V2, documented not faked)
Domain sub-scores (endpoint/identity/cloud/network) — need per-domain telemetry mapping. Trend/history over time —
needs a snapshot table + scheduled compute. Both are honest fast-follows, not shipped as fake data now.
