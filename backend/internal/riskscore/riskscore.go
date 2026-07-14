// Package riskscore computes a per-tenant composite security-posture risk score (0–100, higher = worse) from
// signals the platform already measures: vulnerability exposure, compliance coverage, and incident/SLA posture.
//
// Design principles (see build/GATE_riskscore.md):
//   - HONEST: only real inputs. No domain sub-scores (endpoint/identity/cloud) — those aren't measured.
//   - EXPLAINABLE: each component's risk + weight + the raw driving numbers are returned, never a black box.
//   - CONFIG-DRIVEN (no-hardcoding): weights, bands, and model params come from risk_score_config (seeded default,
//     tenant-overridable). DefaultConfig() here is the code fail-safe mirroring the migration column defaults.
//   - RENORMALIZING: a component with no data (e.g. no compliance framework enabled) is EXCLUDED and the weights
//     renormalize over the present components — a missing signal is never fabricated as 0-risk or 100-risk.
//   - SATURATING: count-based components use 100·(1−e^(−points/scale)) so risk rises with diminishing returns and
//     is bounded to 100 (going from 20 to 30 open criticals barely moves an already-saturated score).
//
// This file is PURE (no DB, no clock): Compute is a deterministic function of (config, inputs), unit-tested.
package riskscore

import (
	"math"
	"sort"
	"strings"
)

// Band maps a composite range to a label + UI tone. Max is inclusive-upper; bands are evaluated ascending.
type Band struct {
	Max   int    `json:"max"`
	Label string `json:"label"`
	Tone  string `json:"tone"`
}

// ModelParams are the scoring-model internals (kept in config data, not code constants).
type ModelParams struct {
	SevWeights         map[string]float64 `json:"sev_weights"` // critical/high/medium/low → points per open vuln
	ExploitedPenalty   float64            `json:"exploited_penalty"`
	OverduePenalty     float64            `json:"overdue_penalty"`
	ExposureScale      float64            `json:"exposure_scale"`
	OpenIncidentWeight float64            `json:"open_incident_weight"`
	BreachWeight       float64            `json:"breach_weight"`
	LateWeight         float64            `json:"late_weight"`
	OperationalScale   float64            `json:"operational_scale"`
}

// Config is the resolved risk-score configuration for a tenant.
type Config struct {
	ExposureWeight    float64     `json:"exposure_weight"`
	ComplianceWeight  float64     `json:"compliance_weight"`
	OperationalWeight float64     `json:"operational_weight"`
	Bands             []Band      `json:"bands"`
	Model             ModelParams `json:"model_params"`
}

// ---- Inputs (gathered by the service from real per-tenant reads) ----

// ExposureInput is the vulnerability exposure signal (from vulnerability.ExposureSummary).
type ExposureInput struct {
	BySeverity    map[string]int
	ExploitedOpen int
	PastDue       int
}

// ComplianceInput is the compliance-coverage signal. Present=false when no framework is enabled → excluded.
type ComplianceInput struct {
	Present        bool
	AvgCoveragePct float64 // 0..100
}

// OperationalInput is the incident/SLA posture signal (from reporting.Summary.SLA).
type OperationalInput struct {
	OpenIncidents    int
	AckBreaching     int
	ResolveBreaching int
	ResolvedLate     int
}

// ---- Output ----

// Component is one scored dimension with the numbers behind it (so the UI can explain the score).
type Component struct {
	Key     string         `json:"key"`
	Label   string         `json:"label"`
	Risk    int            `json:"risk"`   // 0..100
	Weight  float64        `json:"weight"` // effective weight (as configured)
	Present bool           `json:"present"`
	Drivers map[string]int `json:"drivers"`
}

// Score is the composite result.
type Score struct {
	Composite  int         `json:"composite"` // 0..100, higher = worse
	Band       string      `json:"band"`
	Tone       string      `json:"tone"`
	Components []Component `json:"components"`
}

// DefaultConfig is the code fail-safe, identical to the migration 0121 column defaults. Used when a tenant has no
// config row (and as the base the repo layer decodes onto).
func DefaultConfig() Config {
	return Config{
		ExposureWeight:    0.40,
		ComplianceWeight:  0.30,
		OperationalWeight: 0.30,
		Bands: []Band{
			{Max: 20, Label: "Low", Tone: "ok"},
			{Max: 40, Label: "Guarded", Tone: "ok"},
			{Max: 60, Label: "Moderate", Tone: "warn"},
			{Max: 80, Label: "Elevated", Tone: "warn"},
			{Max: 100, Label: "High", Tone: "danger"},
		},
		Model: ModelParams{
			SevWeights:         map[string]float64{"critical": 10, "high": 6, "medium": 3, "low": 1},
			ExploitedPenalty:   8,
			OverduePenalty:     4,
			ExposureScale:      60,
			OpenIncidentWeight: 5,
			BreachWeight:       10,
			LateWeight:         3,
			OperationalScale:   40,
		},
	}
}

// Compute is the pure scoring function: deterministic in (config, inputs).
func Compute(cfg Config, ex ExposureInput, cp ComplianceInput, op OperationalInput) Score {
	// Exposure — saturating over severity-weighted open vulns + exploited/overdue penalties.
	exPoints := 0.0
	openVulns := 0
	for sev, n := range ex.BySeverity {
		exPoints += cfg.Model.SevWeights[strings.ToLower(sev)] * float64(n)
		openVulns += n
	}
	exPoints += cfg.Model.ExploitedPenalty*float64(ex.ExploitedOpen) + cfg.Model.OverduePenalty*float64(ex.PastDue)
	exposureRisk := saturate(exPoints, cfg.Model.ExposureScale)

	// Compliance — inverse of coverage; excluded when no framework is enabled.
	complianceRisk := 0.0
	if cp.Present {
		complianceRisk = clamp100(100 - cp.AvgCoveragePct)
	}

	// Operational — saturating over open incidents + SLA breaches.
	opPoints := cfg.Model.OpenIncidentWeight*float64(op.OpenIncidents) +
		cfg.Model.BreachWeight*float64(op.AckBreaching+op.ResolveBreaching) +
		cfg.Model.LateWeight*float64(op.ResolvedLate)
	operationalRisk := saturate(opPoints, cfg.Model.OperationalScale)

	comps := []Component{
		{Key: "exposure", Label: "Exposure", Risk: roundInt(exposureRisk), Weight: cfg.ExposureWeight, Present: true,
			Drivers: map[string]int{"open_vulnerabilities": openVulns, "exploited": ex.ExploitedOpen, "past_due": ex.PastDue}},
		{Key: "compliance", Label: "Compliance", Risk: roundInt(complianceRisk), Weight: cfg.ComplianceWeight, Present: cp.Present,
			Drivers: map[string]int{"coverage_pct": roundInt(cp.AvgCoveragePct)}},
		{Key: "operational", Label: "Operational", Risk: roundInt(operationalRisk), Weight: cfg.OperationalWeight, Present: true,
			Drivers: map[string]int{"open_incidents": op.OpenIncidents, "ack_breaching": op.AckBreaching, "resolve_breaching": op.ResolveBreaching, "resolved_late": op.ResolvedLate}},
	}

	// Composite = weighted mean over PRESENT components with positive weight (renormalize).
	var wsum, rsum float64
	for _, c := range comps {
		if !c.Present || c.Weight <= 0 {
			continue
		}
		wsum += c.Weight
		rsum += float64(c.Risk) * c.Weight
	}
	composite := 0
	if wsum > 0 {
		composite = roundInt(rsum / wsum)
	}
	band, tone := bandFor(cfg.Bands, composite)
	return Score{Composite: composite, Band: band, Tone: tone, Components: comps}
}

// saturate maps unbounded non-negative points to 0..100 with diminishing returns. At points==scale → ~63.
func saturate(points, scale float64) float64 {
	if points <= 0 {
		return 0
	}
	if scale <= 0 {
		return 100
	}
	return 100 * (1 - math.Exp(-points/scale))
}

func bandFor(bands []Band, composite int) (string, string) {
	sorted := append([]Band(nil), bands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Max < sorted[j].Max })
	for _, b := range sorted {
		if composite <= b.Max {
			return b.Label, b.Tone
		}
	}
	if len(sorted) > 0 {
		return sorted[len(sorted)-1].Label, sorted[len(sorted)-1].Tone
	}
	return "Unknown", "neutral"
}

func clamp100(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func roundInt(v float64) int { return int(math.Round(clamp100(v))) }
