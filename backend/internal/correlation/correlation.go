// Package correlation clusters related alerts and scores their risk (SRS §6.7).
// Alerts that share an entity (a host/user/ip) within a time window are grouped
// into one correlation with an aggregate risk score, so analysts triage a single
// prioritised cluster instead of N independent alerts (alert-fatigue reduction).
package correlation

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/severity"
	"github.com/google/uuid"
)

// Status of a correlation cluster.
type Status string

const (
	StatusOpen     Status = "open"
	StatusPromoted Status = "promoted"
	StatusClosed   Status = "closed"
)

// Window is how long a cluster stays "open" to absorb related alerts.
const Window = 6 * time.Hour

// PromoteThreshold is the aggregate risk at/above which a cluster warrants an
// incident (the SOC's "this is worth a human" line).
const PromoteThreshold = 70

// MinAlertsForPromotion requires corroboration before auto-opening an incident: a
// single event — however high its risk — must not spawn a case (R2 M-A). It takes at
// least two alerts on the same entity within the window, so one crafted "critical"
// event in customer telemetry cannot flood incidents/emails. A human can still promote
// a single alert manually.
const MinAlertsForPromotion = 2

// Correlation is a cluster of related alerts on one entity.
type Correlation struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Entity      string     `json:"entity"`
	Status      Status     `json:"status"`
	AlertCount  int        `json:"alert_count"`
	MaxSeverity string     `json:"max_severity"`
	RiskScore   int        `json:"risk_score"`
	Techniques  []string   `json:"techniques"`
	IncidentID  *uuid.UUID `json:"incident_id,omitempty"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	CreatedAt   time.Time  `json:"created_at"`
}

// severityWeight is the base risk contribution of the worst severity in a cluster.
func severityWeight(s string) int {
	switch s {
	case "critical":
		return 60
	case "high":
		return 40
	case "medium":
		return 25
	case "low":
		return 10
	default:
		return 5
	}
}

// RiskScore computes a 0-100 risk from a cluster's signals: worst severity is the
// base; alert volume, breadth of distinct ATT&CK techniques, and confidence each
// add. Deterministic and monotonic (more/worse signal never lowers the score).
func RiskScore(maxSeverity string, alertCount, distinctTechniques, maxConfidence int) int {
	score := severityWeight(maxSeverity)
	score += clamp(alertCount, 0, 5) * 4         // up to +20 for volume
	score += clamp(distinctTechniques, 0, 5) * 4 // up to +20 for kill-chain breadth
	score += clamp(maxConfidence, 0, 100) / 10   // up to +10 for confidence
	return clamp(score, 0, 100)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// mergeTechniques returns the union of two technique lists (order-stable, deduped).
func mergeTechniques(existing, add []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(add))
	for _, t := range existing {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, t := range add {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// worseSeverity returns the more severe of two (canonical §10.2 ordering).
func worseSeverity(a, b string) string { return severity.Worse(a, b) }
