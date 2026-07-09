package threatintel

// §6.10 slice B: per-tenant threat-intel tuning + the pure decay/corroboration scoring the enricher
// applies to STIX matches. Config-first (threat_intel_settings, lazy default); the math is a pure
// function of stored data so it is deterministic and unit-testable.

import (
	"math"
	"time"
)

// TISettings are the per-tenant threat-intel tuning knobs. Defaults mirror the DB column defaults so a
// tenant with no row still gets sane behaviour.
type TISettings struct {
	DecayHalfLifeDays      int `json:"decay_half_life_days"`     // confidence halves every N days of age
	MinEffectiveConfidence int `json:"min_effective_confidence"` // a STIX match below this (after decay) stops firing
	SightingBoostCap       int `json:"sighting_boost_cap"`       // max corroboration boost from sightings
}

// DefaultTISettings is returned when a tenant has no threat_intel_settings row.
func DefaultTISettings() TISettings {
	return TISettings{DecayHalfLifeDays: 30, MinEffectiveConfidence: 0, SightingBoostCap: 20}
}

// ageDays returns the age of an observable in days: from valid_from when set, else created. Never
// negative (a future valid_from reads as age 0 — full confidence until it becomes current, which the
// SQL valid_from filter already gates).
func ageDays(validFrom *time.Time, created, now time.Time) float64 {
	from := created
	if validFrom != nil {
		from = *validFrom
	}
	d := now.Sub(from).Hours() / 24
	if d < 0 {
		return 0
	}
	return d
}

// effectiveConfidence applies exponential decay to a STIX match's base confidence over its age, then adds
// the bounded sightings corroboration boost, clamped to [0,100]. Decay: base * 0.5^(age/halfLife). Boost
// is applied AFTER decay (a well-corroborated but old IOC recovers some confidence). A non-positive
// half-life disables decay (defensive; the schema CHECK forbids it).
func effectiveConfidence(base int, ageDays float64, sightings int, set TISettings) int {
	c := float64(base)
	if set.DecayHalfLifeDays > 0 {
		c = c * math.Pow(0.5, ageDays/float64(set.DecayHalfLifeDays))
	}
	boost := sightings
	if boost > set.SightingBoostCap {
		boost = set.SightingBoostCap
	}
	if boost < 0 {
		boost = 0
	}
	v := int(math.Round(c)) + boost
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return v
}
