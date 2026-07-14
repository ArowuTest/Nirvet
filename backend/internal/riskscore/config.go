package riskscore

import "github.com/ArowuTest/nirvet/internal/platform/httpx"

// Validate rejects a configuration that would produce a divide-by-zero, an un-normalizable composite, or a
// mislabelled band. A bad config is a 400 — never silently applied (it would corrupt every score for the tenant).
func (c Config) Validate() error {
	if c.ExposureWeight < 0 || c.ComplianceWeight < 0 || c.OperationalWeight < 0 {
		return httpx.ErrBadRequest("component weights must be non-negative")
	}
	if c.ExposureWeight+c.ComplianceWeight+c.OperationalWeight <= 0 {
		return httpx.ErrBadRequest("at least one component weight must be positive")
	}
	if len(c.Bands) == 0 {
		return httpx.ErrBadRequest("at least one risk band is required")
	}
	validTone := map[string]bool{"ok": true, "warn": true, "danger": true, "neutral": true}
	prevMax := -1
	maxSeen := 0
	for _, b := range c.Bands {
		if b.Label == "" {
			return httpx.ErrBadRequest("every band needs a label")
		}
		if !validTone[b.Tone] {
			return httpx.ErrBadRequest("band tone must be one of ok/warn/danger/neutral")
		}
		if b.Max <= prevMax {
			return httpx.ErrBadRequest("band max values must be strictly ascending")
		}
		prevMax = b.Max
		if b.Max > maxSeen {
			maxSeen = b.Max
		}
	}
	if maxSeen < 100 {
		return httpx.ErrBadRequest("the top band must cover up to 100")
	}
	if c.Model.ExposureScale <= 0 || c.Model.OperationalScale <= 0 {
		return httpx.ErrBadRequest("model saturation scales must be positive")
	}
	for _, w := range c.Model.SevWeights {
		if w < 0 {
			return httpx.ErrBadRequest("severity weights must be non-negative")
		}
	}
	if c.Model.ExploitedPenalty < 0 || c.Model.OverduePenalty < 0 ||
		c.Model.OpenIncidentWeight < 0 || c.Model.BreachWeight < 0 || c.Model.LateWeight < 0 {
		return httpx.ErrBadRequest("model penalties/weights must be non-negative")
	}
	return nil
}
