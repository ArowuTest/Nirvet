package correlation

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Incidenter opens an incident for a high-risk correlation cluster. Implemented by
// incident.Service; a narrow interface so correlation does not depend on incident.
type Incidenter interface {
	OpenFromCorrelation(ctx context.Context, tenantID uuid.UUID, entity, severity string, risk int, techniques []string) (uuid.UUID, error)
}

// PolicyResolver returns a tenant's admin-configurable clustering window and auto-promotion
// thresholds (§6.7, implemented by tenant.Service). A nil resolver or an error falls back to the
// built-in defaults (Window/PromoteThreshold/MinAlertsForPromotion), so clustering always has a
// non-zero window. Narrow interface so correlation does not depend on tenant governance.
type PolicyResolver interface {
	ResolveCorrelationPolicy(ctx context.Context, tenantID uuid.UUID) (window time.Duration, promoteThreshold, minAlerts int, err error)
}

// Service clusters alerts and scores risk.
type Service struct {
	repo       *Repository
	incidenter Incidenter
	policy     PolicyResolver
}

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// WithIncidenter wires auto-promotion of high-risk clusters to incidents.
func (s *Service) WithIncidenter(i Incidenter) *Service { s.incidenter = i; return s }

// WithPolicy wires the tenant's admin-configurable correlation window/thresholds (§6.7 Phase 0-D).
// When unwired, the built-in default constants are used.
func (s *Service) WithPolicy(r PolicyResolver) *Service { s.policy = r; return s }

// resolvePolicy returns the effective window + promotion thresholds for a tenant, falling back to
// the built-in defaults when no resolver is wired, it errors, or a value is non-positive.
func (s *Service) resolvePolicy(ctx context.Context, tenantID uuid.UUID) (window time.Duration, promoteThreshold, minAlerts int) {
	window, promoteThreshold, minAlerts = Window, PromoteThreshold, MinAlertsForPromotion
	if s.policy == nil {
		return
	}
	w, th, mn, err := s.policy.ResolveCorrelationPolicy(ctx, tenantID)
	if err != nil {
		return
	}
	if w > 0 {
		window = w
	}
	if th > 0 {
		promoteThreshold = th
	}
	if mn > 0 {
		minAlerts = mn
	}
	return
}

// Correlate places an alert's signals into a correlation cluster for its entity
// (creating one if none is open in the window), recomputes the cluster's aggregate
// risk, and returns the cluster id plus the alert's own individual risk. When the
// alert has no entity to correlate on, it returns (uuid.Nil, individualRisk).
//
// Concurrency: the update to an existing cluster is atomic (UpdateActive locks the row
// FOR UPDATE, so concurrent alerts can't lose an alert_count/risk update — R2 M-C). The
// find-or-CREATE step still has a benign race (two clusters for one entity under heavy
// parallel first-touch); both are valid clusters, resolved by the entity index.
func (s *Service) Correlate(ctx context.Context, tenantID uuid.UUID, entity, severity string, mitre []string, confidence int) (uuid.UUID, int, error) {
	individual := RiskScore(severity, 1, len(mitre), confidence)
	if entity == "" {
		return uuid.Nil, individual, nil
	}
	window, promoteThreshold, minAlerts := s.resolvePolicy(ctx, tenantID)
	since := time.Now().Add(-window)
	c, err := s.repo.UpdateActive(ctx, tenantID, entity, since, func(c *Correlation) {
		c.AlertCount++
		c.MaxSeverity = worseSeverity(c.MaxSeverity, severity)
		c.Techniques = mergeTechniques(c.Techniques, mitre)
		if confidence > c.MaxConfidence {
			c.MaxConfidence = confidence
		}
		c.RiskScore = RiskScore(c.MaxSeverity, c.AlertCount, len(c.Techniques), c.MaxConfidence)
	})
	if err != nil {
		return uuid.Nil, individual, err
	}
	if c == nil {
		c = &Correlation{
			ID: uuid.New(), TenantID: tenantID, Entity: entity, Status: StatusOpen,
			AlertCount: 1, MaxSeverity: severity, Techniques: mergeTechniques(nil, mitre),
			MaxConfidence: confidence,
			RiskScore:     RiskScore(severity, 1, len(mitre), confidence),
		}
		if err := s.repo.Create(ctx, c); err != nil {
			return uuid.Nil, individual, err
		}
	}
	s.maybePromote(ctx, tenantID, entity, c, promoteThreshold, minAlerts)
	return c.ID, individual, nil
}

// maybePromote opens an incident once a cluster's aggregate risk crosses the promote
// threshold — exactly once. It CLAIMS the cluster atomically (open->promoted) before
// creating the incident, so under the multi-process topology two workers can never both
// open an incident, and a cluster is never re-promoted (R2 H-C). Best-effort: a promotion
// failure never breaks correlation; on incident-open failure the cluster stays 'promoted'
// with no incident (it will not re-promote or spam) rather than looping forever.
func (s *Service) maybePromote(ctx context.Context, tenantID uuid.UUID, entity string, c *Correlation, promoteThreshold, minAlerts int) {
	// Corroboration + threshold: an incident is auto-opened only when the cluster is both
	// high-risk AND seen by >= minAlerts alerts (R2 M-A anti-spam). Both are the tenant's
	// admin-configured values (§6.7 Phase 0-D), defaulting to the built-in constants.
	if s.incidenter == nil || c.RiskScore < promoteThreshold || c.AlertCount < minAlerts {
		return
	}
	// The in-memory status may be stale; the DB WHERE status='open' is authoritative.
	claimed, err := s.repo.ClaimForPromotion(ctx, tenantID, c.ID)
	if err != nil || !claimed {
		return
	}
	incID, err := s.incidenter.OpenFromCorrelation(ctx, tenantID, entity, c.MaxSeverity, c.RiskScore, c.Techniques)
	if err != nil {
		return
	}
	_ = s.repo.SetIncident(ctx, tenantID, c.ID, incID)
	c.IncidentID = &incID
	c.Status = StatusPromoted
}

// List returns a tenant's correlations (highest risk first).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, status string) ([]Correlation, error) {
	return s.repo.List(ctx, tenantID, status)
}

// ListByEntity returns all correlation clusters for an entity ref (entity graph §6.9).
func (s *Service) ListByEntity(ctx context.Context, tenantID uuid.UUID, entity string) ([]Correlation, error) {
	return s.repo.ListByEntity(ctx, tenantID, entity)
}

// Get returns one correlation.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Correlation, error) {
	c, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("correlation not found")
	}
	return c, nil
}

// Explain returns the risk-factor breakdown for a cluster (COR-006).
func (s *Service) Explain(ctx context.Context, tenantID, id uuid.UUID) (*Correlation, []Factor, error) {
	c, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, nil, httpx.ErrNotFound("correlation not found")
	}
	return c, Explain(c.MaxSeverity, c.AlertCount, len(c.Techniques), c.MaxConfidence), nil
}

// OverrideInput is an analyst severity/risk override with a mandatory reason (COR-009).
type OverrideInput struct {
	Severity string `json:"severity"` // "" leaves severity unoverridden
	Risk     *int   `json:"risk"`     // nil leaves risk unoverridden
	Reason   string `json:"reason"`
}

// Override records an analyst's adjustment of a cluster's severity/risk with a reason (COR-009). At
// least one of severity/risk must be provided; the reason is mandatory (audited via mutation middleware).
func (s *Service) Override(ctx context.Context, tenantID, id uuid.UUID, by uuid.UUID, in OverrideInput) error {
	if in.Reason == "" {
		return httpx.ErrBadRequest("an override reason is required")
	}
	if in.Severity == "" && in.Risk == nil {
		return httpx.ErrBadRequest("provide a severity and/or risk to override")
	}
	var sev *string
	if in.Severity != "" {
		if !validSeverity(in.Severity) {
			return httpx.ErrBadRequest("invalid severity")
		}
		sev = &in.Severity
	}
	if in.Risk != nil && (*in.Risk < 0 || *in.Risk > 100) {
		return httpx.ErrBadRequest("risk must be 0-100")
	}
	applied, err := s.repo.Override(ctx, tenantID, id, sev, in.Risk, in.Reason, by)
	if err != nil {
		return httpx.ErrInternal("could not apply override")
	}
	if !applied {
		return httpx.ErrNotFound("correlation not found")
	}
	return nil
}

func validSeverity(s string) bool {
	switch s {
	case "informational", "low", "medium", "high", "critical":
		return true
	}
	return false
}
