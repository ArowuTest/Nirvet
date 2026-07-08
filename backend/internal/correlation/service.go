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

// Service clusters alerts and scores risk.
type Service struct {
	repo       *Repository
	incidenter Incidenter
}

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// WithIncidenter wires auto-promotion of high-risk clusters to incidents.
func (s *Service) WithIncidenter(i Incidenter) *Service { s.incidenter = i; return s }

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
	since := time.Now().Add(-Window)
	c, err := s.repo.UpdateActive(ctx, tenantID, entity, since, func(c *Correlation) {
		c.AlertCount++
		c.MaxSeverity = worseSeverity(c.MaxSeverity, severity)
		c.Techniques = mergeTechniques(c.Techniques, mitre)
		c.RiskScore = RiskScore(c.MaxSeverity, c.AlertCount, len(c.Techniques), confidence)
	})
	if err != nil {
		return uuid.Nil, individual, err
	}
	if c == nil {
		c = &Correlation{
			ID: uuid.New(), TenantID: tenantID, Entity: entity, Status: StatusOpen,
			AlertCount: 1, MaxSeverity: severity, Techniques: mergeTechniques(nil, mitre),
			RiskScore: RiskScore(severity, 1, len(mitre), confidence),
		}
		if err := s.repo.Create(ctx, c); err != nil {
			return uuid.Nil, individual, err
		}
	}
	s.maybePromote(ctx, tenantID, entity, c)
	return c.ID, individual, nil
}

// maybePromote opens an incident once a cluster's aggregate risk crosses the promote
// threshold — exactly once. It CLAIMS the cluster atomically (open->promoted) before
// creating the incident, so under the multi-process topology two workers can never both
// open an incident, and a cluster is never re-promoted (R2 H-C). Best-effort: a promotion
// failure never breaks correlation; on incident-open failure the cluster stays 'promoted'
// with no incident (it will not re-promote or spam) rather than looping forever.
func (s *Service) maybePromote(ctx context.Context, tenantID uuid.UUID, entity string, c *Correlation) {
	if s.incidenter == nil || c.RiskScore < PromoteThreshold {
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
