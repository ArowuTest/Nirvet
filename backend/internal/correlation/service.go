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
// Concurrency note: find-or-create has a small race under heavy parallel ingest
// (two clusters for the same entity); it is benign (both are valid clusters) and
// the shared entity index keeps lookups cheap. A future SELECT ... FOR UPDATE on a
// per-entity lock row would make it strictly single-cluster.
func (s *Service) Correlate(ctx context.Context, tenantID uuid.UUID, entity, severity string, mitre []string, confidence int) (uuid.UUID, int, error) {
	individual := RiskScore(severity, 1, len(mitre), confidence)
	if entity == "" {
		return uuid.Nil, individual, nil
	}
	existing, err := s.repo.FindActive(ctx, tenantID, entity, time.Now().Add(-Window))
	if err != nil {
		return uuid.Nil, individual, err
	}
	var c *Correlation
	if existing != nil {
		existing.AlertCount++
		existing.MaxSeverity = worseSeverity(existing.MaxSeverity, severity)
		existing.Techniques = mergeTechniques(existing.Techniques, mitre)
		existing.RiskScore = RiskScore(existing.MaxSeverity, existing.AlertCount, len(existing.Techniques), confidence)
		if err := s.repo.Update(ctx, existing); err != nil {
			return uuid.Nil, individual, err
		}
		c = existing
	} else {
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

// maybePromote opens an incident for a cluster once its aggregate risk crosses the
// promote threshold (once — an already-promoted cluster is skipped). Best-effort:
// a promotion failure never breaks correlation, and the cluster still holds its risk.
func (s *Service) maybePromote(ctx context.Context, tenantID uuid.UUID, entity string, c *Correlation) {
	if s.incidenter == nil || c.Status != StatusOpen || c.IncidentID != nil || c.RiskScore < PromoteThreshold {
		return
	}
	incID, err := s.incidenter.OpenFromCorrelation(ctx, tenantID, entity, c.MaxSeverity, c.RiskScore, c.Techniques)
	if err != nil {
		return
	}
	c.IncidentID = &incID
	c.Status = StatusPromoted
	_ = s.repo.Update(ctx, c)
}

// List returns a tenant's correlations (highest risk first).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, status string) ([]Correlation, error) {
	return s.repo.List(ctx, tenantID, status)
}

// Get returns one correlation.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Correlation, error) {
	c, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("correlation not found")
	}
	return c, nil
}
