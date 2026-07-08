package correlation

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service clusters alerts and scores risk.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

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
	existing, err := s.repo.FindOpen(ctx, tenantID, entity, time.Now().Add(-Window))
	if err != nil {
		return uuid.Nil, individual, err
	}
	if existing != nil {
		existing.AlertCount++
		existing.MaxSeverity = worseSeverity(existing.MaxSeverity, severity)
		existing.Techniques = mergeTechniques(existing.Techniques, mitre)
		existing.RiskScore = RiskScore(existing.MaxSeverity, existing.AlertCount, len(existing.Techniques), confidence)
		if err := s.repo.Update(ctx, existing); err != nil {
			return uuid.Nil, individual, err
		}
		return existing.ID, individual, nil
	}
	c := &Correlation{
		ID: uuid.New(), TenantID: tenantID, Entity: entity, Status: StatusOpen,
		AlertCount: 1, MaxSeverity: severity, Techniques: mergeTechniques(nil, mitre),
		RiskScore: RiskScore(severity, 1, len(mitre), confidence),
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return uuid.Nil, individual, err
	}
	return c.ID, individual, nil
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
