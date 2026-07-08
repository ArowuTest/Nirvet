package alert

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service holds alert business logic.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// Spec is the detection-supplied definition of an alert to raise.
type Spec struct {
	Title       string
	Severity    string
	Confidence  int
	DedupeKey   string // typically event_id:rule_id — enforces one alert per (event, rule)
	DetectionID *uuid.UUID
	MITRE       []string
}

// CreateFromEvent raises an alert from a normalized event + detection spec.
// Idempotent on the spec's dedupe key; returns whether a new alert was created.
func (s *Service) CreateFromEvent(ctx context.Context, ev eventstore.NormalizedEvent, spec Spec) (*Alert, bool, error) {
	eid := ev.ID
	a := &Alert{
		ID:          uuid.New(),
		TenantID:    ev.TenantID,
		EventID:     &eid,
		DetectionID: spec.DetectionID,
		DedupeKey:   spec.DedupeKey,
		Title:       spec.Title,
		Severity:    spec.Severity,
		Confidence:  spec.Confidence,
		Source:      ev.Source,
		Status:      StatusNew,
		ActorRef:    ev.ActorRef,
		TargetRef:   ev.TargetRef,
		MITRE:       spec.MITRE,
	}
	inserted, err := s.repo.Create(ctx, a)
	if err != nil {
		return nil, false, err
	}
	return a, inserted, nil
}

// List returns alerts for a tenant.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, status string) ([]Alert, error) {
	return s.repo.List(ctx, tenantID, status, 0)
}

// Get returns one alert.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Alert, error) {
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("alert not found")
	}
	return a, nil
}

// Assign assigns an alert to an analyst.
func (s *Service) Assign(ctx context.Context, tenantID, id, assignee uuid.UUID) error {
	if err := s.repo.Assign(ctx, tenantID, id, assignee); err != nil {
		return httpx.ErrNotFound("alert not assignable")
	}
	return nil
}

// Repo exposes the repository for cross-module transactional promotion (incident).
func (s *Service) Repo() *Repository { return s.repo }

// SetCorrelation links an alert to its correlation cluster and stores its risk (§6.7).
func (s *Service) SetCorrelation(ctx context.Context, tenantID, id uuid.UUID, correlationID *uuid.UUID, risk int) error {
	return s.repo.SetCorrelation(ctx, tenantID, id, correlationID, risk)
}
