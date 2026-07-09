package alert

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// FeedbackSink receives an analyst's alert disposition so the detection module can attribute it to
// the firing rule (DET-007). Kept narrow so alert does not depend on the detection package (mirrors
// ingestion.Correlator / iam.Alerter). Implemented by detection.Service.
type FeedbackSink interface {
	RecordDetectionFeedback(ctx context.Context, tenantID, ruleID, alertID uuid.UUID, disposition, reason string, by uuid.UUID) error
}

// Service holds alert business logic.
type Service struct {
	repo     *Repository
	feedback FeedbackSink // optional (nil = no detection feedback wired)
}

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// WithFeedbackSink wires the detection FP-feedback loop (DET-007).
func (s *Service) WithFeedbackSink(f FeedbackSink) *Service { s.feedback = f; return s }

// validDispositions are the verdicts an analyst may record when closing an alert (DET-007).
var validDispositions = map[string]bool{
	"true_positive": true, "false_positive": true, "benign": true, "duplicate": true,
}

// Disposition closes an alert with an analyst verdict and, when the alert came from a detection rule,
// feeds that verdict back to detection tuning (DET-007). The alert close is the authoritative action;
// feedback is best-effort so a feedback failure never blocks dispositioning the alert.
func (s *Service) Disposition(ctx context.Context, tenantID, id uuid.UUID, disposition, reason string, by uuid.UUID) error {
	if !validDispositions[disposition] {
		return httpx.ErrBadRequest("invalid disposition: must be true_positive|false_positive|benign|duplicate")
	}
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return httpx.ErrNotFound("alert not found")
	}
	if err := s.repo.Close(ctx, tenantID, id); err != nil {
		return httpx.ErrBadRequest("alert cannot be dispositioned (already promoted or closed)")
	}
	if s.feedback != nil && a.DetectionID != nil {
		// Attribute the verdict to the firing rule. Best-effort: the alert is already closed.
		_ = s.feedback.RecordDetectionFeedback(ctx, tenantID, *a.DetectionID, id, disposition, reason, by)
	}
	return nil
}

// Spec is the detection-supplied definition of an alert to raise.
type Spec struct {
	Title       string
	Severity    string
	Confidence  int
	DedupeKey   string // typically event_id:rule_id — enforces one alert per (event, rule)
	DetectionID *uuid.UUID
	MITRE       []string
}

// RaisePlatform raises a PLATFORM-generated alert (no source detection event) into the triage queue — e.g. a
// SOAR containment the vendor reported failed/stalled (reconciler D-3). Idempotent on dedupeKey; returns
// whether a new alert was created (false = already raised, so callers avoid duplicate downstream side effects).
func (s *Service) RaisePlatform(ctx context.Context, tenantID uuid.UUID, dedupeKey, title, severity, targetRef, source string) (bool, error) {
	a := &Alert{
		ID: uuid.New(), TenantID: tenantID, DedupeKey: dedupeKey,
		Title: title, Severity: severity, Source: source, Status: StatusNew, TargetRef: targetRef,
	}
	return s.repo.Create(ctx, a)
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

// ListByIncident returns the alerts promoted into an incident (for evidence packs).
func (s *Service) ListByIncident(ctx context.Context, tenantID, incidentID uuid.UUID) ([]Alert, error) {
	return s.repo.ListByIncident(ctx, tenantID, incidentID)
}

// ListByRef returns alerts touching an entity ref (actor or target) — entity graph.
func (s *Service) ListByRef(ctx context.Context, tenantID uuid.UUID, ref string) ([]Alert, error) {
	return s.repo.ListByRef(ctx, tenantID, ref)
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
