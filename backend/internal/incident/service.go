package incident

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Notifier sends incident notifications (implemented by notify.Service). Kept as
// a narrow interface so incident does not depend on the notify package.
type Notifier interface {
	NotifyIncident(ctx context.Context, tenantID uuid.UUID, subject, body string) error
}

// Assignees resolves a candidate analyst within a tenant, returning their email.
// It keeps incident decoupled from the iam package (implemented by iam.Service).
// A membership miss (user in another tenant / not found) returns an error so an
// incident can never be assigned outside its tenant.
type Assignees interface {
	LookupInTenant(ctx context.Context, tenantID, userID uuid.UUID) (email string, err error)
}

// Service holds incident business logic. It depends on the alert service to
// promote alerts (one-way dependency: incident -> alert) and an optional notifier.
type Service struct {
	repo      *Repository
	alertSvc  *alert.Service
	notifier  Notifier
	assignees Assignees
}

// NewService builds the service. notifier and assignees may be nil.
func NewService(repo *Repository, alertSvc *alert.Service, notifier Notifier) *Service {
	return &Service{repo: repo, alertSvc: alertSvc, notifier: notifier}
}

// WithAssignees wires the analyst resolver (used to validate incident assignment).
func (s *Service) WithAssignees(a Assignees) *Service { s.assignees = a; return s }

// CreateFromAlert promotes an alert into a new incident (atomic write).
func (s *Service) CreateFromAlert(ctx context.Context, p auth.Principal, alertID uuid.UUID) (*Incident, error) {
	a, err := s.alertSvc.Get(ctx, p.TenantID, alertID)
	if err != nil {
		return nil, err
	}
	owner := p.UserID
	inc := &Incident{
		ID:       uuid.New(),
		TenantID: p.TenantID,
		Title:    a.Title,
		Severity: a.Severity,
		Category: "uncategorised",
		Stage:    StageTriage,
		OwnerID:  &owner,
	}
	seed := &TimelineEntry{ID: uuid.New(), Author: p.Email, Kind: "status", Note: "Promoted from alert " + alertID.String()}
	promote := func(ctx context.Context, tx pgx.Tx, incidentID uuid.UUID) error {
		return s.alertSvc.Repo().MarkPromoted(ctx, tx, alertID, incidentID)
	}
	if err := s.repo.CreateFromAlertTx(ctx, p.TenantID, inc, seed, promote); err != nil {
		return nil, httpx.ErrInternal("could not promote alert")
	}
	// Customer notification (draft; external delivery gated by approval). Closes
	// the end-to-end flow: alert -> incident -> notification.
	if s.notifier != nil {
		_ = s.notifier.NotifyIncident(ctx, p.TenantID,
			"Incident opened: "+inc.Title,
			"A "+inc.Severity+" incident was opened from alert "+alertID.String()+".")
	}
	return inc, nil
}

// Assign hands an incident to an analyst, moving it into 'investigating' and
// recording the handoff on the timeline. The assignee must belong to the same
// tenant (verified via the Assignees resolver when wired) so a case can never be
// owned across tenant boundaries.
func (s *Service) Assign(ctx context.Context, p auth.Principal, id, assigneeID uuid.UUID) error {
	if assigneeID == uuid.Nil {
		return httpx.ErrBadRequest("assignee is required")
	}
	assigneeLabel := assigneeID.String()
	if s.assignees != nil {
		email, err := s.assignees.LookupInTenant(ctx, p.TenantID, assigneeID)
		if err != nil {
			return httpx.ErrBadRequest("assignee is not a user in this tenant")
		}
		assigneeLabel = email
	}
	e := &TimelineEntry{
		ID:         uuid.New(),
		IncidentID: id,
		Author:     p.Email,
		Kind:       "status",
		Note:       "Assigned to " + assigneeLabel,
	}
	if err := s.repo.Assign(ctx, p.TenantID, id, assigneeID, e); err != nil {
		return httpx.ErrNotFound("incident not assignable")
	}
	return nil
}

// List returns incidents.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	return s.repo.List(ctx, tenantID)
}

// Get returns one incident.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Incident, error) {
	i, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	return i, nil
}

// Timeline returns an incident's timeline.
func (s *Service) Timeline(ctx context.Context, tenantID, id uuid.UUID) ([]TimelineEntry, error) {
	return s.repo.ListTimeline(ctx, tenantID, id)
}

// AddNote appends an analyst note.
func (s *Service) AddNote(ctx context.Context, p auth.Principal, id uuid.UUID, note string) error {
	if note == "" {
		return httpx.ErrBadRequest("note is required")
	}
	e := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "note", Note: note}
	return s.repo.AddNote(ctx, p.TenantID, e)
}

// Close closes an incident with a closure note.
func (s *Service) Close(ctx context.Context, p auth.Principal, id uuid.UUID, note string) error {
	e := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "status", Note: "Closed: " + note}
	if err := s.repo.Close(ctx, p.TenantID, id, e); err != nil {
		return httpx.ErrNotFound("incident not closable")
	}
	return nil
}
