package incident

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

// Ticketer mirrors an incident into the tenant's ITSM (ServiceNow/Jira) and
// returns the external ticket ref. Implemented by ticketing.Service; kept narrow
// so incident does not depend on the ticketing package. Returns empty ref when the
// tenant has no ITSM configured.
type Ticketer interface {
	MirrorIncident(ctx context.Context, tenantID uuid.UUID, title, severity, body string) (ref, url string, err error)
}

// AssetContext resolves the highest business criticality among a set of entity refs,
// so an incident affecting a critical asset can be escalated (SRS §6.8/§6.15).
// Implemented by asset.Service; optional (nil = no escalation).
type AssetContext interface {
	TopCriticalityForRefs(ctx context.Context, tenantID uuid.UUID, refs []string) (criticality, ref string, found bool)
}

// severityRank orders the severity/criticality scale for escalation comparisons.
var severityRank = map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Service holds incident business logic. It depends on the alert service to
// promote alerts (one-way dependency: incident -> alert) and an optional notifier.
type Service struct {
	repo      *Repository
	alertSvc  *alert.Service
	notifier  Notifier
	assignees Assignees
	ticketer  Ticketer
	assets    AssetContext
}

// NewService builds the service. notifier and assignees may be nil.
func NewService(repo *Repository, alertSvc *alert.Service, notifier Notifier) *Service {
	return &Service{repo: repo, alertSvc: alertSvc, notifier: notifier}
}

// WithAssignees wires the analyst resolver (used to validate incident assignment).
func (s *Service) WithAssignees(a Assignees) *Service { s.assignees = a; return s }

// WithTicketer wires outbound ITSM mirroring (best-effort on incident open).
func (s *Service) WithTicketer(t Ticketer) *Service { s.ticketer = t; return s }

// WithAssetContext wires asset-criticality escalation (best-effort on incident open).
func (s *Service) WithAssetContext(a AssetContext) *Service { s.assets = a; return s }

// CreateFromAlert promotes an alert into a new incident (atomic write).
func (s *Service) CreateFromAlert(ctx context.Context, p auth.Principal, alertID uuid.UUID) (*Incident, error) {
	a, err := s.alertSvc.Get(ctx, p.TenantID, alertID)
	if err != nil {
		return nil, err
	}
	owner := p.UserID
	// Asset-criticality escalation (§6.8/§6.15): if this alert affects a more critical
	// asset than its own severity, raise the incident's severity (never lower). This
	// also tightens the SLA, since due-times are computed from the escalated severity.
	severity := a.Severity
	var escalationNote string
	if s.assets != nil {
		if crit, ref, ok := s.assets.TopCriticalityForRefs(ctx, p.TenantID, []string{a.TargetRef, a.ActorRef}); ok && severityRank[crit] > severityRank[severity] {
			escalationNote = fmt.Sprintf("Severity escalated %s→%s: affects %s-criticality asset %s", severity, crit, crit, ref)
			severity = crit
		}
	}
	// SLA: an analyst promoted and owns this case, so it is acknowledged now; the
	// ack/resolve deadlines follow the (possibly escalated) severity policy (§6.8).
	now := time.Now()
	ackDue, resolveDue := slaFor(severity).dueTimes(now)
	inc := &Incident{
		ID:             uuid.New(),
		TenantID:       p.TenantID,
		Title:          a.Title,
		Severity:       severity,
		Category:       "uncategorised",
		Stage:          StageTriage,
		OwnerID:        &owner,
		AcknowledgedAt: &now,
		AckDueAt:       &ackDue,
		ResolveDueAt:   &resolveDue,
	}
	seed := &TimelineEntry{ID: uuid.New(), Author: p.Email, Kind: "status", Note: "Promoted from alert " + alertID.String()}
	promote := func(ctx context.Context, tx pgx.Tx, incidentID uuid.UUID) error {
		return s.alertSvc.Repo().MarkPromoted(ctx, tx, alertID, incidentID)
	}
	if err := s.repo.CreateFromAlertTx(ctx, p.TenantID, inc, seed, promote); err != nil {
		return nil, httpx.ErrInternal("could not promote alert")
	}
	// Record the asset-driven escalation on the timeline (best-effort).
	if escalationNote != "" {
		_ = s.repo.AddNote(ctx, p.TenantID, &TimelineEntry{
			ID: uuid.New(), IncidentID: inc.ID, Author: "system", Kind: "status", Note: escalationNote,
		})
	}
	// Customer notification (draft; external delivery gated by approval). Closes
	// the end-to-end flow: alert -> incident -> notification.
	if s.notifier != nil {
		_ = s.notifier.NotifyIncident(ctx, p.TenantID,
			"Incident opened: "+inc.Title,
			"A "+inc.Severity+" incident was opened from alert "+alertID.String()+".")
	}
	// Mirror to the tenant's ITSM (ServiceNow/Jira), best-effort: a ticketing
	// outage must never fail incident creation. Record the external ref on the
	// timeline so analysts can cross-reference the customer's system of record.
	if s.ticketer != nil {
		if ref, url, terr := s.ticketer.MirrorIncident(ctx, p.TenantID, inc.Title, inc.Severity,
			"Nirvet incident opened from alert "+alertID.String()+"."); terr == nil && ref != "" {
			entry := &TimelineEntry{ID: uuid.New(), IncidentID: inc.ID, Author: "system", Kind: "action",
				Note: "Ticket created: " + ref + " " + url}
			_ = s.repo.AddNote(ctx, p.TenantID, entry)
		}
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

// OpenFromCorrelation opens a system-initiated incident for a high-risk
// correlation cluster (§6.7 auto-promotion). Unassigned (an analyst picks it up),
// severity carried from the cluster, and the customer is notified (best-effort).
// Satisfies correlation.Incidenter.
func (s *Service) OpenFromCorrelation(ctx context.Context, tenantID uuid.UUID, entity, severity string, risk int, techniques []string) (uuid.UUID, error) {
	// SLA: system-opened and unassigned (no acknowledgement yet); ack/resolve
	// deadlines follow the severity policy so a neglected auto-incident will breach.
	ackDue, resolveDue := slaFor(severity).dueTimes(time.Now())
	inc := &Incident{
		ID: uuid.New(), TenantID: tenantID,
		Title: "Correlated activity on " + entity, Severity: severity,
		Category: "correlation", Stage: StageTriage,
		AckDueAt: &ackDue, ResolveDueAt: &resolveDue,
	}
	seed := &TimelineEntry{
		ID: uuid.New(), Author: "system", Kind: "status",
		Note: fmt.Sprintf("Auto-opened from correlation (risk %d; techniques %s)", risk, strings.Join(techniques, ", ")),
	}
	if err := s.repo.CreateWithSeed(ctx, tenantID, inc, seed); err != nil {
		return uuid.Nil, httpx.ErrInternal("could not open incident from correlation")
	}
	if s.notifier != nil {
		_ = s.notifier.NotifyIncident(ctx, tenantID,
			"Incident opened: "+inc.Title,
			fmt.Sprintf("A %s incident was auto-opened from a correlated cluster (risk %d) on %s.", severity, risk, entity))
	}
	return inc.ID, nil
}

// SweepSLABreaches finds open incidents that have breached their ack or resolve SLA
// deadline and have not yet been alerted, notifies the customer (best-effort) and
// records the breach on the incident timeline, then marks it notified so it fires
// exactly once per breach kind. Runs at the system level (spans tenants); the marker
// makes it safe to run on every tick and in multiple processes. Returns the number of
// breaches alerted.
func (s *Service) SweepSLABreaches(ctx context.Context, now time.Time, limit int) (int, error) {
	breaches, err := s.repo.FindSLABreaches(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range breaches {
		subject := fmt.Sprintf("SLA breach (%s): %s", b.Kind, b.Title)
		body := fmt.Sprintf("Incident %s (%s severity) has breached its %s SLA deadline.", b.ID, b.Severity, b.Kind)
		if s.notifier != nil {
			_ = s.notifier.NotifyIncident(ctx, b.TenantID, subject, body)
		}
		entry := &TimelineEntry{
			ID: uuid.New(), IncidentID: b.ID, Author: "system", Kind: "status",
			Note: fmt.Sprintf("SLA %s deadline breached", b.Kind),
		}
		_ = s.repo.AddNote(ctx, b.TenantID, entry)
		// Mark last: if this fails, the next sweep simply retries (at-least-once alert).
		if err := s.repo.MarkBreachNotified(ctx, b.TenantID, b.ID, b.Kind); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

// StartSLASweeper runs SweepSLABreaches on a ticker until ctx is cancelled.
func (s *Service) StartSLASweeper(ctx context.Context, log *slog.Logger, interval time.Duration, limit int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.SweepSLABreaches(ctx, time.Now(), limit); err != nil {
				log.Warn("sla breach sweep failed", "err", err)
			} else if n > 0 {
				log.Info("sla breach sweep alerted incidents", "count", n)
			}
		}
	}
}

// List returns incidents with their SLA-breach status computed as of now.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	incs, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for idx := range incs {
		computeBreach(&incs[idx], now)
	}
	return incs, nil
}

// AtRisk returns open incidents breaching or near-breaching their SLA, urgency-ordered,
// with breach flags computed as of now (§6.8 at-risk queue).
func (s *Service) AtRisk(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	incs, err := s.repo.ListAtRisk(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for idx := range incs {
		computeBreach(&incs[idx], now)
	}
	return incs, nil
}

// Get returns one incident with its SLA-breach status computed as of now.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Incident, error) {
	i, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	computeBreach(i, time.Now())
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
