package incident

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	sev "github.com/ArowuTest/nirvet/internal/platform/severity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Notifier sends incident notifications (implemented by notify.Service). Kept as
// a narrow interface so incident does not depend on the notify package.
type Notifier interface {
	NotifyIncident(ctx context.Context, tenantID uuid.UUID, subject, body string) error
}

// Enqueuer durably enqueues a notification INSIDE an existing tenant transaction, so it
// commits atomically with the state change that produced it (implemented by
// notify.OutboxRepository). Used by the SLA sweeper so a breach notification is never
// silently dropped on a transient delivery failure — the outbox dispatcher retries it
// (R3 §6.5). Kept narrow so incident does not depend on the notify package.
type Enqueuer interface {
	EnqueueTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, channel, recipient, subject, body string) error
}

// EscalationTarget is one resolved notification destination (channel + address).
type EscalationTarget struct {
	Channel string
	Address string
}

// EscalationResolver returns the tenant escalation-matrix contacts that fire at or above a
// severity, in escalation order (implemented by tenant.Service). Empty = no matrix configured
// → fall back to the log channel. Keeps incident decoupled from tenant governance internals.
type EscalationResolver interface {
	ResolveEscalation(ctx context.Context, tenantID uuid.UUID, severity string) ([]EscalationTarget, error)
	// ResolveEscalationFor is the #188 category-scoped router: an empty category broadcasts to all matching
	// contacts; a non-empty category routes to general + same-category contacts only.
	ResolveEscalationFor(ctx context.Context, tenantID uuid.UUID, severity, category string) ([]EscalationTarget, error)
}

// SLAResolver returns a tenant's admin-configured ack/resolve deadlines for a severity
// (implemented by tenant.Service, §6.8). A nil resolver, an error, or a non-positive duration
// means "not configured" → the service falls back to the built-in default policy (slaFor), so an
// incident always gets a valid, non-zero SLA. Keeps incident decoupled from tenant governance.
type SLAResolver interface {
	ResolveSLA(ctx context.Context, tenantID uuid.UUID, severity string) (ack, resolve time.Duration, err error)
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

// MaintenanceGate answers whether an active maintenance window is currently pausing SLA for a tenant
// (§6.18 #122 M-2). Implemented by platformadmin.MaintenanceService; optional (nil = no window ever pauses).
// The gate ALWAYS returns false for a critical severity, so a P1 breach can never be silenced by a window —
// the "critical breaks through" invariant lives in the service that implements this, not here.
type MaintenanceGate interface {
	PauseSLA(ctx context.Context, tenantID uuid.UUID, severity string) bool
}

// Service holds incident business logic. It depends on the alert service to
// promote alerts (one-way dependency: incident -> alert) and an optional notifier.
type Service struct {
	repo       *Repository
	alertSvc   *alert.Service
	notifier   Notifier
	enqueuer   Enqueuer
	escalation EscalationResolver
	sla        SLAResolver
	assignees  Assignees
	ticketer   Ticketer
	assets     AssetContext
	blobs      BlobPutter
	maint      MaintenanceGate
}

// NewService builds the service. notifier and assignees may be nil.
func NewService(repo *Repository, alertSvc *alert.Service, notifier Notifier) *Service {
	return &Service{repo: repo, alertSvc: alertSvc, notifier: notifier}
}

// WithAssignees wires the analyst resolver (used to validate incident assignment).
func (s *Service) WithAssignees(a Assignees) *Service { s.assignees = a; return s }

// WithEnqueuer wires the durable notification outbox used by the SLA sweeper (R3 §6.5).
func (s *Service) WithEnqueuer(e Enqueuer) *Service { s.enqueuer = e; return s }

// WithEscalation wires the tenant escalation-matrix resolver so breach notifications route to
// the configured on-call contacts by severity (§6.1 TEN-006 → §6.16 routing, Phase 0).
func (s *Service) WithEscalation(r EscalationResolver) *Service { s.escalation = r; return s }

// WithSLA wires the tenant's admin-configurable SLA policy resolver (§6.8, Phase 0-D). When
// unwired, due-times use the built-in default policy.
func (s *Service) WithSLA(r SLAResolver) *Service { s.sla = r; return s }

// WithMaintenance wires the platform maintenance gate (§6.18 #122 M-2). When wired, the SLA sweeper defers a
// non-critical breach whose tenant is inside an active pause-SLA window; a critical (P1) always breaks through.
// Unwired (nil) → no window ever pauses a breach (current behavior).
func (s *Service) WithMaintenance(g MaintenanceGate) *Service { s.maint = g; return s }

// resolveSLA returns the ack/resolve targets for a severity: the tenant's admin-configured SLA
// when wired and present, else the built-in default policy — so an incident always gets a valid,
// non-zero SLA even if the resolver is unwired, errors, or the tenant lacks a row (Phase 0-D).
func (s *Service) resolveSLA(ctx context.Context, tenantID uuid.UUID, severity string) slaTarget {
	if s.sla != nil {
		if ack, resolve, err := s.sla.ResolveSLA(ctx, tenantID, severity); err == nil && ack > 0 && resolve > 0 {
			return slaTarget{ack: ack, resolve: resolve}
		}
	}
	return slaFor(severity)
}

// resolveTargets returns the escalation-matrix destinations for a severity (best-effort — a
// resolver error or missing resolver yields no targets, and the caller falls back to log).
func (s *Service) resolveTargets(ctx context.Context, tenantID uuid.UUID, severity, category string) []EscalationTarget {
	if s.escalation == nil {
		return nil
	}
	t, err := s.escalation.ResolveEscalationFor(ctx, tenantID, severity, category)
	if err != nil {
		return nil
	}
	return t
}

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
		if crit, ref, ok := s.assets.TopCriticalityForRefs(ctx, p.TenantID, []string{a.TargetRef, a.ActorRef}); ok && sev.Rank(crit) > sev.Rank(severity) {
			escalationNote = fmt.Sprintf("Severity escalated %s→%s: affects %s-criticality asset %s", severity, crit, crit, ref)
			severity = crit
		}
	}
	// SLA: an analyst promoted and owns this case, so it is acknowledged now; the
	// ack/resolve deadlines follow the (possibly escalated) severity policy (§6.8).
	now := time.Now()
	ackDue, resolveDue := s.resolveSLA(ctx, p.TenantID, severity).dueTimes(now)
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

// ManualInput is an analyst-declared incident (CASE-001): a case opened directly rather than promoted from an
// alert or a correlation cluster — e.g. from a threat hunt, a customer report, or intel.
type ManualInput struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// CreateManual opens an analyst-declared incident. The declaring analyst owns it (so it is acknowledged now), and
// the ack/resolve deadlines follow the severity policy (§6.8). Notifies + mirrors to ITSM best-effort like a
// promoted case, so a manually-declared incident behaves identically downstream.
func (s *Service) CreateManual(ctx context.Context, p auth.Principal, in ManualInput) (*Incident, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return nil, httpx.ErrBadRequest("title is required")
	}
	if !sev.Valid(in.Severity) {
		return nil, httpx.ErrBadRequest("severity must be one of informational, low, medium, high, critical")
	}
	category := strings.TrimSpace(in.Category)
	if category == "" {
		category = "uncategorised"
	}
	now := time.Now()
	owner := p.UserID
	ackDue, resolveDue := s.resolveSLA(ctx, p.TenantID, in.Severity).dueTimes(now)
	inc := &Incident{
		ID:             uuid.New(),
		TenantID:       p.TenantID,
		Title:          title,
		Severity:       in.Severity,
		Category:       category,
		Stage:          StageTriage,
		OwnerID:        &owner,
		AcknowledgedAt: &now,
		AckDueAt:       &ackDue,
		ResolveDueAt:   &resolveDue,
	}
	seed := &TimelineEntry{ID: uuid.New(), Author: p.Email, Kind: "status", Note: "Incident manually declared by " + p.Email}
	if err := s.repo.CreateWithSeed(ctx, p.TenantID, inc, seed); err != nil {
		return nil, httpx.ErrInternal("could not create incident")
	}
	if s.notifier != nil {
		_ = s.notifier.NotifyIncident(ctx, p.TenantID,
			"Incident opened: "+inc.Title,
			"A "+inc.Severity+" incident was declared by an analyst.")
	}
	if s.ticketer != nil {
		if ref, url, terr := s.ticketer.MirrorIncident(ctx, p.TenantID, inc.Title, inc.Severity,
			"Nirvet incident manually declared."); terr == nil && ref != "" {
			_ = s.repo.AddNote(ctx, p.TenantID, &TimelineEntry{ID: uuid.New(), IncidentID: inc.ID, Author: "system", Kind: "action",
				Note: "Ticket created: " + ref + " " + url})
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
	ackDue, resolveDue := s.resolveSLA(ctx, tenantID, severity).dueTimes(time.Now())
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
		// §6.18 #122 M-2: if the tenant is inside an active pause-SLA maintenance window, DEFER this breach —
		// do not claim/alert it this tick (the deadline effectively pauses; the next sweep after the window closes
		// will alert it if still overdue). A CRITICAL (P1) always returns false from the gate, so it breaks through
		// immediately — a window can never silence a P1 breach.
		if s.maint != nil && s.maint.PauseSLA(ctx, b.TenantID, b.Severity) {
			continue
		}
		// Claim + record + enqueue ATOMICALLY: the conditional marker elects exactly one
		// winning sweeper per breach (R2 M-B dedupe), and the timeline entry + the durable
		// notification outbox row commit in the SAME tx as the claim. So the notification
		// can never be silently dropped on a transient notifier failure — the outbox
		// dispatcher delivers it with retry (R3 §6.5, delivery guarantee).
		subject := fmt.Sprintf("SLA breach (%s): %s", b.Kind, b.Title)
		body := fmt.Sprintf("Incident %s (%s severity) has breached its %s SLA deadline.", b.ID, b.Severity, b.Kind)
		entry := &TimelineEntry{
			ID: uuid.New(), IncidentID: b.ID, Author: "system", Kind: "status",
			Note: fmt.Sprintf("SLA %s deadline breached", b.Kind),
		}
		tenantID, kind, severity, category := b.TenantID, b.Kind, b.Severity, b.Category
		var onClaim func(ctx context.Context, tx pgx.Tx) error
		if s.enqueuer != nil {
			// Route to the tenant's escalation matrix: one durable outbox row per contact
			// whose min_severity <= the incident severity, in escalation order. When no matrix
			// is configured (or no resolver wired), fall back to a single log-channel row so a
			// breach is never silently unnotified.
			targets := s.resolveTargets(ctx, tenantID, severity, category)
			onClaim = func(ctx context.Context, tx pgx.Tx) error {
				if len(targets) == 0 {
					return s.enqueuer.EnqueueTx(ctx, tx, tenantID, "log", "", subject, body)
				}
				for _, t := range targets {
					if e := s.enqueuer.EnqueueTx(ctx, tx, tenantID, t.Channel, t.Address, subject, body); e != nil {
						return e
					}
				}
				return nil
			}
		}
		claimed, err := s.repo.ClaimBreachTx(ctx, tenantID, b.ID, kind, entry, onClaim)
		if err != nil {
			// A real error (not a lost claim) — log and move on; the marker rolls back with
			// the tx, so this breach is retried on the next sweep.
			s.logBreachError(b.ID, err)
			continue
		}
		if claimed {
			n++
		}
	}
	return n, nil
}

// logBreachError records a transient SLA-sweep failure for one breach without a logger
// dependency on the hot struct (the sweeper's StartSLASweeper already logs sweep-level
// failures; this keeps per-breach errors observable during a partial sweep).
func (s *Service) logBreachError(id uuid.UUID, err error) {
	slog.Warn("sla breach claim/enqueue failed for one incident", "incident", id, "err", err)
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
			safe.Do(log, "sla-breach-sweeper", func() {
				if n, err := s.SweepSLABreaches(ctx, time.Now(), limit); err != nil {
					log.Warn("sla breach sweep failed", "err", err)
				} else if n > 0 {
					log.Info("sla breach sweep alerted incidents", "count", n)
				}
			})
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

// GetByIDs returns incidents by id (batched, with SLA-breach status computed) — used by
// the entity graph to avoid an N+1 (R2 M-E).
func (s *Service) GetByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Incident, error) {
	incs, err := s.repo.GetByIDs(ctx, tenantID, ids)
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

// CustomerTimeline returns only the customer-visible timeline entries (CASE-004) — the seam a
// customer portal reads, so analyst-only notes never leak (filtered at query time).
func (s *Service) CustomerTimeline(ctx context.Context, tenantID, id uuid.UUID) ([]TimelineEntry, error) {
	return s.repo.ListCustomerTimeline(ctx, tenantID, id)
}

// AddNote appends an analyst note at the given visibility (internal|customer, CASE-004).
func (s *Service) AddNote(ctx context.Context, p auth.Principal, id uuid.UUID, note, visibility string) error {
	if note == "" {
		return httpx.ErrBadRequest("note is required")
	}
	if visibility == "" {
		visibility = VisibilityInternal
	}
	if visibility != VisibilityInternal && visibility != VisibilityCustomer {
		return httpx.ErrBadRequest("visibility must be internal or customer")
	}
	e := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "note", Visibility: visibility, Note: note}
	return s.repo.AddNote(ctx, p.TenantID, e)
}

// noteSuffix appends an optional free-text note to a transition message.
func noteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return " — " + note
}

// Transition moves an incident to a new stage, enforcing the CASE-002 state machine fail-closed.
// Closing is NOT done here (it requires closure criteria — use Close). Reopen (closed→investigating)
// and post_incident_review are valid transitions. Idempotent for a same-stage target.
func (s *Service) Transition(ctx context.Context, p auth.Principal, id uuid.UUID, to Stage, note string) (*Incident, error) {
	if !validStage(to) {
		return nil, httpx.ErrBadRequest("unknown stage")
	}
	if to == StageClosed {
		return nil, httpx.ErrBadRequest("closing requires closure criteria — use the close endpoint")
	}
	cur, err := s.repo.Get(ctx, p.TenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	if cur.Stage == to {
		return cur, nil // idempotent
	}
	// Round-4 residual (reopen BFLA): a transition FROM 'closed' (reopen → investigating, or → PIR)
	// reverses a senior-gated close and restarts SLA exposure, so it needs the SAME senior authority
	// as closing. The transition route is provider-gated (incl. analyst_t1); this closes the parity gap.
	if cur.Stage == StageClosed && !auth.IsSenior(p.Role) {
		return nil, httpx.ErrForbidden("reopening or reviewing a closed incident requires a senior role")
	}
	if !canTransition(cur.Stage, to) {
		return nil, httpx.ErrBadRequest(fmt.Sprintf("illegal stage transition %s -> %s", cur.Stage, to))
	}
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "status",
		Note: fmt.Sprintf("Stage %s → %s%s", cur.Stage, to, noteSuffix(note))}
	auditE := audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "incident.transition",
		Target: "incident:" + id.String(), Metadata: map[string]any{"from": cur.Stage, "to": to}}
	applied, err := s.repo.Transition(ctx, p.TenantID, id, cur.Stage, to, nil, entry, auditE)
	if err != nil {
		return nil, httpx.ErrInternal("could not transition incident")
	}
	if !applied {
		return nil, httpx.ErrConflict("incident stage changed concurrently; retry")
	}
	cur.Stage = to
	return cur, nil
}

// Close closes an incident, enforcing the CASE-009 closure criteria (disposition + root cause +
// impact + actions taken). Any active stage may close (a false positive closes early). Idempotent.
func (s *Service) Close(ctx context.Context, p auth.Principal, id uuid.UUID, in ClosureInput) (*Incident, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	cur, err := s.repo.Get(ctx, p.TenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	if cur.Stage == StageClosed {
		return cur, nil // idempotent
	}
	if !canTransition(cur.Stage, StageClosed) {
		return nil, httpx.ErrBadRequest(fmt.Sprintf("cannot close from stage %s", cur.Stage))
	}
	entry := &TimelineEntry{ID: uuid.New(), IncidentID: id, Author: p.Email, Kind: "status",
		Note: fmt.Sprintf("Closed (%s): %s", in.Disposition, in.RootCause)}
	auditE := audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "incident.close",
		Target: "incident:" + id.String(), Metadata: map[string]any{"disposition": in.Disposition, "customer_ack": in.CustomerAck}}
	applied, err := s.repo.Transition(ctx, p.TenantID, id, cur.Stage, StageClosed, &in, entry, auditE)
	if err != nil {
		return nil, httpx.ErrInternal("could not close incident")
	}
	if !applied {
		return nil, httpx.ErrConflict("incident changed concurrently; retry")
	}
	cur.Stage = StageClosed
	cur.Disposition, cur.RootCause, cur.Impact = string(in.Disposition), in.RootCause, in.Impact
	cur.ActionsTaken, cur.LessonsLearned, cur.CustomerAck = in.ActionsTaken, in.LessonsLearned, in.CustomerAck
	return cur, nil
}
