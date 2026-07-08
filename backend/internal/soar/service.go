package soar

import (
	"context"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Authorizer resolves the tenant's per-action authority-to-act policy and sets the tenant-wide
// catch-all. Implemented by tenant.Service (single source of truth: authority_policies). SOAR
// consumes this instead of the legacy tenants.authority_mode column (Phase 0 reconciliation).
// ResolveAuthorityDecision returns the FULL policy (mode + approver_role floor + business_hours_only)
// so SOAR can actually enforce the stored controls (Round-4 H2 — they were written but unconsumed).
type Authorizer interface {
	ResolveAuthorityMode(ctx context.Context, tenantID uuid.UUID, actionType string) (string, error)
	ResolveAuthorityDecision(ctx context.Context, tenantID uuid.UUID, actionType string) (mode, approverRole string, businessHoursOnly bool, err error)
	SetCatchAllAuthority(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, mode string) error
}

// Service orchestrates playbook runs under authority-to-act with approval gates.
type Service struct {
	repo  *Repository
	authz Authorizer
	execs *Executors
}

// NewService builds the service. The executor registry starts empty (every action simulates); real
// executors are registered via WithExecutors at wiring time.
func NewService(repo *Repository) *Service { return &Service{repo: repo, execs: NewExecutors()} }

// WithAuthorizer wires the per-action authority store (tenant.Service, the single source of truth:
// authority_policies). Always wired in production; a nil authorizer resolves fail-closed to 'observe'
// (nothing auto-runs). The legacy tenants.authority_mode column was dropped (Round-4 hygiene).
func (s *Service) WithAuthorizer(a Authorizer) *Service { s.authz = a; return s }

// WithExecutors wires the action-executor registry (real dispatch for registered actions; unregistered
// actions simulate). Passing nil resets to an empty registry rather than nil-panicking on dispatch.
func (s *Service) WithExecutors(e *Executors) *Service {
	if e == nil {
		e = NewExecutors()
	}
	s.execs = e
	return s
}

// stepParams builds the parameter map handed to an executor for a step.
func stepParams(incidentID *uuid.UUID, playbook, step string) map[string]any {
	m := map[string]any{"playbook": playbook, "step": step}
	if incidentID != nil {
		m["incident_id"] = incidentID.String()
	}
	return m
}

var validModes = map[AuthorityMode]bool{
	AuthorityObserve: true, AuthorityApproval: true, AuthorityPreAuth: true, AuthorityEmergency: true,
}

// resolveDecision returns the effective authority mode + approver-role floor + business-hours-only
// flag for an action (per-action SOAR-003 granularity). Falls back to the legacy tenant-wide mode
// (no floor) when no authorizer is wired (unit tests).
func (s *Service) resolveDecision(ctx context.Context, tenantID uuid.UUID, actionType string) (mode AuthorityMode, approverRole string, businessHours bool, err error) {
	if s.authz != nil {
		m, ar, bh, e := s.authz.ResolveAuthorityDecision(ctx, tenantID, actionType)
		return AuthorityMode(m), ar, bh, e
	}
	return AuthorityObserve, "", false, nil // fail-closed: no authorizer wired ⇒ nothing auto-runs
}

// requiredApproverRank is the minimum approver seniority (auth.RoleRank) to clear a step of the given
// §9.5 risk class: the HIGHER of a risk-scaled default (medium→analyst_t3, high→soc_manager) and the
// tenant-configured approver_role floor (H2 — the stored control is now enforced). business_critical
// is handled separately (never cleared by standard approval in this slice). Uses the canonical role
// rank in auth so this floor and the break-glass tier-cap share one ordering.
func requiredApproverRank(risk RiskClass, configuredApproverRole string) int {
	base := 0
	switch risk {
	case RiskMedium:
		base = auth.RoleRank(auth.RoleAnalystT3)
	case RiskHigh:
		base = auth.RoleRank(auth.RoleSOCManager)
	}
	if configuredApproverRole != "" {
		if r := auth.RoleRank(auth.Role(configuredApproverRole)); r > base {
			base = r
		}
	}
	return base
}

// SetAuthority sets the tenant-wide catch-all authority-to-act mode (POST /soar/authority is a
// convenience over the per-action policy API; it upserts the '*' policy).
func (s *Service) SetAuthority(ctx context.Context, p auth.Principal, tenantID uuid.UUID, mode AuthorityMode) error {
	if !validModes[mode] {
		return httpx.ErrBadRequest("invalid authority mode")
	}
	if s.authz == nil {
		return httpx.ErrInternal("authority store not configured")
	}
	if err := s.authz.SetCatchAllAuthority(ctx, p, tenantID, string(mode)); err != nil {
		return httpx.ErrInternal("could not set authority")
	}
	return nil
}

// ListPlaybooks returns available playbooks.
func (s *Service) ListPlaybooks(ctx context.Context, tenantID uuid.UUID) ([]Playbook, error) {
	return s.repo.ListPlaybooks(ctx, tenantID)
}

// ListRuns returns recent runs.
func (s *Service) ListRuns(ctx context.Context, tenantID uuid.UUID) ([]PlaybookRun, error) {
	return s.repo.ListRuns(ctx, tenantID)
}

// GetRun returns a run.
func (s *Service) GetRun(ctx context.Context, tenantID, id uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	return run, nil
}

// stepPlan is a resolved step decided in Run's read phase (no side effects yet).
type stepPlan struct {
	act  ActionCatalog
	auto bool // may auto-execute now (permitted by authority, no approval, in-hours)
	sr   StepResult
}

// Run starts a playbook against an incident. It resolves each step's §9.5 risk class + authority in
// a read phase, then dispatches permitted steps and persists the run + audit in ONE transaction
// (Round-4 M2: effect + audit atomic), deduped per (playbook, incident) (M3). Steps needing approval
// leave the run pending_approval.
func (s *Service) Run(ctx context.Context, p auth.Principal, playbookID uuid.UUID, incidentID *uuid.UUID) (*PlaybookRun, error) {
	pb, err := s.repo.GetPlaybook(ctx, p.TenantID, playbookID)
	if err != nil {
		return nil, httpx.ErrNotFound("playbook not found")
	}

	// Phase 1 — reads only, no side effects: resolve catalog + authority per step and decide auto-run.
	plans := make([]stepPlan, 0, len(pb.Steps))
	for _, st := range pb.Steps {
		// Risk class comes from the admin-configurable action catalog (§9.5), NOT the step JSON — an
		// action absent from the catalog fails closed to business_critical (max approval).
		act, _ := s.repo.resolveAction(ctx, p.TenantID, st.Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = st.ConnectorKey
		}
		mode, _, businessHours, derr := s.resolveDecision(ctx, p.TenantID, st.Action)
		if derr != nil {
			return nil, httpx.ErrInternal("could not read authority-to-act")
		}
		// business_hours_only fails closed to approval: we cannot yet verify the tenant's business-hours
		// calendar, so an hours-restricted action never auto-runs (Round-4 H2 — consume the stored flag).
		autoEligible := !st.RequiresApproval && Allowed(mode, act.RiskClass)
		sr := StepResult{Name: st.Name, ConnectorKey: act.ConnectorKey, Action: st.Action, Risk: act.RiskClass}
		if !autoEligible {
			sr.Status = StatusAwaitingApproval
			sr.Note = fmt.Sprintf("requires approval (class %s, authority '%s')", act.RiskClass, mode)
		} else if businessHours {
			sr.Status = StatusAwaitingApproval
			sr.Note = fmt.Sprintf("business-hours-only: deferred to approval (class %s, authority '%s')", act.RiskClass, mode)
		}
		plans = append(plans, stepPlan{act: act, auto: autoEligible && !businessHours, sr: sr})
	}

	// Phase 2 — one tx: idempotency check, dispatch permitted steps, persist run + audit atomically.
	run := &PlaybookRun{ID: uuid.New(), TenantID: p.TenantID, PlaybookID: pb.ID, IncidentID: incidentID, RequestedBy: &p.UserID}
	var existing *PlaybookRun
	err = s.repo.RunTx(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Round-4 R-1 (concurrent fully-auto): serialise concurrent Runs for the same (playbook,
		// incident) with a tx-scoped advisory lock, so the idempotency check below can't be raced by a
		// second run whose terminal-status insert the 0038 partial index doesn't cover. Released at tx end.
		if incidentID != nil {
			if e := s.repo.lockRunKeyTx(ctx, tx, pb.ID, *incidentID); e != nil {
				return e
			}
		}
		if ex, e := s.repo.activeRunForTx(ctx, tx, p.TenantID, pb.ID, incidentID); e != nil {
			return e
		} else if ex != nil {
			existing = ex // M3: a retried run returns the existing active run, no re-dispatch
			return nil
		}
		needsApproval, anyFailed := false, false
		for i := range plans {
			pl := &plans[i]
			if pl.auto {
				pl.sr.Status, pl.sr.Note = s.execs.dispatch(ctx, tx, p.TenantID, pl.act, stepParams(incidentID, pb.Name, pl.sr.Name))
				if pl.sr.Status == StatusFailed {
					anyFailed = true
				}
				if e := audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.action_execute",
					Target: "action:" + pl.sr.Action, Metadata: map[string]any{"status": pl.sr.Status, "risk": pl.sr.Risk}}); e != nil {
					return e
				}
			} else {
				needsApproval = true
			}
			run.Steps = append(run.Steps, pl.sr)
		}
		switch {
		case needsApproval:
			run.Status = RunPendingApproval
		case anyFailed:
			run.Status = RunFailed
			now := time.Now()
			run.CompletedAt = &now
		default:
			run.Status = RunCompleted
			now := time.Now()
			run.CompletedAt = &now
		}
		if e := s.repo.insertRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_start",
			Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"status": run.Status, "steps": len(run.Steps)}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not start run")
	}
	if existing != nil {
		return existing, nil
	}
	return run, nil
}

// canApprove enforces separation of duties: the user who requested a run may not
// approve it. A run with no recorded requester (system/correlation-initiated) may
// be approved by any authorised approver. This is a pure guard so it can be unit
// tested without a database (SRS §6.11; four-eyes on authority-to-act).
func canApprove(run *PlaybookRun, approver uuid.UUID) error {
	if run.RequestedBy != nil && *run.RequestedBy == approver {
		return httpx.ErrForbidden("separation of duties: the requester of a playbook run may not approve it")
	}
	return nil
}

// approvedStep is a pending step cleared for dispatch in Approve's authorization phase.
type approvedStep struct {
	idx   int
	act   ActionCatalog
	block bool // business_critical — never executed by standard approval (§9.5)
}

// Approve executes the awaiting steps of a pending run. It RE-RESOLVES risk + authority per step and
// enforces the approver-role floor scaled to §9.5 risk class + the tenant-configured approver_role
// (Round-4 H2 — previously ignored, one approval green-lit every pending step). business_critical
// steps are never cleared here (they need incident-commander + customer authorization not modelled in
// this slice) — they are recorded skipped, fail-closed. Dispatch + audit run in one tx (M2).
func (s *Service) Approve(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, p.TenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
	// Four-eyes: an approver cannot rubber-stamp their own requested action.
	if err := canApprove(run, p.UserID); err != nil {
		return nil, err
	}

	// Authorization phase (no side effects): re-resolve each pending step and check the approver floor
	// BEFORE executing any step, so a too-junior approver is rejected without partial execution.
	var steps []approvedStep
	for i := range run.Steps {
		if run.Steps[i].Status != StatusAwaitingApproval {
			continue
		}
		act, _ := s.repo.resolveAction(ctx, p.TenantID, run.Steps[i].Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = run.Steps[i].ConnectorKey
		}
		if act.RiskClass == RiskBusinessCritical {
			steps = append(steps, approvedStep{idx: i, act: act, block: true})
			continue
		}
		_, approverRole, _, derr := s.resolveDecision(ctx, p.TenantID, run.Steps[i].Action)
		if derr != nil {
			return nil, httpx.ErrInternal("could not read authority-to-act")
		}
		if auth.RoleRank(p.Role) < requiredApproverRank(act.RiskClass, approverRole) {
			return nil, httpx.ErrForbidden(fmt.Sprintf("approver role '%s' is insufficient to approve a %s-risk action", p.Role, act.RiskClass))
		}
		steps = append(steps, approvedStep{idx: i, act: act})
	}

	// Execution phase (one tx): CLAIM the run (pending_approval→running) before dispatching, so two
	// concurrent approves can't both execute (Round-4 R-2 claim-then-act — the row lock serialises
	// them and the loser sees status≠pending_approval). Then dispatch, persist, audit.
	claimed := false
	err = s.repo.RunTx(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ok, e := s.repo.claimPendingTx(ctx, tx, run.ID)
		if e != nil {
			return e
		}
		if !ok {
			return nil // another approver claimed it first — nothing dispatched
		}
		claimed = true
		anyFailed := false
		for _, st := range steps {
			if st.block {
				run.Steps[st.idx].Status = StatusSkipped
				run.Steps[st.idx].Note = "business_critical requires incident-commander + customer authorization (not available in this flow)"
				continue
			}
			status, note := s.execs.dispatch(ctx, tx, p.TenantID, st.act, stepParams(run.IncidentID, "", run.Steps[st.idx].Name))
			run.Steps[st.idx].Status = status
			run.Steps[st.idx].Note = note + " (approved by " + p.Email + ")"
			if status == StatusFailed {
				anyFailed = true
			}
			if e := audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.action_execute",
				Target: "action:" + run.Steps[st.idx].Action, Metadata: map[string]any{"status": status, "risk": st.act.RiskClass, "approved": true}}); e != nil {
				return e
			}
		}
		run.ApprovedBy = &p.UserID
		if anyFailed {
			run.Status = RunFailed
		} else {
			run.Status = RunCompleted
		}
		now := time.Now()
		run.CompletedAt = &now
		if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_approve",
			Target: "run:" + run.ID.String(), Metadata: map[string]any{"status": run.Status}})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not approve run")
	}
	if !claimed {
		return nil, httpx.ErrConflict("run is no longer pending approval (already decided)")
	}
	return run, nil
}

// Reject rejects a pending run without executing further. Like Approve it CLAIMS the run in-tx
// (Round-4 residual: a concurrent Approve+Reject on one run must be serialised — the loser gets 409,
// so a run can't be both approved and rejected).
func (s *Service) Reject(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, p.TenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
	claimed := false
	err = s.repo.RunTx(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ok, e := s.repo.claimPendingTx(ctx, tx, run.ID)
		if e != nil {
			return e
		}
		if !ok {
			return nil // a concurrent Approve/Reject claimed it first
		}
		claimed = true
		for i := range run.Steps {
			if run.Steps[i].Status == StatusAwaitingApproval {
				run.Steps[i].Status = StatusSkipped
				run.Steps[i].Note = "rejected by " + p.Email
			}
		}
		run.ApprovedBy = &p.UserID
		run.Status = RunRejected
		now := time.Now()
		run.CompletedAt = &now
		if e := s.repo.updateRunTx(ctx, tx, run); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_reject",
			Target: "run:" + run.ID.String()})
	})
	if err != nil {
		return nil, httpx.ErrInternal("could not reject run")
	}
	if !claimed {
		return nil, httpx.ErrConflict("run is no longer pending approval (already decided)")
	}
	return run, nil
}
