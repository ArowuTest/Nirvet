package soar

import (
	"context"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Authorizer resolves the tenant's per-action authority-to-act mode and sets the tenant-wide
// catch-all. Implemented by tenant.Service (single source of truth: authority_policies). SOAR
// consumes this instead of the legacy tenants.authority_mode column (Phase 0 reconciliation).
type Authorizer interface {
	ResolveAuthorityMode(ctx context.Context, tenantID uuid.UUID, actionType string) (string, error)
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

// WithAuthorizer wires the per-action authority store (tenant.Service). When set, SOAR resolves
// authority per action from authority_policies; when nil it falls back to the legacy
// tenants.authority_mode column (kept only so unit tests without a tenant service still run).
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

// resolveMode returns the authority mode for an action type, preferring the per-action policy
// store and falling back to the legacy tenant-wide column.
func (s *Service) resolveMode(ctx context.Context, tenantID uuid.UUID, actionType string) (AuthorityMode, error) {
	if s.authz != nil {
		m, err := s.authz.ResolveAuthorityMode(ctx, tenantID, actionType)
		return AuthorityMode(m), err
	}
	return s.repo.TenantAuthority(ctx, tenantID)
}

// SetAuthority sets the tenant-wide catch-all authority-to-act mode (POST /soar/authority is a
// convenience over the per-action policy API; it upserts the '*' policy).
func (s *Service) SetAuthority(ctx context.Context, p auth.Principal, tenantID uuid.UUID, mode AuthorityMode) error {
	if !validModes[mode] {
		return httpx.ErrBadRequest("invalid authority mode")
	}
	if s.authz != nil {
		if err := s.authz.SetCatchAllAuthority(ctx, p, tenantID, string(mode)); err != nil {
			return httpx.ErrInternal("could not set authority")
		}
		return nil
	}
	if err := s.repo.SetTenantAuthority(ctx, tenantID, mode); err != nil {
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

// Run starts a playbook against an incident. Low-risk steps permitted by the
// tenant authority mode auto-execute (simulated); anything requiring approval
// leaves the run pending_approval.
func (s *Service) Run(ctx context.Context, p auth.Principal, playbookID uuid.UUID, incidentID *uuid.UUID) (*PlaybookRun, error) {
	pb, err := s.repo.GetPlaybook(ctx, p.TenantID, playbookID)
	if err != nil {
		return nil, httpx.ErrNotFound("playbook not found")
	}
	run := &PlaybookRun{
		ID: uuid.New(), TenantID: p.TenantID, PlaybookID: pb.ID,
		IncidentID: incidentID, RequestedBy: &p.UserID,
	}
	needsApproval, anyFailed := false, false
	for _, st := range pb.Steps {
		// Risk class comes from the admin-configurable action catalog (§9.5), NOT the step JSON —
		// an action absent from the catalog fails closed to business_critical (max approval).
		act, _ := s.repo.resolveAction(ctx, p.TenantID, st.Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = st.ConnectorKey
		}
		// Authority is resolved PER ACTION (SOAR-003): a tenant may pre-authorise isolate_endpoint
		// while still requiring approval for disable_user, etc.
		mode, err := s.resolveMode(ctx, p.TenantID, st.Action)
		if err != nil {
			return nil, httpx.ErrInternal("could not read authority-to-act")
		}
		sr := StepResult{Name: st.Name, ConnectorKey: act.ConnectorKey, Action: st.Action, Risk: act.RiskClass}
		if !st.RequiresApproval && Allowed(mode, act.RiskClass) {
			// Permitted → dispatch for real (or truthful simulation when no live executor).
			sr.Status, sr.Note = s.execs.dispatch(ctx, p.TenantID, act, stepParams(incidentID, pb.Name, st.Name))
			if sr.Status == StatusFailed {
				anyFailed = true
			}
		} else {
			sr.Status = StatusAwaitingApproval
			sr.Note = fmt.Sprintf("requires approval (class %s, authority '%s')", act.RiskClass, mode)
			needsApproval = true
		}
		run.Steps = append(run.Steps, sr)
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
	entry := audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_start",
		Target: "playbook:" + pb.ID.String(), Metadata: map[string]any{"status": run.Status, "steps": len(run.Steps)}}
	if err := s.repo.CreateRun(ctx, run, entry); err != nil {
		return nil, httpx.ErrInternal("could not start run")
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

// Approve executes the awaiting steps of a pending run (simulated) and completes it.
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
	anyFailed := false
	for i := range run.Steps {
		if run.Steps[i].Status != StatusAwaitingApproval {
			continue
		}
		// Dispatch the now-approved step for real (or truthful simulation).
		act, _ := s.repo.resolveAction(ctx, p.TenantID, run.Steps[i].Action)
		if act.ConnectorKey == "" {
			act.ConnectorKey = run.Steps[i].ConnectorKey
		}
		status, note := s.execs.dispatch(ctx, p.TenantID, act, stepParams(run.IncidentID, "", run.Steps[i].Name))
		run.Steps[i].Status = status
		run.Steps[i].Note = note + " (approved by " + p.Email + ")"
		if status == StatusFailed {
			anyFailed = true
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
	entry := audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_approve",
		Target: "run:" + run.ID.String(), Metadata: map[string]any{"status": run.Status}}
	if err := s.repo.UpdateRun(ctx, run, entry); err != nil {
		return nil, httpx.ErrInternal("could not approve run")
	}
	return run, nil
}

// Reject rejects a pending run without executing further.
func (s *Service) Reject(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, p.TenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
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
	entry := audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.run_reject",
		Target: "run:" + run.ID.String()}
	if err := s.repo.UpdateRun(ctx, run, entry); err != nil {
		return nil, httpx.ErrInternal("could not reject run")
	}
	return run, nil
}
