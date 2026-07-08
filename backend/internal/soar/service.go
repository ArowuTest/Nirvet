package soar

import (
	"context"
	"fmt"
	"time"

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
}

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// WithAuthorizer wires the per-action authority store (tenant.Service). When set, SOAR resolves
// authority per action from authority_policies; when nil it falls back to the legacy
// tenants.authority_mode column (kept only so unit tests without a tenant service still run).
func (s *Service) WithAuthorizer(a Authorizer) *Service { s.authz = a; return s }

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
	needsApproval := false
	for _, st := range pb.Steps {
		// Authority is resolved PER ACTION (SOAR-003): a tenant may pre-authorise
		// isolate_endpoint while still requiring approval for disable_user, etc.
		mode, err := s.resolveMode(ctx, p.TenantID, st.Action)
		if err != nil {
			return nil, httpx.ErrInternal("could not read authority-to-act")
		}
		sr := StepResult{Name: st.Name, ConnectorKey: st.ConnectorKey, Action: st.Action, Risk: st.Risk}
		if !st.RequiresApproval && Allowed(mode, st.Risk) {
			sr.Status = "simulated"
			sr.Note = fmt.Sprintf("auto-run under authority '%s' (simulated: would invoke %s.%s)", mode, st.ConnectorKey, st.Action)
		} else {
			sr.Status = "awaiting_approval"
			sr.Note = fmt.Sprintf("requires approval (risk %s, authority '%s')", st.Risk, mode)
			needsApproval = true
		}
		run.Steps = append(run.Steps, sr)
	}
	if needsApproval {
		run.Status = RunPendingApproval
	} else {
		run.Status = RunCompleted
		now := time.Now()
		run.CompletedAt = &now
	}
	if err := s.repo.CreateRun(ctx, run); err != nil {
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
	for i := range run.Steps {
		if run.Steps[i].Status == "awaiting_approval" {
			run.Steps[i].Status = "simulated"
			run.Steps[i].Note = fmt.Sprintf("executed after approval by %s (simulated: would invoke %s.%s)",
				p.Email, run.Steps[i].ConnectorKey, run.Steps[i].Action)
		}
	}
	run.ApprovedBy = &p.UserID
	run.Status = RunCompleted
	now := time.Now()
	run.CompletedAt = &now
	if err := s.repo.UpdateRun(ctx, run); err != nil {
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
		if run.Steps[i].Status == "awaiting_approval" {
			run.Steps[i].Status = "skipped"
			run.Steps[i].Note = "rejected by " + p.Email
		}
	}
	run.ApprovedBy = &p.UserID
	run.Status = RunRejected
	now := time.Now()
	run.CompletedAt = &now
	if err := s.repo.UpdateRun(ctx, run); err != nil {
		return nil, httpx.ErrInternal("could not reject run")
	}
	return run, nil
}
