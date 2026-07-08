package soar

import (
	"context"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service orchestrates playbook runs under authority-to-act with approval gates.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

var validModes = map[AuthorityMode]bool{
	AuthorityObserve: true, AuthorityApproval: true, AuthorityPreAuth: true, AuthorityEmergency: true,
}

// SetAuthority updates the caller's tenant authority-to-act mode.
func (s *Service) SetAuthority(ctx context.Context, tenantID uuid.UUID, mode AuthorityMode) error {
	if !validModes[mode] {
		return httpx.ErrBadRequest("invalid authority mode")
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
	mode, err := s.repo.TenantAuthority(ctx, p.TenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not read authority-to-act")
	}
	run := &PlaybookRun{
		ID: uuid.New(), TenantID: p.TenantID, PlaybookID: pb.ID,
		IncidentID: incidentID, RequestedBy: &p.UserID,
	}
	needsApproval := false
	for _, st := range pb.Steps {
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
