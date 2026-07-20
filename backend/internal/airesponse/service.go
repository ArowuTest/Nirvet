// Package airesponse is the human-promotion boundary between an AI response PROPOSAL (a data record in internal/ai)
// and a real SOAR RUN. It lives OUTSIDE internal/ai on purpose: it imports internal/soar to reach the EXISTING run
// pipeline, which internal/ai must never do (check-ai-no-direct-execution.sh). The AI proposes; a HUMAN here promotes;
// the run then flows through every authority gate (Allowed(mode,risk) + four-eyes + D5 + authority_policies). The AI
// is strictly upstream and removes no gate (S2b gate non-negotiable #1).
package airesponse

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/ai"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/soar"
)

// Proposals is the read/transition surface of the AI proposal store (satisfied by *ai.Service).
type Proposals interface {
	GetProposal(ctx context.Context, p auth.Principal, id uuid.UUID) (*ai.Proposal, error)
	MarkProposalAccepted(ctx context.Context, p auth.Principal, id, runID uuid.UUID) error
}

// Runner is the EXISTING soar run entry plus a read to validate the enacting playbook (satisfied by *soar.Service).
// Run is the SAME entry a human uses to run a playbook — it applies every authority gate; this package adds none and
// bypasses none.
type Runner interface {
	GetPlaybook(ctx context.Context, tenantID, id uuid.UUID) (*soar.Playbook, error)
	Run(ctx context.Context, p auth.Principal, playbookID uuid.UUID, incidentID *uuid.UUID) (*soar.PlaybookRun, error)
}

// Service promotes accepted proposals into runs.
type Service struct {
	proposals Proposals
	runner    Runner
}

// NewService builds the accept usecase.
func NewService(p Proposals, r Runner) *Service { return &Service{proposals: p, runner: r} }

// AcceptResult reports the promotion outcome (the created run + the now-accepted proposal).
type AcceptResult struct {
	Proposal *ai.Proposal `json:"proposal"`
	RunID    uuid.UUID    `json:"run_id"`
	Status   string       `json:"status"`
}

// Accept promotes a PENDING AI proposal into a run through the EXISTING soar pipeline — the human gate between
// AI-proposes and action-runs. Guards, in order:
//  1. Role floor soc_manager+ enforced HERE (defense-in-depth behind the soarApprover route middleware): an analyst/T1
//     — or a stolen T1 token that reached this usecase — can never promote a proposal to a run.
//  2. The proposal must be pending + in the caller's own tenant (GetProposal is RLS-scoped).
//  3. The senior-selected enacting playbook must belong to the tenant AND contain the proposal's recommended_action,
//     so accept runs what the AI proposed — never an unrelated playbook.
//  4. soar.Run creates the run → Allowed(mode,risk) + !FleetWide + four-eyes + D5 + authority_policies all apply. The
//     accepting senior becomes the run's RequestedBy, so a DIFFERENT approver must clear any step left pending
//     (four-eyes). Two human/authority gates total: this accept + the run's approval.
//  5. MarkProposalAccepted transitions pending->accepted keyed on status='pending' — the double-promotion guard: a
//     proposal can be promoted to a run exactly once.
func (s *Service) Accept(ctx context.Context, p auth.Principal, proposalID, playbookID uuid.UUID) (*AcceptResult, error) {
	if auth.RoleRank(p.Role) < auth.RoleRank(auth.RoleSOCManager) {
		return nil, httpx.ErrForbidden("accepting an AI response proposal requires soc_manager or higher")
	}
	prop, err := s.proposals.GetProposal(ctx, p, proposalID)
	if err != nil {
		return nil, err
	}
	if prop.Status != "pending" {
		return nil, httpx.ErrConflict("proposal is not pending")
	}
	pb, err := s.runner.GetPlaybook(ctx, p.TenantID, playbookID)
	if err != nil {
		return nil, err
	}
	if !playbookHasAction(pb, prop.RecommendedAction) {
		return nil, httpx.ErrBadRequest("selected playbook does not enact the proposed action")
	}

	incidentRef := prop.IncidentRef
	run, err := s.runner.Run(ctx, p, playbookID, &incidentRef)
	if err != nil {
		return nil, err
	}
	// Record acceptance AFTER the run exists. If two accepts race, both call Run (idempotent per (playbook, incident)
	// → ONE run) but only one MarkProposalAccepted wins (WHERE status='pending'); the loser gets a conflict — no
	// double execution.
	if err := s.proposals.MarkProposalAccepted(ctx, p, proposalID, run.ID); err != nil {
		return nil, err
	}
	prop.Status = "accepted"
	prop.AcceptedBy = &p.UserID
	prop.AcceptedRunID = &run.ID
	return &AcceptResult{Proposal: prop, RunID: run.ID, Status: string(run.Status)}, nil
}

// playbookHasAction reports whether any of the playbook's steps enact the given catalog action_key (case-insensitive).
func playbookHasAction(pb *soar.Playbook, action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	for _, st := range pb.Steps {
		if strings.ToLower(strings.TrimSpace(st.Action)) == a {
			return true
		}
	}
	return false
}
