package soar

// §6.11 SB3 — the IN-PORTAL, AUTHENTICATED customer approval path. #188 gave the customer a single-use
// out-of-band LINK (ApproveViaLink); this adds the same decision for a logged-in customer_admin from the portal
// approvals queue. It reuses the EXACT same machinery — resolveCustomerPolicy, recordApproval(kind=customer),
// evaluateGate, executeRun — so there is no parallel authorization path. Differences from the link path:
//   - the session IS the capability (no token); the read/write are RLS-scoped to the customer's OWN tenant.
//   - the approval is recorded against the REAL authenticated customer principal (accountable identity), not a
//     synthetic ref — evaluateGate's dual-role + four-eyes guards then apply to a real person.
//   - the decision NEVER executes anything destructive inline itself: it records the approval and lets
//     evaluateGate/executeRun (the existing supervised path) decide — identical to the link flow.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CustomerApprovalItem is the customer-safe summary of a run awaiting the customer's approval. It names only what
// a customer needs to decide: which playbook, on which of their own incidents, since when. Internal step detail,
// the requester identity, and the internal approver are absent by construction.
type CustomerApprovalItem struct {
	RunID        uuid.UUID  `json:"run_id"`
	PlaybookName string     `json:"playbook_name"`
	IncidentID   *uuid.UUID `json:"incident_id,omitempty"`
	CreatedAt    string     `json:"created_at"`
}

// CustomerPendingApprovals lists the tenant's runs awaiting a CUSTOMER approval that has not yet been given. Empty
// (not an error) when the tenant's authority mode does not involve the customer — the queue is dormant until an
// operator sets customer_approver/both_required.
func (s *Service) CustomerPendingApprovals(ctx context.Context, tenantID uuid.UUID) ([]CustomerApprovalItem, error) {
	policy := s.resolveCustomerPolicy(ctx, tenantID)
	if policy.Authority == AuthorityPlatformAnalyst {
		return []CustomerApprovalItem{}, nil // customer not in the loop → nothing to show
	}
	runs, err := s.repo.ListRuns(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load runs")
	}
	nameByID := map[uuid.UUID]string{}
	out := []CustomerApprovalItem{}
	for _, run := range runs {
		if run.Status != RunPendingApproval {
			continue
		}
		// Skip runs the customer has already approved (awaiting the internal signer under both_required).
		approvals, aerr := s.listApprovals(ctx, tenantID, run.ID)
		if aerr != nil {
			return nil, httpx.ErrInternal("could not read approvals")
		}
		hasCustomer := false
		for _, a := range approvals {
			if a.Kind == approvalCustomer {
				hasCustomer = true
				break
			}
		}
		if hasCustomer {
			continue
		}
		name, ok := nameByID[run.PlaybookID]
		if !ok {
			if pb, perr := s.repo.GetPlaybook(ctx, tenantID, run.PlaybookID); perr == nil {
				name = pb.Name
			}
			nameByID[run.PlaybookID] = name
		}
		out = append(out, CustomerApprovalItem{
			RunID: run.ID, PlaybookName: name, IncidentID: run.IncidentID,
			CreatedAt: run.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return out, nil
}

// ApproveAsCustomer records the authenticated customer's approval for a pending run in their OWN tenant, then lets
// the existing gate decide execution. Mirrors ApproveViaLink's guards: run must be pending; the tenant's policy
// must involve the customer; the decision is audited; execution (if the gate is satisfied) runs via the existing
// supervised executeRun. Never executes anything inline itself.
func (s *Service) ApproveAsCustomer(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	run, err := s.repo.GetRun(ctx, p.TenantID, runID) // RLS-scoped → a run outside the tenant is not found
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrConflict("run is not pending approval")
	}
	policy := s.resolveCustomerPolicy(ctx, p.TenantID)
	if policy.Authority == AuthorityPlatformAnalyst {
		return nil, httpx.ErrForbidden("customer approval is not enabled for this tenant")
	}
	uid := p.UserID
	if err := s.recordApproval(ctx, p.TenantID, runID, approvalCustomer, &uid, p.Email, string(p.Role)); err != nil {
		return nil, httpx.ErrInternal("could not record customer approval")
	}
	_ = s.repo.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "soar.customer_approve", Target: "run:" + runID.String()})
	})

	cf := map[string]Step{}
	if pb, perr := s.repo.GetPlaybook(ctx, p.TenantID, run.PlaybookID); perr == nil {
		for _, st := range pb.Steps {
			cf[st.Name] = st
		}
	}
	ready, execP, ea, gerr := s.evaluateGate(ctx, p.TenantID, run, policy)
	if gerr != nil {
		return nil, gerr
	}
	if !ready {
		return run, nil // recorded; still awaiting the internal signer (both_required)
	}
	return s.executeRun(ctx, execP, p.TenantID, run, cf, ea)
}

// RejectAsCustomer cancels a pending run in the customer's own tenant (fail-safe: nothing executes). Only
// meaningful when the tenant's policy involves the customer; audited via rejectFor.
func (s *Service) RejectAsCustomer(ctx context.Context, p auth.Principal, runID uuid.UUID) (*PlaybookRun, error) {
	policy := s.resolveCustomerPolicy(ctx, p.TenantID)
	if policy.Authority == AuthorityPlatformAnalyst {
		return nil, httpx.ErrForbidden("customer approval is not enabled for this tenant")
	}
	return s.rejectFor(ctx, p, p.TenantID, runID)
}
