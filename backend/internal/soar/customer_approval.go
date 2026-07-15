package soar

// §6.11 #188 HEAVY-2 (sub-commit 2/3) — customer-approval authority + the two-principal execution gate.
//
// Owner intent: route destructive-action approval flexibly — to a customer/agency-appointed approver OR the
// assigned platform analyst, switchable per customer — BOTH through the same catalog-risk + four-eyes gate, never
// a bypass. Modes (per tenant, default platform_analyst = today's behavior):
//   - platform_analyst : internal analyst approves + executes (historical path, unchanged).
//   - customer_approver : the customer authorizes via a single-use run-bound link; their tenant-delegated
//                         authority stands in for the platform approver rank on HIGH-risk destructive steps.
//   - both_required    : a destructive step needs BOTH an internal approver (with rank) AND a customer approval,
//                         two DISTINCT principals.
// business_critical is NEVER executed via this flow — it stays skipped (fail-safe); customer-approval covers the
// HIGH-risk destructive class (isolate/disable/block), which is the launch use case.

import (
	"context"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CodeCustomerApprovalDisabled marks the one 403 on the customer approval path that is ABOUT THE CUSTOMER'S OWN
// tenant policy — so it is the only refusal the audience boundary lets through verbatim (customerSafeError in
// handler.go allowlists it by CODE, never by matching its prose).
const CodeCustomerApprovalDisabled = "customer_approval_disabled"

// ErrCustomerApprovalDisabled is returned when a customer tries to approve while their tenant still routes
// authority to the platform analyst (the fail-safe default).
func ErrCustomerApprovalDisabled() *httpx.APIError {
	return &httpx.APIError{Status: http.StatusForbidden, Code: CodeCustomerApprovalDisabled,
		Message: "customer approval is not enabled for this tenant"}
}

// Authority modes (source of truth for the customer_approval_policy.authority CHECK).
const (
	AuthorityPlatformAnalyst  = "platform_analyst"
	AuthorityCustomerApprover = "customer_approver"
	AuthorityBothRequired     = "both_required"
)

// approval kinds (source of truth for the run_approval.kind CHECK).
const (
	approvalInternal = "internal"
	approvalCustomer = "customer"
)

// execAuth carries the customer-approval context into executeRun.
type execAuth struct {
	skipInternalRank bool // a customer-delegated authorization needs no platform approver rank on non-BC steps
}

// CustomerApprovalPolicy is the resolved per-tenant policy.
type CustomerApprovalPolicy struct {
	Authority              string `json:"authority"`
	BCCustomerAuthorizable bool   `json:"bc_customer_authorizable"`
	LinkTTLSeconds         int    `json:"link_ttl_seconds"`
	CustomerApproverRef    string `json:"customer_approver_ref"`
}

func defaultCustomerPolicy() CustomerApprovalPolicy {
	return CustomerApprovalPolicy{Authority: AuthorityPlatformAnalyst, LinkTTLSeconds: 10800}
}

// resolveCustomerPolicy returns the tenant's effective policy (own row wins, else global default). Any error →
// the fail-safe platform_analyst default (i.e. NO customer involvement, historical behavior).
func (s *Service) resolveCustomerPolicy(ctx context.Context, tenantID uuid.UUID) CustomerApprovalPolicy {
	pol := defaultCustomerPolicy()
	_ = s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var authority, ref string
		var bc bool
		var ttl int
		err := tx.QueryRow(ctx,
			`SELECT authority, bc_customer_authorizable, link_ttl_seconds, customer_approver_ref
			   FROM customer_approval_policy WHERE tenant_id = $1 OR tenant_id IS NULL
			  ORDER BY tenant_id NULLS LAST LIMIT 1`, tenantID).Scan(&authority, &bc, &ttl, &ref)
		if err == nil && (authority == AuthorityPlatformAnalyst || authority == AuthorityCustomerApprover || authority == AuthorityBothRequired) {
			pol = CustomerApprovalPolicy{Authority: authority, BCCustomerAuthorizable: bc, LinkTTLSeconds: ttl, CustomerApproverRef: ref}
		}
		return nil
	})
	return pol
}

// approvalRec is one recorded approval on a run.
type approvalRec struct {
	Kind        string
	PrincipalID *uuid.UUID
	Ref         string
	Role        string
}

// recordApproval appends an approval (idempotent per run/kind/ref via the dedup index).
func (s *Service) recordApproval(ctx context.Context, tenantID, runID uuid.UUID, kind string, principalID *uuid.UUID, ref, role string) error {
	return s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO run_approval (tenant_id, run_id, kind, principal_id, principal_ref, principal_role)
			 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (run_id, kind, principal_ref) DO NOTHING`,
			tenantID, runID, kind, principalID, ref, role)
		return e
	})
}

func (s *Service) listApprovals(ctx context.Context, tenantID, runID uuid.UUID) ([]approvalRec, error) {
	var out []approvalRec
	err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT kind, principal_id, principal_ref, principal_role FROM run_approval WHERE run_id = $1`, runID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r approvalRec
			if e := rows.Scan(&r.Kind, &r.PrincipalID, &r.Ref, &r.Role); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// evaluateGate decides whether the run's accumulated approvals satisfy the policy, and returns the principal to
// execute AS. Enforces: the required set of DISTINCT principals is present; four-eyes (internal ≠ requester); and
// the dual-role guard (an internal and a customer approval may NOT be the same person). Re-validates the internal
// approver is still active (a stale approval cannot fire).
func (s *Service) evaluateGate(ctx context.Context, tenantID uuid.UUID, run *PlaybookRun, policy CustomerApprovalPolicy) (ready bool, execP auth.Principal, ea execAuth, err error) {
	approvals, e := s.listApprovals(ctx, tenantID, run.ID)
	if e != nil {
		return false, auth.Principal{}, execAuth{}, httpx.ErrInternal("could not read approvals")
	}
	var internal, customer []approvalRec
	for _, a := range approvals {
		if a.Kind == approvalInternal {
			internal = append(internal, a)
		} else if a.Kind == approvalCustomer {
			customer = append(customer, a)
		}
	}
	// Fail-closed: a run with no recorded requester cannot be gated for four-eyes, so it must never be
	// customer/both-approved (no nil-requester hole).
	if run.RequestedBy == nil {
		return false, auth.Principal{}, execAuth{}, httpx.ErrForbidden("run has no requester; cannot be approved in this flow")
	}
	needCustomer := policy.Authority == AuthorityCustomerApprover || policy.Authority == AuthorityBothRequired
	needInternal := policy.Authority == AuthorityBothRequired
	if needInternal && len(internal) == 0 {
		return false, auth.Principal{}, execAuth{}, nil
	}
	if needCustomer && len(customer) == 0 {
		return false, auth.Principal{}, execAuth{}, nil
	}
	// Dual-role guard: the same human cannot fill both the internal and the customer slot (two-distinct-principals).
	for _, in := range internal {
		for _, cu := range customer {
			if in.Ref != "" && in.Ref == cu.Ref {
				return false, auth.Principal{}, execAuth{}, httpx.ErrForbidden("the same principal cannot provide both the internal and the customer approval")
			}
		}
	}
	// Four-eyes (defense-in-depth; the analyst path also enforces it at record time via canApprove).
	if run.RequestedBy != nil {
		for _, in := range internal {
			if in.PrincipalID != nil && *in.PrincipalID == *run.RequestedBy {
				return false, auth.Principal{}, execAuth{}, httpx.ErrForbidden("separation of duties: the requester may not approve")
			}
		}
	}

	if len(internal) > 0 {
		in := internal[0]
		if s.validator != nil && in.PrincipalID != nil && !s.validator.IsActive(ctx, tenantID, *in.PrincipalID) {
			return false, auth.Principal{}, execAuth{}, httpx.ErrForbidden("the internal approver is no longer active")
		}
		var uid uuid.UUID
		if in.PrincipalID != nil {
			uid = *in.PrincipalID
		}
		execP = auth.Principal{TenantID: tenantID, UserID: uid, Email: in.Ref, Role: auth.Role(in.Role)}
		// customer_approver: the customer delegated authority → non-BC needs no platform rank. both_required: the
		// internal approver's rank IS required (skipInternalRank stays false).
		ea.skipInternalRank = policy.Authority == AuthorityCustomerApprover
	} else {
		// customer_approver with a customer approval only → execute as a synthetic customer principal (no platform
		// rank; the customer's delegated authority is the authorization).
		ref := "customer"
		if len(customer) > 0 && customer[0].Ref != "" {
			ref = customer[0].Ref
		}
		execP = auth.Principal{TenantID: tenantID, UserID: uuid.Nil, Email: "customer:" + ref, Role: auth.Role("")}
		ea.skipInternalRank = true
	}
	return true, execP, ea, nil
}

// ApproveViaLink is the customer's approval path: consume the single-use, run-bound link (from sub-commit 1),
// record a CUSTOMER approval, and — if the policy is now satisfied — execute (never customer-alone for BC, which
// is skipped anyway). No platform session: the link IS the capability, and it resolves the tenant + run.
func (s *Service) ApproveViaLink(ctx context.Context, rawToken string) (*PlaybookRun, error) {
	if rawToken == "" {
		return nil, httpx.ErrBadRequest("token is required")
	}
	tenantID, runID, err := s.repo.consumeApprovalLink(ctx, hashToken(rawToken))
	if err != nil {
		return nil, err // invalid / expired / already used
	}
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, httpx.ErrNotFound("run not found")
	}
	if run.Status != RunPendingApproval {
		return nil, httpx.ErrBadRequest("run is not pending approval")
	}
	policy := s.resolveCustomerPolicy(ctx, tenantID)
	if policy.Authority == AuthorityPlatformAnalyst {
		return nil, ErrCustomerApprovalDisabled()
	}
	ref := policy.CustomerApproverRef
	if ref == "" {
		ref = "customer"
	}
	if err := s.recordApproval(ctx, tenantID, runID, approvalCustomer, nil, ref, ""); err != nil {
		return nil, httpx.ErrInternal("could not record customer approval")
	}
	cf := map[string]Step{}
	if pb, perr := s.repo.GetPlaybook(ctx, tenantID, run.PlaybookID); perr == nil {
		for _, st := range pb.Steps {
			cf[st.Name] = st
		}
	}
	ready, execP, ea, gerr := s.evaluateGate(ctx, tenantID, run, policy)
	if gerr != nil {
		return nil, gerr
	}
	if !ready {
		return run, nil // customer approval recorded; the run stays pending until an internal approver signs off
	}
	return s.executeRun(ctx, execP, tenantID, run, cf, ea)
}

// GetCustomerPolicy returns the tenant's effective policy for display.
func (s *Service) GetCustomerPolicy(ctx context.Context, p auth.Principal) CustomerApprovalPolicy {
	return s.resolveCustomerPolicy(ctx, p.TenantID)
}

// SetCustomerPolicy upserts the tenant's own policy (never the global default). Audited.
func (s *Service) SetCustomerPolicy(ctx context.Context, p auth.Principal, in CustomerApprovalPolicy) (CustomerApprovalPolicy, error) {
	if in.Authority != AuthorityPlatformAnalyst && in.Authority != AuthorityCustomerApprover && in.Authority != AuthorityBothRequired {
		return CustomerApprovalPolicy{}, httpx.ErrBadRequest("authority must be platform_analyst, customer_approver, or both_required")
	}
	if in.LinkTTLSeconds < 300 || in.LinkTTLSeconds > 86400 {
		return CustomerApprovalPolicy{}, httpx.ErrBadRequest("link_ttl_seconds must be 300..86400")
	}
	if len(in.CustomerApproverRef) > 320 {
		return CustomerApprovalPolicy{}, httpx.ErrBadRequest("customer_approver_ref too long")
	}
	err := s.repo.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO customer_approval_policy (tenant_id, authority, bc_customer_authorizable, link_ttl_seconds, customer_approver_ref)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
			 DO UPDATE SET authority=EXCLUDED.authority, bc_customer_authorizable=EXCLUDED.bc_customer_authorizable,
			               link_ttl_seconds=EXCLUDED.link_ttl_seconds, customer_approver_ref=EXCLUDED.customer_approver_ref, updated_at=now()`,
			p.TenantID, in.Authority, in.BCCustomerAuthorizable, in.LinkTTLSeconds, in.CustomerApproverRef); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "soar.customer_approval_set_policy",
			Target: "tenant:" + p.TenantID.String(), Metadata: map[string]any{"authority": in.Authority}})
	})
	if err != nil {
		return CustomerApprovalPolicy{}, err
	}
	return in, nil
}
