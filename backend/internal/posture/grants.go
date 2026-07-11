package posture

// Oversight grant management (MA-OV-3): the platform_admin issues/revokes the org/payer grants that scope each
// delegate's cross-tenant oversight read. Every issue/revoke writes an AUDIT event (actor + granted_by +
// target) in the SAME transaction as the grant mutation — "who can see across tenants, granted by whom, when"
// is the exact control a CSA auditor probes, so a bare table row isn't enough. padmin-only (route-gated).

import (
	"context"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GrantService issues/revokes oversight grants with an audit trail.
type GrantService struct{ db *database.DB }

// NewGrantService wires the grant service.
func NewGrantService(db *database.DB) *GrantService { return &GrantService{db: db} }

// mutate applies a grant INSERT/DELETE and its audit row in one tx (under the padmin's own tenant so the audit
// lands with a tenant_id). The grant tables carry no tenant_id, so the mutation is unaffected by the GUC.
func (s *GrantService) mutate(ctx context.Context, p auth.Principal, sql, action, target string, args ...any) error {
	return s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: action, Target: target,
			Metadata: map[string]any{"granted_by": p.UserID.String()}})
	})
}

// GrantOrg grants an org-sub-admin principal oversight of an organisation's tenants.
func (s *GrantService) GrantOrg(ctx context.Context, p auth.Principal, principalID, orgID uuid.UUID) error {
	return s.mutate(ctx, p,
		`INSERT INTO org_admin_grant (principal_id, org_id, granted_by) VALUES ($1,$2,$3)
		 ON CONFLICT (principal_id, org_id) DO NOTHING`,
		"oversight.grant.org", "org:"+orgID.String()+" principal:"+principalID.String(), principalID, orgID, p.UserID)
}

// RevokeOrg removes an org-sub-admin grant.
func (s *GrantService) RevokeOrg(ctx context.Context, p auth.Principal, principalID, orgID uuid.UUID) error {
	return s.mutate(ctx, p,
		`DELETE FROM org_admin_grant WHERE principal_id=$1 AND org_id=$2`,
		"oversight.revoke.org", "org:"+orgID.String()+" principal:"+principalID.String(), principalID, orgID)
}

// GrantPayer grants a payer principal oversight of a billing account's covered tenants.
func (s *GrantService) GrantPayer(ctx context.Context, p auth.Principal, principalID, accountID uuid.UUID) error {
	return s.mutate(ctx, p,
		`INSERT INTO payer_account_grant (principal_id, account_id, granted_by) VALUES ($1,$2,$3)
		 ON CONFLICT (principal_id, account_id) DO NOTHING`,
		"oversight.grant.payer", "account:"+accountID.String()+" principal:"+principalID.String(), principalID, accountID, p.UserID)
}

// RevokePayer removes a payer grant.
func (s *GrantService) RevokePayer(ctx context.Context, p auth.Principal, principalID, accountID uuid.UUID) error {
	return s.mutate(ctx, p,
		`DELETE FROM payer_account_grant WHERE principal_id=$1 AND account_id=$2`,
		"oversight.revoke.payer", "account:"+accountID.String()+" principal:"+principalID.String(), principalID, accountID)
}

// GrantHandler is the padmin oversight-grant HTTP surface.
type GrantHandler struct{ svc *GrantService }

// NewGrantHandler wires the grant handler.
func NewGrantHandler(svc *GrantService) *GrantHandler { return &GrantHandler{svc: svc} }

type orgGrantReq struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	OrgID       uuid.UUID `json:"org_id"`
}
type payerGrantReq struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	AccountID   uuid.UUID `json:"account_id"`
}

// GrantOrg handles POST /admin/oversight/org-grants.
func (h *GrantHandler) GrantOrg(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in orgGrantReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.GrantOrg(r.Context(), p, in.PrincipalID, in.OrgID); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not grant"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "granted"})
}

// RevokeOrg handles DELETE /admin/oversight/org-grants.
func (h *GrantHandler) RevokeOrg(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in orgGrantReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.RevokeOrg(r.Context(), p, in.PrincipalID, in.OrgID); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not revoke"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// GrantPayer handles POST /admin/oversight/payer-grants.
func (h *GrantHandler) GrantPayer(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in payerGrantReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.GrantPayer(r.Context(), p, in.PrincipalID, in.AccountID); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not grant"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "granted"})
}

// RevokePayer handles DELETE /admin/oversight/payer-grants.
func (h *GrantHandler) RevokePayer(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in payerGrantReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.RevokePayer(r.Context(), p, in.PrincipalID, in.AccountID); err != nil {
		httpx.Error(w, httpx.ErrInternal("could not revoke"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
