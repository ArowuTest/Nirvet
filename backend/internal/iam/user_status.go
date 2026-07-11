package iam

// L9 — per-user disable / kill-switch. The operator's lever to instantly revoke ONE compromised or departed
// user without offboarding the whole tenant. Disabling sets status=disabled AND bumps the user's session
// generation, so every live JWT for that user is rejected on its next request (no window), and Login already
// refuses a non-active account for fresh logins. Role-domain guarded and self-disable is refused.

import (
	"context"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetUserActive disables (active=false) or reactivates (active=true) a target user.
func (s *Service) SetUserActive(ctx context.Context, p auth.Principal, tenantID, targetID uuid.UUID, active bool) error {
	if p.UserID == targetID {
		return httpx.ErrBadRequest("cannot change your own account status")
	}
	u, err := s.repo.GetByID(ctx, tenantID, targetID)
	if err != nil {
		return httpx.ErrNotFound("user not found")
	}
	// Same boundary as password reset (RP-1): a customer_admin cannot disable a provider/platform_admin,
	// and platform_admin is never a target here (validateGrantableRole rejects it).
	if err := validateGrantableRole(p.Role, u.Role); err != nil {
		return err
	}
	status, action := UserDisabled, "iam.user_disabled"
	if active {
		status, action = UserActive, "iam.user_reactivated"
	}
	ok, err := s.repo.SetStatus(ctx, tenantID, targetID, status)
	if err != nil || !ok {
		return httpx.ErrInternal("could not update user status")
	}
	if !active {
		// Kill the user's live sessions now — a disabled account's existing JWTs must stop working
		// immediately, not at token expiry. Reactivation needs no bump (the old tokens are already dead).
		if berr := s.BumpUserGeneration(ctx, tenantID, targetID); berr != nil {
			return berr // fail loud: a disable that didn't revoke live sessions is not a disable
		}
	}
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: action, Target: "user:" + targetID.String(),
		})
	})
	return nil
}

// DisableUser handles POST /admin/tenants/{id}/users/{uid}/disable (L9 kill-switch).
func (h *Handler) DisableUser(w http.ResponseWriter, r *http.Request) { h.setUserActive(w, r, false) }

// ReactivateUser handles POST /admin/tenants/{id}/users/{uid}/reactivate.
func (h *Handler) ReactivateUser(w http.ResponseWriter, r *http.Request) { h.setUserActive(w, r, true) }

func (h *Handler) setUserActive(w http.ResponseWriter, r *http.Request, active bool) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	uid, err := uuid.Parse(r.PathValue("uid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid user id"))
		return
	}
	if err := h.svc.SetUserActive(r.Context(), p, id, uid, active); err != nil {
		httpx.Error(w, err)
		return
	}
	out := "disabled"
	if active {
		out = "active"
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": out})
}
