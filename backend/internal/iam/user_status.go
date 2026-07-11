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
	// F-L1: status change + session-generation bump + audit in ONE transaction, so a disable is genuinely
	// atomic — the "no window" guarantee (existing JWTs stop working the instant the status changes) is only
	// true if the generation bump commits together with the status, not as a separate tx that could fail
	// after the status write. Mirrors the gold-standard password_reset.go path.
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE users SET status=$2 WHERE id=$1`, targetID, string(status))
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return httpx.ErrNotFound("user not found")
		}
		if !active {
			// Kill the user's live sessions now — a disabled account's existing JWTs must stop working
			// immediately, not at token expiry. Reactivation needs no bump (the old tokens are already dead).
			if _, e := tx.Exec(ctx,
				`INSERT INTO user_session_state (tenant_id, user_id, generation) VALUES ($1,$2,1)
				 ON CONFLICT (tenant_id, user_id) DO UPDATE SET generation = user_session_state.generation + 1, updated_at=now()`,
				tenantID, targetID); e != nil {
				return e
			}
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: action, Target: "user:" + targetID.String(),
		})
	})
	if err != nil {
		return err
	}
	if !active {
		userGenCache.Delete(tenantID.String() + ":" + targetID.String()) // cache-bust AFTER the bump commits
	}
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
