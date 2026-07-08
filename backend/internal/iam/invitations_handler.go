package iam

// HTTP handlers for invitations + access review (SRS §6.2 IAM-001/008/009). Admin routes are
// tenant-scoped via scopeTenant (defined with the API-key handlers); accept is public.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// CreateInvitation handles POST /admin/tenants/{id}/invitations.
func (h *Handler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	var in InviteInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inv, token, err := h.svc.CreateInvitation(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"invitation": inv, "token": token,
		"warning": "share this invitation token now; it cannot be retrieved again"})
}

// ListInvitations handles GET /admin/tenants/{id}/invitations.
func (h *Handler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	invs, err := h.svc.ListInvitations(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list invitations"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"invitations": invs})
}

// RevokeInvitation handles DELETE /admin/tenants/{id}/invitations/{iid}.
func (h *Handler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	iid, err := uuid.Parse(r.PathValue("iid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid invitation id"))
		return
	}
	if err := h.svc.RevokeInvitation(r.Context(), p, id, iid); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// AcceptInvitation handles POST /auth/invitations/accept (PUBLIC): the invitee sets a password.
func (h *Handler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	u, err := h.svc.AcceptInvitation(r.Context(), in.Token, in.Password)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"status": "activated", "email": u.Email, "role": u.Role})
}

// AccessReview handles GET /admin/tenants/{id}/access-review (IAM-009).
func (h *Handler) AccessReview(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	rep, err := h.svc.BuildAccessReview(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not build access review"))
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}
