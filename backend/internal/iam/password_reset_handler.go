package iam

// HTTP handlers for G1 admin-issued password reset (§6.2). Issue is admin-only + tenant-scoped (scopeTenant);
// confirm is PUBLIC but capability-gated by the token.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// IssuePasswordReset handles POST /admin/tenants/{id}/users/{uid}/reset-password (admin-issued).
func (h *Handler) IssuePasswordReset(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	uid, err := uuid.Parse(r.PathValue("uid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid user id"))
		return
	}
	var in struct {
		ReturnLink bool `json:"return_link"` // opt-in out-of-band fallback; body is optional
	}
	_ = httpx.Decode(r, &in) // empty body → return_link=false (email-only default)
	res, link, err := h.svc.IssuePasswordReset(r.Context(), p, id, uid, in.ReturnLink)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	out := map[string]any{"reset": res}
	if link != "" {
		out["link"] = link
		out["warning"] = "returned once for out-of-band delivery; anyone with this link can set the password"
	}
	httpx.JSON(w, http.StatusCreated, out)
}

// ConfirmPasswordReset handles POST /auth/password-reset/confirm (PUBLIC): the user sets a new password with a
// valid reset token. No email lookup → no enumeration oracle.
func (h *Handler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.ConfirmPasswordReset(r.Context(), in.Token, in.NewPassword); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "password_updated"})
}
