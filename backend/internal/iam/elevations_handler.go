package iam

// HTTP handlers for privileged elevation + break-glass (SRS §6.2 IAM-004/006). /me/* act on
// the caller's own principal; /admin/* (approve/reject/review/list) are senior-gated in main
// and act within the caller's tenant.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// RequestElevation handles POST /me/elevations.
func (h *Handler) RequestElevation(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ElevationInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	e, err := h.svc.RequestElevation(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

// BreakGlass handles POST /me/elevations/break-glass.
func (h *Handler) BreakGlass(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ElevationInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	e, err := h.svc.BreakGlass(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

// ListMyElevations handles GET /me/elevations.
func (h *Handler) ListMyElevations(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	es, err := h.svc.ListMyElevations(r.Context(), p)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list elevations"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"elevations": es})
}

// MintElevatedToken handles POST /me/elevations/{id}/token.
func (h *Handler) MintElevatedToken(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid elevation id"))
		return
	}
	token, e, err := h.svc.MintElevatedToken(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"token": token, "elevated_role": e.ElevatedRole, "expires_at": e.ExpiresAt})
}

// elevID resolves {id} for the admin routes and returns the acting principal.
func elevID(w http.ResponseWriter, r *http.Request) (auth.Principal, uuid.UUID, bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid elevation id"))
		return p, uuid.Nil, false
	}
	return p, id, true
}

// ApproveElevation handles POST /admin/elevations/{id}/approve.
func (h *Handler) ApproveElevation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := elevID(w, r)
	if !ok {
		return
	}
	e, err := h.svc.ApproveElevation(r.Context(), p, p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

// RejectElevation handles POST /admin/elevations/{id}/reject.
func (h *Handler) RejectElevation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := elevID(w, r)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	_ = httpx.Decode(r, &in)
	if err := h.svc.RejectElevation(r.Context(), p, p.TenantID, id, in.Reason); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// ReviewElevation handles POST /admin/elevations/{id}/review (break-glass post-use review).
func (h *Handler) ReviewElevation(w http.ResponseWriter, r *http.Request) {
	p, id, ok := elevID(w, r)
	if !ok {
		return
	}
	var in struct {
		Notes string `json:"notes"`
	}
	_ = httpx.Decode(r, &in)
	if err := h.svc.ReviewElevation(r.Context(), p, p.TenantID, id, in.Notes); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "reviewed"})
}

// ListElevations handles GET /admin/elevations.
func (h *Handler) ListElevations(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	es, err := h.svc.ListElevations(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list elevations"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"elevations": es})
}
