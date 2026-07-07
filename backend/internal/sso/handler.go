package sso

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes SSO endpoints: public login start/callback and admin connection
// management.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Start handles GET /auth/sso/start?connection=<id>|domain=<domain> (public).
// It 302-redirects the browser to the IdP authorization endpoint.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	url, err := h.svc.Start(r.Context(), r.URL.Query().Get("connection"), r.URL.Query().Get("domain"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// Callback handles GET /auth/sso/callback?code=&state= (public). On success it
// returns the Nirvet session token as JSON (the SPA stores it and proceeds).
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Callback(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// CreateConnection handles POST /admin/sso (tenant admin / platform admin).
func (h *Handler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	c, err := h.svc.CreateConnection(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

// ListConnections handles GET /admin/sso.
func (h *Handler) ListConnections(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.ListConnections(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"connections": xs})
}

// DeleteConnection handles DELETE /admin/sso/{id}.
func (h *Handler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid connection id"))
		return
	}
	if err := h.svc.DeleteConnection(r.Context(), p.TenantID, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
