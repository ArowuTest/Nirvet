package sso

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// SAMLHandler exposes SAML endpoints: public SP-initiated start + ACS, and admin
// connection management.
type SAMLHandler struct {
	svc     *SAMLService
	cookies auth.CookieOpts // ADR-0007 session cookies
	appURL  string          // SPA URL to redirect to after a successful login
}

// NewSAMLHandler builds the handler.
func NewSAMLHandler(svc *SAMLService, cookies auth.CookieOpts, appURL string) *SAMLHandler {
	return &SAMLHandler{svc: svc, cookies: cookies, appURL: appURL}
}

// Start handles GET /auth/sso/saml/start?connection=<id>|domain=<domain> (public).
// It 302-redirects the browser to the IdP with a SAML AuthnRequest.
func (h *SAMLHandler) Start(w http.ResponseWriter, r *http.Request) {
	url, err := h.svc.Start(r.Context(), r.URL.Query().Get("connection"), r.URL.Query().Get("domain"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// ACS handles POST /auth/sso/saml/acs (public) — the Assertion Consumer Service.
// It reads the IdP's SAMLResponse + RelayState from the form and, on successful
// validation, returns the Nirvet session token.
func (h *SAMLHandler) ACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not parse ACS form"))
		return
	}
	res, err := h.svc.ACS(r.Context(), r.PostFormValue("SAMLResponse"), r.PostFormValue("RelayState"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	// Cookie-based browser login (ADR-0007): set httpOnly session cookies + redirect to the SPA.
	writeSSOSession(w, r, h.svc, h.cookies, h.appURL, res)
}

// CreateConnection handles POST /admin/sso/saml (tenant/platform admin).
func (h *SAMLHandler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SAMLCreateInput
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

// ListConnections handles GET /admin/sso/saml.
func (h *SAMLHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.ListConnections(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"connections": xs})
}

// DeleteConnection handles DELETE /admin/sso/saml/{id}.
func (h *SAMLHandler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
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
