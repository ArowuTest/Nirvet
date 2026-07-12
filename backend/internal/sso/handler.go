package sso

import (
	"context"
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes SSO endpoints: public login start/callback and admin connection
// management.
type Handler struct {
	svc     *Service
	cookies auth.CookieOpts // ADR-0007 session cookies
	appURL  string          // SPA URL to redirect to after a successful login
}

// NewHandler builds the handler. cookies + appURL let a completed SSO login establish the httpOnly cookie
// session and land the browser on the console (ADR-0007).
func NewHandler(svc *Service, cookies auth.CookieOpts, appURL string) *Handler {
	return &Handler{svc: svc, cookies: cookies, appURL: appURL}
}

// sessionRefresher issues a rotating refresh-token family for a principal (satisfied by *Service and
// *SAMLService, both delegating to iam).
type sessionRefresher interface {
	IssueRefresh(ctx context.Context, p auth.Principal) (string, time.Time, error)
}

// writeSSOSession completes a browser SSO login by setting the ADR-0007 httpOnly session cookies (access +
// rotating refresh + CSRF) and 302-redirecting to the SPA. The access JWT rides in a cookie — NOT a URL/body
// token — so it is never exposed in browser history or referrer headers.
func writeSSOSession(w http.ResponseWriter, r *http.Request, ref sessionRefresher, cookies auth.CookieOpts, appURL string, res *LoginResult) {
	var refreshRaw string
	var refreshTTL time.Duration
	if raw, exp, err := ref.IssueRefresh(r.Context(), res.Principal); err == nil {
		refreshRaw = raw
		refreshTTL = time.Until(exp)
	}
	csrf, _ := auth.NewCSRFToken()
	cookies.SetSessionCookies(w, res.Token, refreshRaw, csrf, res.AccessTTL, refreshTTL)
	http.Redirect(w, r, appURL, http.StatusFound)
}

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

// Callback handles GET /auth/sso/callback?code=&state= (public). On success it sets the httpOnly session
// cookies (ADR-0007) and redirects the browser to the SPA — a cookie-based browser login, no token in the URL.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Callback(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	writeSSOSession(w, r, h.svc, h.cookies, h.appURL, res)
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
