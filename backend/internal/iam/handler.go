package iam

import (
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes IAM endpoints.
type Handler struct {
	svc     *Service
	cookies auth.CookieOpts // ADR-0007 browser session cookies
}

// NewHandler builds the handler with the environment-appropriate cookie attributes.
func NewHandler(svc *Service, cookies auth.CookieOpts) *Handler {
	return &Handler{svc: svc, cookies: cookies}
}

// Login handles POST /auth/login (public). On success it BOTH returns the token in the body (API/CLI
// back-compat) AND sets the httpOnly session cookies + a CSRF token cookie (browser, ADR-0007). A user with MFA
// enabled who omits the code gets a distinct `mfa_required` 401 so the SPA can show the TOTP step.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.Login(r.Context(), in.Email, in.Password, in.MFACode, httpx.RequestIDFrom(r.Context()))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	h.issueSessionCookies(w, r, res.Principal, res.Token, res.AccessTTL)
	httpx.JSON(w, http.StatusOK, res)
}

// CSRFToken handles GET /auth/csrf — returns the double-submit CSRF token in the body so a cross-site SPA (served
// from a different registrable domain than the API, which therefore cannot READ the __Host- CSRF cookie) can echo
// it in the X-CSRF-Token header on writes. Mints + sets one if the session has none. The cookie itself is still
// sent to the API automatically for the server-side double-submit compare; CORS restricts who can read this
// response body to the trusted SPA origin, so the token value is not exposed to a cross-site attacker.
func (h *Handler) CSRFToken(w http.ResponseWriter, r *http.Request) {
	tok := h.cookies.EnsureCSRF(w, r, refreshTokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]string{"csrf_token": tok})
}

// issueSessionCookies mints a refresh-token family + CSRF token and sets all three cookies. Best-effort on the
// refresh side: if refresh issuance fails the access cookie is still set (the user is logged in, just without
// silent refresh — they re-login when the short access token expires).
func (h *Handler) issueSessionCookies(w http.ResponseWriter, r *http.Request, p auth.Principal, access string, accessTTL time.Duration) {
	var refreshRaw string
	if raw, _, err := h.svc.IssueRefresh(r.Context(), p); err == nil {
		refreshRaw = raw
	}
	csrf, _ := auth.NewCSRFToken()
	h.cookies.SetSessionCookies(w, access, refreshRaw, csrf, accessTTL, refreshTokenTTL)
}

// Refresh handles POST /auth/refresh (public — authenticated by the refresh cookie). It rotates the refresh
// token and re-issues the access cookie. Reuse of a rotated token revokes the whole family.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	raw := auth.RefreshTokenFromCookie(r)
	if raw == "" {
		httpx.Error(w, httpx.ErrUnauthorized("no refresh token"))
		return
	}
	access, newRefresh, accessTTL, err := h.svc.RedeemRefresh(r.Context(), raw)
	if err != nil {
		h.cookies.ClearSessionCookies(w) // a bad/reused/expired refresh clears the session
		httpx.Error(w, httpx.ErrUnauthorized("invalid refresh token"))
		return
	}
	// Rotate the refresh cookie; leave the CSRF cookie in place (the SPA still holds it).
	h.cookies.SetSessionCookies(w, access, newRefresh, "", accessTTL, refreshTokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "refreshed"})
}

// Logout handles POST /auth/logout. Clears the cookies and revokes the presented refresh token (this session).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if raw := auth.RefreshTokenFromCookie(r); raw != "" {
		h.svc.RevokeRefreshToken(r.Context(), raw)
	}
	h.cookies.ClearSessionCookies(w)
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "logged_out"})
}

// LogoutAll handles POST /auth/logout-all (authenticated). "Log out everywhere": bumps the user's session
// generation — which immediately invalidates every live access JWT for the user (not just this browser, and
// unlike plain logout it kills the ≤access-TTL window on other devices) — and revokes all their refresh
// families. Clears this browser's cookies too (LOW #3).
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	if err := h.svc.BumpUserGeneration(r.Context(), p.TenantID, p.UserID); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.RevokeAllUserRefreshTokens(r.Context(), p.TenantID, p.UserID); err != nil {
		httpx.Error(w, err)
		return
	}
	h.cookies.ClearSessionCookies(w)
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "logged_out_all"})
}

// Create handles POST /admin/users. A platform_admin may target any tenant via
// tenant_id; otherwise the user is created in the caller's tenant.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		CreateInput
		TenantID string `json:"tenant_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	tenantID := p.TenantID
	if p.Role == auth.RolePlatformAdmin && in.TenantID != "" {
		id, err := uuid.Parse(in.TenantID)
		if err != nil {
			httpx.Error(w, httpx.ErrBadRequest("invalid tenant_id"))
			return
		}
		tenantID = id
	}
	u, err := h.svc.Create(r.Context(), tenantID, in.CreateInput)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, u)
}

// EnrollMFA handles POST /mfa/enroll — returns the otpauth URI + secret (once). Re-auth gated (M4): the
// body must carry the current password, plus a current TOTP code when MFA is already active.
func (h *Handler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"` // current TOTP, required only when re-enrolling an active factor
	}
	_ = httpx.Decode(r, &in)
	uri, secret, err := h.svc.EnrollMFA(r.Context(), p, in.CurrentPassword, in.Code)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"otpauth_uri": uri, "secret": secret})
}

// ActivateMFA handles POST /mfa/activate with {"code":"123456"}.
func (h *Handler) ActivateMFA(w http.ResponseWriter, r *http.Request) { h.mfaAction(w, r, true) }

// DisableMFA handles POST /mfa/disable with {"code":"123456"}.
func (h *Handler) DisableMFA(w http.ResponseWriter, r *http.Request) { h.mfaAction(w, r, false) }

func (h *Handler) mfaAction(w http.ResponseWriter, r *http.Request, activate bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	var err error
	if activate {
		err = h.svc.ActivateMFA(r.Context(), p, in.Code)
	} else {
		err = h.svc.DisableMFA(r.Context(), p, in.Code)
	}
	if err != nil {
		httpx.Error(w, err)
		return
	}
	// S1: if this activation completed a forced-enrollment grace session, promote it to a FULL session in place
	// (fresh cookies) so the user continues without a re-login. Best-effort — on a mint hiccup they simply re-login.
	if activate && p.MFAPending {
		if tok, ttl, mErr := h.svc.MintFullSessionAfterMFA(r.Context(), p); mErr == nil {
			full := p
			full.MFAPending = false
			h.issueSessionCookies(w, r, full, tok, ttl)
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"mfa_enabled": activate})
}

// ChangePassword handles POST /me/password with
// {"current_password":"...","new_password":"..."}.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.ChangePassword(r.Context(), p, in.CurrentPassword, in.NewPassword); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"changed": true})
}

// Me handles GET /me.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	u, err := h.svc.Me(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, u)
}
