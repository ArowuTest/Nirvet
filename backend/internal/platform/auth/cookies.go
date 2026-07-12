package auth

// ADR-0007 browser session cookies. The access JWT and the opaque refresh secret are delivered as HttpOnly
// cookies (unreadable by JS → not XSS-exfiltratable). A separate NON-httpOnly CSRF token cookie is the
// double-submit value the SPA echoes in the X-CSRF-Token header on writes. Non-browser clients (API keys, CLI)
// never see these — they keep using Authorization: Bearer.

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

const (
	// AccessCookie carries the short-lived access JWT (HttpOnly).
	AccessCookie = "nirvet_access"
	// RefreshCookie carries the opaque refresh secret (HttpOnly), scoped to the /auth path only.
	RefreshCookie = "nirvet_refresh"
	// CSRFCookie carries the double-submit CSRF token (readable by the SPA's JS; NOT HttpOnly).
	CSRFCookie = "nirvet_csrf"
	// CSRFHeader is the request header the SPA must echo the CSRF cookie value in, on unsafe methods.
	CSRFHeader = "X-CSRF-Token"

	refreshCookiePath = "/auth" // sent to /auth/refresh and /auth/logout only, never to the general API
)

// CookieOpts are the environment-dependent cookie attributes. Secure is on in production (TLS); SameSite=Lax
// blocks cross-site cookie attachment on top-level navigations' sub-requests.
type CookieOpts struct {
	Secure   bool
	SameSite http.SameSite
}

// DefaultCookieOpts derives cookie attributes: Secure when in production (served over TLS), SameSite=Lax.
func DefaultCookieOpts(production bool) CookieOpts {
	return CookieOpts{Secure: production, SameSite: http.SameSiteLaxMode}
}

// NewCSRFToken returns a fresh random double-submit token.
func NewCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (o CookieOpts) base(name, value, path string, maxAge time.Duration, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: httpOnly,
		Secure:   o.Secure,
		SameSite: o.SameSite,
	}
}

// SetSessionCookies sets the access, refresh, and CSRF cookies for a fresh/rotated session. csrf may be "" to
// leave the existing CSRF cookie untouched (e.g. on refresh, the SPA already holds a CSRF token).
func (o CookieOpts) SetSessionCookies(w http.ResponseWriter, access, refresh, csrf string, accessTTL, refreshTTL time.Duration) {
	http.SetCookie(w, o.base(AccessCookie, access, "/", accessTTL, true))
	if refresh != "" {
		http.SetCookie(w, o.base(RefreshCookie, refresh, refreshCookiePath, refreshTTL, true))
	}
	if csrf != "" {
		http.SetCookie(w, o.base(CSRFCookie, csrf, "/", refreshTTL, false)) // readable by JS (double-submit)
	}
}

// ClearSessionCookies expires all three cookies (logout).
func (o CookieOpts) ClearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, o.base(AccessCookie, "", "/", -time.Second, true))
	http.SetCookie(w, o.base(RefreshCookie, "", refreshCookiePath, -time.Second, true))
	http.SetCookie(w, o.base(CSRFCookie, "", "/", -time.Second, false))
}

// accessTokenFromCookie returns the access JWT from the cookie, or "".
func accessTokenFromCookie(r *http.Request) string {
	if c, err := r.Cookie(AccessCookie); err == nil {
		return c.Value
	}
	return ""
}

// RefreshTokenFromCookie returns the raw refresh secret from the cookie, or "".
func RefreshTokenFromCookie(r *http.Request) string {
	if c, err := r.Cookie(RefreshCookie); err == nil {
		return c.Value
	}
	return ""
}
