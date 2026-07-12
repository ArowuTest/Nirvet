package auth

// ADR-0007 browser session cookies. The access JWT and the opaque refresh secret are delivered as HttpOnly
// cookies (unreadable by JS → not XSS-exfiltratable). A separate NON-httpOnly CSRF token cookie is the
// double-submit value the SPA echoes in the X-CSRF-Token header on writes. Non-browser clients (API keys, CLI)
// never see these — they keep using Authorization: Bearer.
//
// Cookie prefixes (reviewer landing LOW #1): in production (Secure) the access and CSRF cookies use the __Host-
// prefix and the refresh cookie uses __Secure-. __Host- binds a cookie to its exact host with Path=/ and no
// Domain, so a sibling subdomain (or a network attacker who can set cookies for the parent domain) CANNOT plant
// a forged cookie — which is the one residual that double-submit CSRF alone doesn't cover. __Host- forbids a
// non-"/" Path, so the /auth-scoped refresh cookie uses __Secure- (Secure-only) instead. Both prefixes REQUIRE
// Secure, so they're used only in production; dev (http) keeps the plain names. Reads accept either form.

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

const (
	// AccessCookie is the base name for the access-JWT cookie (HttpOnly). Prefixed with __Host- in production.
	AccessCookie = "nirvet_access"
	// RefreshCookie is the base name for the refresh-secret cookie (HttpOnly, /auth-scoped). __Secure- in prod.
	RefreshCookie = "nirvet_refresh"
	// CSRFCookie is the base name for the double-submit CSRF token (readable by JS; NOT HttpOnly). __Host- in prod.
	CSRFCookie = "nirvet_csrf"
	// CSRFHeader is the request header the SPA must echo the CSRF cookie value in, on unsafe methods.
	CSRFHeader = "X-CSRF-Token"

	refreshCookiePath = "/auth" // sent to /auth/refresh and /auth/logout only, never to the general API

	hostPrefix   = "__Host-"
	securePrefix = "__Secure-"
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

// Prefixed cookie names. Only Secure sessions get the prefixes (browsers reject __Host-/__Secure- without Secure).
func (o CookieOpts) accessName() string  { return o.prefixed(hostPrefix, AccessCookie) }
func (o CookieOpts) csrfName() string    { return o.prefixed(hostPrefix, CSRFCookie) }
func (o CookieOpts) refreshName() string { return o.prefixed(securePrefix, RefreshCookie) }

func (o CookieOpts) prefixed(prefix, base string) string {
	if o.Secure {
		return prefix + base
	}
	return base
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
		Path:     path, // no Domain set → host-only, which __Host- also requires
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: httpOnly,
		Secure:   o.Secure,
		SameSite: o.SameSite,
	}
}

// SetSessionCookies sets the access, refresh, and CSRF cookies for a fresh/rotated session. csrf may be "" to
// leave the existing CSRF cookie untouched (e.g. on refresh, the SPA already holds a CSRF token).
func (o CookieOpts) SetSessionCookies(w http.ResponseWriter, access, refresh, csrf string, accessTTL, refreshTTL time.Duration) {
	http.SetCookie(w, o.base(o.accessName(), access, "/", accessTTL, true))
	if refresh != "" {
		http.SetCookie(w, o.base(o.refreshName(), refresh, refreshCookiePath, refreshTTL, true))
	}
	if csrf != "" {
		http.SetCookie(w, o.base(o.csrfName(), csrf, "/", refreshTTL, false)) // readable by JS (double-submit)
	}
}

// ClearSessionCookies expires the session cookies (logout). It clears BOTH the prefixed and plain names so a
// logout is effective regardless of which the browser holds (e.g. across a config flip).
func (o CookieOpts) ClearSessionCookies(w http.ResponseWriter) {
	for _, n := range []string{o.accessName(), AccessCookie} {
		http.SetCookie(w, o.base(n, "", "/", -time.Second, true))
	}
	for _, n := range []string{o.refreshName(), RefreshCookie} {
		http.SetCookie(w, o.base(n, "", refreshCookiePath, -time.Second, true))
	}
	for _, n := range []string{o.csrfName(), CSRFCookie} {
		http.SetCookie(w, o.base(n, "", "/", -time.Second, false))
	}
}

// firstCookie returns the value of the first present, non-empty cookie among names.
func firstCookie(r *http.Request, names ...string) string {
	for _, n := range names {
		if c, err := r.Cookie(n); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// accessTokenFromCookie returns the access JWT from the cookie (prefixed or plain), or "".
func accessTokenFromCookie(r *http.Request) string {
	return firstCookie(r, hostPrefix+AccessCookie, AccessCookie)
}

// RefreshTokenFromCookie returns the raw refresh secret from the cookie (prefixed or plain), or "".
func RefreshTokenFromCookie(r *http.Request) string {
	return firstCookie(r, securePrefix+RefreshCookie, RefreshCookie)
}

// csrfTokenFromCookie returns the double-submit CSRF token from the cookie (prefixed or plain), or "".
func csrfTokenFromCookie(r *http.Request) string {
	return firstCookie(r, hostPrefix+CSRFCookie, CSRFCookie)
}

// hasAuthCookie reports whether the request carries any session (access or refresh) cookie — used by the CSRF
// middleware to decide whether the request is cookie-authenticated (and thus CSRF-exposed).
func hasAuthCookie(r *http.Request) bool {
	return accessTokenFromCookie(r) != "" || RefreshTokenFromCookie(r) != ""
}
