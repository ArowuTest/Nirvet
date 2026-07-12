package auth

// ADR-0007 CSRF defense for cookie auth (double-submit token). Cookie auth is CSRF-exposed in a way the
// Authorization-header scheme was not (a cross-site form auto-attaches cookies). Defense in depth:
//   1. SameSite=Lax on the auth cookies blocks cross-site cookie attachment on unsafe requests, AND
//   2. on every unsafe method of a COOKIE-authenticated request, the non-httpOnly CSRF cookie value must be
//      echoed in the X-CSRF-Token header. A cross-site attacker can neither read the cookie value (different
//      origin) nor set a custom header, so the check fails closed.
// Bearer / API-key requests (no auth cookie) were never CSRF-exposed and are skipped.

import (
	"crypto/subtle"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CSRF enforces the double-submit token on unsafe methods of cookie-authenticated requests.
func CSRF() httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if csrfRequired(r) {
				cookieVal := csrfTokenFromCookie(r)
				hdr := r.Header.Get(CSRFHeader)
				if cookieVal == "" || hdr == "" ||
					subtle.ConstantTimeCompare([]byte(cookieVal), []byte(hdr)) != 1 {
					httpx.Error(w, httpx.ErrForbidden("CSRF token missing or invalid"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// csrfRequired is true only for a state-changing method carried on a COOKIE-authenticated request.
func csrfRequired(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		return false // safe methods never need CSRF
	}
	// hasAuthCookie is prefix-aware (matches __Host-/__Secure- and plain names). No auth cookie →
	// Bearer/API-key/pre-login request → not CSRF-exposed.
	return hasAuthCookie(r)
}
