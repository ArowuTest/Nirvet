package auth

// ADR-0007 unit tests (no DB): the CSRF double-submit middleware and the middleware's cookie-auth fallback.

import (
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// CSRF is enforced only on unsafe methods of COOKIE-authenticated requests; a matching double-submit passes,
// a missing/mismatched token is 403, and Bearer/safe/no-cookie requests are skipped.
func TestCSRF_DoubleSubmit(t *testing.T) {
	h := CSRF()(okHandler())

	run := func(method string, mutate func(*http.Request)) int {
		r := httptest.NewRequest(method, "/x", nil)
		if mutate != nil {
			mutate(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	withAccessCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: AccessCookie, Value: "jwt"}) }
	withCSRF := func(tok string) func(*http.Request) {
		return func(r *http.Request) {
			withAccessCookie(r)
			r.AddCookie(&http.Cookie{Name: CSRFCookie, Value: tok})
			r.Header.Set(CSRFHeader, tok)
		}
	}

	// Safe method with a cookie → no CSRF needed.
	if code := run(http.MethodGet, withAccessCookie); code != http.StatusOK {
		t.Errorf("GET with cookie: got %d, want 200", code)
	}
	// Unsafe + cookie + matching token → OK.
	if code := run(http.MethodPost, withCSRF("tok-123")); code != http.StatusOK {
		t.Errorf("POST with matching CSRF: got %d, want 200", code)
	}
	// Unsafe + cookie + MISSING header → 403.
	if code := run(http.MethodPost, func(r *http.Request) {
		withAccessCookie(r)
		r.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "tok-123"})
	}); code != http.StatusForbidden {
		t.Errorf("POST missing CSRF header: got %d, want 403", code)
	}
	// Unsafe + cookie + MISMATCHED header → 403.
	if code := run(http.MethodPost, func(r *http.Request) {
		withAccessCookie(r)
		r.AddCookie(&http.Cookie{Name: CSRFCookie, Value: "tok-123"})
		r.Header.Set(CSRFHeader, "different")
	}); code != http.StatusForbidden {
		t.Errorf("POST mismatched CSRF: got %d, want 403", code)
	}
	// Unsafe + Bearer (no cookie) → skipped (API/CLI is not CSRF-exposed).
	if code := run(http.MethodPost, func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }); code != http.StatusOK {
		t.Errorf("POST with Bearer (no cookie): got %d, want 200 (CSRF skipped)", code)
	}
	// Unsafe + no auth at all → skipped by CSRF (the auth middleware rejects it elsewhere).
	if code := run(http.MethodPost, nil); code != http.StatusOK {
		t.Errorf("POST with no auth: got %d, want 200 (CSRF not applicable)", code)
	}
}

// The auth middleware accepts the access JWT from the cookie when there is no Bearer header, and the header
// still wins when both are present.
func TestAuthenticate_CookieFallback(t *testing.T) {
	m := NewManager("session-auth-test-secret-0123456789", "nirvet", time.Hour)
	p := Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: RoleAnalystT1, Email: "a@b.c"}
	tok, err := m.IssueWithTTL(p, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var got Principal
	seen := false
	h := Authenticate(m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r.Context())
		seen = true
		w.WriteHeader(http.StatusOK)
	}))

	// Cookie only (no Authorization header) → authenticated.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: AccessCookie, Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !seen || got.UserID != p.UserID {
		t.Fatalf("cookie auth failed: code=%d seen=%v uid=%v", w.Code, seen, got.UserID == p.UserID)
	}

	// No cookie and no header → 401.
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth request: got %d, want 401", w2.Code)
	}
}
