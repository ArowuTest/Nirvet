package auth

// Reviewer landing LOW #1: __Host-/__Secure- cookie prefixes in production, plain names in dev, and reads
// that accept either form.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setCookies(t *testing.T, o CookieOpts) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	o.SetSessionCookies(rec, "acc", "ref", "csrf", time.Minute, time.Hour)
	return rec.Result().Cookies()
}

func find(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCookiePrefixes_ProductionUsesHostAndSecure(t *testing.T) {
	prod := DefaultCookieOpts(true) // Secure=true
	cookies := setCookies(t, prod)

	access := find(cookies, "__Host-"+AccessCookie)
	if access == nil {
		t.Fatalf("expected access cookie named %q, got %+v", "__Host-"+AccessCookie, cookies)
	}
	// __Host- requires Secure, Path=/, and no Domain.
	if !access.Secure || access.Path != "/" || access.Domain != "" {
		t.Errorf("__Host- access cookie violates prefix rules: secure=%v path=%q domain=%q", access.Secure, access.Path, access.Domain)
	}

	csrf := find(cookies, "__Host-"+CSRFCookie)
	if csrf == nil || csrf.HttpOnly {
		t.Errorf("expected non-httpOnly __Host- csrf cookie, got %+v", csrf)
	}

	// Refresh is /auth-scoped, so it cannot be __Host- (that forbids non-"/" paths) → __Secure-.
	refresh := find(cookies, "__Secure-"+RefreshCookie)
	if refresh == nil {
		t.Fatalf("expected refresh cookie named %q, got %+v", "__Secure-"+RefreshCookie, cookies)
	}
	if !refresh.Secure || refresh.Path != refreshCookiePath || !refresh.HttpOnly {
		t.Errorf("__Secure- refresh cookie malformed: secure=%v path=%q httpOnly=%v", refresh.Secure, refresh.Path, refresh.HttpOnly)
	}
	if find(cookies, "__Host-"+RefreshCookie) != nil {
		t.Errorf("refresh cookie must NOT use __Host- (path-scoped)")
	}
}

func TestCookiePrefixes_DevUsesPlainNames(t *testing.T) {
	dev := DefaultCookieOpts(false) // Secure=false → browsers reject prefixes
	cookies := setCookies(t, dev)
	for _, name := range []string{AccessCookie, RefreshCookie, CSRFCookie} {
		if find(cookies, name) == nil {
			t.Errorf("dev: expected plain cookie %q, got %+v", name, cookies)
		}
	}
	for _, name := range []string{"__Host-" + AccessCookie, "__Secure-" + RefreshCookie, "__Host-" + CSRFCookie} {
		if find(cookies, name) != nil {
			t.Errorf("dev: must NOT emit prefixed cookie %q without Secure", name)
		}
	}
}

func TestCookieReads_AcceptEitherForm(t *testing.T) {
	cases := []struct {
		label      string
		access     string
		refresh    string
		csrf       string
		wantAccess bool
	}{
		{"prefixed", "__Host-" + AccessCookie, "__Secure-" + RefreshCookie, "__Host-" + CSRFCookie, true},
		{"plain", AccessCookie, RefreshCookie, CSRFCookie, true},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(&http.Cookie{Name: tc.access, Value: "A"})
			r.AddCookie(&http.Cookie{Name: tc.refresh, Value: "R"})
			r.AddCookie(&http.Cookie{Name: tc.csrf, Value: "C"})
			if got := accessTokenFromCookie(r); got != "A" {
				t.Errorf("access read: got %q want A", got)
			}
			if got := RefreshTokenFromCookie(r); got != "R" {
				t.Errorf("refresh read: got %q want R", got)
			}
			if got := csrfTokenFromCookie(r); got != "C" {
				t.Errorf("csrf read: got %q want C", got)
			}
			if !hasAuthCookie(r) {
				t.Errorf("hasAuthCookie should be true when a session cookie is present")
			}
		})
	}
}
