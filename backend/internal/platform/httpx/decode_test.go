package httpx

// Content-Type enforcement in Decode (reviewer landing: LOGIN CSRF backstop). Rejecting non-JSON forces a
// cross-origin request into a CORS preflight, which the origin-locked CORS blocks — closing the simple-request
// CSRF class on every JSON endpoint, including the cookie-less ones like /auth/login.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecode_RequiresJSONContentType(t *testing.T) {
	type body struct {
		Email string `json:"email"`
	}
	decode := func(ct string) error {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"a@b.c"}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		var v body
		return Decode(r, &v)
	}

	// The CSRF-relevant cases: a cross-site "simple request" uses text/plain or form-encoding and NO custom
	// header — these must be rejected so the request is forced into a (blocked) preflight.
	for _, ct := range []string{"", "text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data"} {
		err := decode(ct)
		api, ok := err.(*APIError)
		if !ok || api.Status != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: expected 415 unsupported_media_type, got %v", ct, err)
		}
	}

	// Legitimate JSON (with or without charset param) is accepted.
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON"} {
		if err := decode(ct); err != nil {
			t.Errorf("Content-Type %q: expected success, got %v", ct, err)
		}
	}
}
