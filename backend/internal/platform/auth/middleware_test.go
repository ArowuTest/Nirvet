package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRequireRoleMiddleware(t *testing.T) {
	m := NewManager("secret", "nirvet", 15*time.Minute)
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	// Authenticate then require analyst_t2 (SOC role).
	handler := Authenticate(m)(RequireRole(RoleAnalystT2)(final))

	token := func(role Role) string {
		tok, _ := m.Issue(Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: role, Email: "u@t"})
		return tok
	}

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"allowed role", "Bearer " + token(RoleAnalystT2), http.StatusOK},
		{"wrong role forbidden", "Bearer " + token(RoleCustomerViewer), http.StatusForbidden},
		{"no token unauthorized", "", http.StatusUnauthorized},
		{"garbage token unauthorized", "Bearer not.a.jwt", http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d", rec.Code, c.want)
			}
		})
	}
}
