package auth

import (
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Authenticate verifies the Bearer token and injects the Principal into context.
func Authenticate(m *Manager) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				httpx.Error(w, httpx.ErrUnauthorized("missing bearer token"))
				return
			}
			p, err := m.Verify(strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				httpx.Error(w, httpx.ErrUnauthorized("invalid token"))
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RequireRole allows the request only if the principal holds one of the roles.
func RequireRole(roles ...Role) httpx.Middleware {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
				return
			}
			if !allowed[p.Role] {
				httpx.Error(w, httpx.ErrForbidden("insufficient role"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsProviderRole reports whether the role is a provider-side (SOC) role.
func IsProviderRole(r Role) bool {
	switch r {
	case RolePlatformAdmin, RoleSOCManager, RoleAnalystT1, RoleAnalystT2, RoleAnalystT3, RoleDetectionEng:
		return true
	default:
		return false
	}
}
