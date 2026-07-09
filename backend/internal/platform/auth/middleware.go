package auth

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// apiKeyScheme prefixes raw API keys (nvt_…). Kept here so the middleware can distinguish an
// API key from a JWT without importing the iam package (which would be a cycle).
const apiKeyScheme = "nvt_"

// APIKeyResolver authenticates a raw API key to a Principal. Implemented by iam.Service and
// injected at wiring time — the auth package must not depend on iam.
type APIKeyResolver interface {
	ResolveAPIKey(ctx context.Context, rawKey string) (Principal, error)
}

// SessionChecker enforces the tenant's session policy (IP allow-list, §6.2 IAM-007) on a
// resolved Principal. Implemented by iam.Service; injected at wiring time. Returning an error
// denies the request. A nil checker disables the check.
type SessionChecker interface {
	CheckSession(ctx context.Context, p Principal, clientIP string) error
}

// authDeps bundles the optional authenticators/checkers so the constructors stay simple.
type authDeps struct {
	resolver       APIKeyResolver
	checker        SessionChecker
	trustedProxies int
}

// Authenticate verifies the Bearer token and injects the Principal into context.
func Authenticate(m *Manager) httpx.Middleware { return authenticate(m, authDeps{}) }

// AuthenticateWithAPIKeys accepts EITHER a JWT or an API key (Authorization: Bearer nvt_… or
// X-API-Key: nvt_…), resolving the key via the resolver.
func AuthenticateWithAPIKeys(m *Manager, resolver APIKeyResolver) httpx.Middleware {
	return authenticate(m, authDeps{resolver: resolver})
}

// AuthenticateFull is AuthenticateWithAPIKeys plus per-tenant session-policy enforcement
// (IP allow-list) applied to the resolved Principal (§6.2 IAM-007). trustedProxies controls
// spoof-resistant client-IP extraction from X-Forwarded-For.
func AuthenticateFull(m *Manager, resolver APIKeyResolver, checker SessionChecker, trustedProxies int) httpx.Middleware {
	return authenticate(m, authDeps{resolver: resolver, checker: checker, trustedProxies: trustedProxies})
}

func authenticate(m *Manager, d authDeps) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := resolvePrincipal(w, r, m, d.resolver)
			if !ok {
				return
			}
			if d.checker != nil {
				if err := d.checker.CheckSession(r.Context(), p, clientIP(r, d.trustedProxies)); err != nil {
					httpx.Error(w, err)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// resolvePrincipal authenticates the request (API key first, then JWT), writing an error
// response and returning ok=false on failure.
func resolvePrincipal(w http.ResponseWriter, r *http.Request, m *Manager, resolver APIKeyResolver) (Principal, bool) {
	if resolver != nil {
		if raw := apiKeyFromRequest(r); raw != "" {
			p, err := resolver.ResolveAPIKey(r.Context(), raw)
			if err != nil {
				httpx.Error(w, httpx.ErrUnauthorized("invalid api key"))
				return Principal{}, false
			}
			return p, true
		}
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		httpx.Error(w, httpx.ErrUnauthorized("missing bearer token"))
		return Principal{}, false
	}
	p, err := m.Verify(strings.TrimPrefix(h, "Bearer "))
	if err != nil {
		httpx.Error(w, httpx.ErrUnauthorized("invalid token"))
		return Principal{}, false
	}
	return p, true
}

// clientIP extracts the caller IP, honouring the rightmost trustedProxies entries of
// X-Forwarded-For (spoof-resistant, matching the login-throttle logic).
func clientIP(r *http.Request, trustedProxies int) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && trustedProxies > 0 {
		parts := strings.Split(xff, ",")
		idx := len(parts) - trustedProxies
		if idx < 0 {
			idx = 0
		}
		return strings.TrimSpace(parts[idx])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// apiKeyFromRequest returns a raw API key from the X-API-Key header or an Authorization:
// Bearer nvt_… token, or "" if the request carries no API key.
func apiKeyFromRequest(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); strings.HasPrefix(k, apiKeyScheme) {
		return k
	}
	if t := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); strings.HasPrefix(t, apiKeyScheme) {
		return t
	}
	return ""
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

// roleRank orders roles by privilege tier (higher = more privileged) for floor/cap comparisons —
// SOAR approver floors (§6.11) and break-glass one-tier caps (§6.2). Single source of truth so those
// callers don't each keep a divergent rank map. Provider seniors outrank customer roles. customer_viewer
// is the lowest VALID tier (0); an UNKNOWN/garbage role ranks -1 so it satisfies no floor (fail-closed).
var roleRank = map[Role]int{
	RoleCustomerViewer: 0, RoleCustomerAdmin: 1,
	RoleAnalystT1: 1, RoleAnalystT2: 2, RoleDetectionEng: 2,
	RoleAnalystT3: 3, RoleSOCManager: 4, RolePlatformAdmin: 5,
}

// RoleRank returns a role's privilege tier. R6: an unknown role returns -1 (not the map's zero
// value, which would tie with customer_viewer and let a garbage role clear a viewer-level floor) —
// so an unrecognized role fails every floor comparison rather than silently passing the lowest one.
func RoleRank(r Role) int {
	if rank, ok := roleRank[r]; ok {
		return rank
	}
	return -1
}

// seniorRoleSet are the provider roles trusted with destructive/senior actions (close incident,
// promote alert, create connector, reopen a closed case). Excludes analyst_t1 and detection_engineer.
// Single source of truth — cmd/api wires the route middleware from SeniorRoles(), and domain services
// (e.g. incident reopen) gate with IsSenior, so the two can't drift.
var seniorRoleSet = map[Role]bool{
	RolePlatformAdmin: true, RoleSOCManager: true, RoleAnalystT2: true, RoleAnalystT3: true,
}

// IsSenior reports whether a role is trusted with senior/destructive actions.
func IsSenior(r Role) bool { return seniorRoleSet[r] }

// SeniorRoles returns the senior role list (for RequireRole wiring).
func SeniorRoles() []Role {
	return []Role{RolePlatformAdmin, RoleSOCManager, RoleAnalystT2, RoleAnalystT3}
}
