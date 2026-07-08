package auth

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// ScopeToTenant resolves a tenant id from the request path and enforces tenant scope: a
// platform_admin may target any tenant; anyone else (e.g. customer_admin) only their own. It
// writes the error response and returns ok=false when the id is malformed or access is denied.
// Shared by the admin handlers (iam, tenant) so the self-scope guard has ONE definition and one
// error contract (Phase 0 hygiene — it was duplicated as Handler.scopeTenant / Handler.scoped).
func ScopeToTenant(w http.ResponseWriter, r *http.Request, pathKey string) (Principal, uuid.UUID, bool) {
	p, _ := PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue(pathKey))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return p, uuid.Nil, false
	}
	if p.Role != RolePlatformAdmin && p.TenantID != id {
		httpx.Error(w, httpx.ErrForbidden("cannot manage another tenant"))
		return p, uuid.Nil, false
	}
	return p, id, true
}
