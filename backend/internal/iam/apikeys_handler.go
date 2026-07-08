package iam

// HTTP handlers for service accounts + API keys (SRS §6.2). Routes are tenant-scoped under
// /admin/tenants/{id}/…; a platform_admin may target any tenant, a customer_admin only their
// own (self-scope enforced here).

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// scopeTenant resolves the target tenant from {id} and enforces tenant scope (shared guard).
func (h *Handler) scopeTenant(w http.ResponseWriter, r *http.Request) (auth.Principal, uuid.UUID, bool) {
	return auth.ScopeToTenant(w, r, "id")
}

// CreateServiceAccount handles POST /admin/tenants/{id}/service-accounts.
func (h *Handler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	var in SACreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	sa, err := h.svc.CreateServiceAccount(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, sa)
}

// ListServiceAccounts handles GET /admin/tenants/{id}/service-accounts.
func (h *Handler) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	sas, err := h.svc.ListServiceAccounts(r.Context(), id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list service accounts"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"service_accounts": sas})
}

// CreateAPIKey handles POST /admin/tenants/{id}/service-accounts/{sid}/keys. The raw key is
// returned exactly once in the "key" field and can never be retrieved again.
func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	sid, err := uuid.Parse(r.PathValue("sid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid service account id"))
		return
	}
	var in KeyCreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	k, raw, err := h.svc.CreateAPIKey(r.Context(), p, id, sid, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"api_key": k, "key": raw,
		"warning": "store this key now; it cannot be retrieved again"})
}

// ListAPIKeys handles GET /admin/tenants/{id}/service-accounts/{sid}/keys (metadata only).
func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	sid, err := uuid.Parse(r.PathValue("sid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid service account id"))
		return
	}
	ks, err := h.svc.ListAPIKeys(r.Context(), id, sid)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list api keys"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"keys": ks})
}

// GetSessionPolicy handles GET /admin/tenants/{id}/session-policy (§6.2 IAM-007).
func (h *Handler) GetSessionPolicy(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	pol, err := h.svc.GetSessionPolicy(r.Context(), id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, pol)
}

// UpdateSessionPolicy handles PUT /admin/tenants/{id}/session-policy.
func (h *Handler) UpdateSessionPolicy(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	var in SessionPolicyInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	pol, err := h.svc.UpdateSessionPolicy(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, pol)
}

// RevokeAPIKey handles DELETE /admin/tenants/{id}/api-keys/{kid}.
func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p, id, ok := h.scopeTenant(w, r)
	if !ok {
		return
	}
	kid, err := uuid.Parse(r.PathValue("kid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid key id"))
		return
	}
	if err := h.svc.RevokeAPIKey(r.Context(), p, id, kid); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
