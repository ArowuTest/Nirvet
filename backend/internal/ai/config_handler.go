package ai

// §6.12 #117 A-4 — HTTP handlers for the AI-provider config surface. Platform-admin routes (global provider,
// allowlist, tenant policy) and tenant-admin routes (own provider override) are gated in the router (padmin /
// ssoAdmin chains); the tighten-only + allowlist-at-save enforcement lives in ConfigService.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// ConfigHandler exposes the config endpoints.
type ConfigHandler struct{ svc *ConfigService }

// NewConfigHandler builds the handler.
func NewConfigHandler(svc *ConfigService) *ConfigHandler { return &ConfigHandler{svc: svc} }

// --- platform-admin: global provider ---

// GetGlobalProvider handles GET /admin/ai/provider.
func (h *ConfigHandler) GetGlobalProvider(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.svc.GetGlobalProvider(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	if !ok {
		httpx.Error(w, httpx.ErrNotFound("no global AI provider configured"))
		return
	}
	httpx.JSON(w, http.StatusOK, v)
}

// SetGlobalProvider handles PUT /admin/ai/provider.
func (h *ConfigHandler) SetGlobalProvider(w http.ResponseWriter, r *http.Request) {
	var in ProviderUpdate
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetGlobalProvider(r.Context(), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// --- platform-admin: allowlist ---

// ListAllowedEndpoints handles GET /admin/ai/allowed-endpoints.
func (h *ConfigHandler) ListAllowedEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := h.svc.ListAllowedEndpoints(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"endpoints": eps})
}

type addEndpointReq struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Note   string `json:"note"`
}

// AddAllowedEndpoint handles POST /admin/ai/allowed-endpoints.
func (h *ConfigHandler) AddAllowedEndpoint(w http.ResponseWriter, r *http.Request) {
	var in addEndpointReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AddAllowedEndpoint(r.Context(), in.Scheme, in.Host, in.Port, in.Note); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

// DeleteAllowedEndpoint handles DELETE /admin/ai/allowed-endpoints/{id}.
func (h *ConfigHandler) DeleteAllowedEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid endpoint id"))
		return
	}
	if err := h.svc.DeleteAllowedEndpoint(r.Context(), id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- platform-admin: tenant policy ---

type policyReq struct {
	AllowedKinds []string `json:"allowed_kinds"`
}

// SetTenantPolicy handles PUT /admin/tenants/{id}/ai-policy.
func (h *ConfigHandler) SetTenantPolicy(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	var in policyReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetTenantPolicy(r.Context(), tid, in.AllowedKinds); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"tenant_id": tid, "allowed_kinds": in.AllowedKinds})
}

// --- tenant-admin: own provider override ---

// GetTenantProvider handles GET /tenant/ai/provider — the caller's effective provider + its policy.
func (h *ConfigHandler) GetTenantProvider(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	v, ok, err := h.svc.GetEffectiveProvider(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	allowed, err := h.svc.GetTenantPolicy(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"provider": v, "configured": ok, "allowed_kinds": allowed})
}

// SetTenantProvider handles PUT /tenant/ai/provider.
func (h *ConfigHandler) SetTenantProvider(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ProviderUpdate
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetTenantProvider(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}
