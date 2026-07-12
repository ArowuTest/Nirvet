package ai

// §6.12 #188 HEAVY-1 — the tenant-admin surface for AI-egress redaction: view/set the policy (enabled + mode) and
// manage config-extensible masking patterns. Tenant-scoped (RLS confines every read/write to the caller's tenant);
// the global default policy + global patterns are read-only here. Routes are gated at tenant-admin (ssoAdmin).

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// RedactionHandler serves the redaction config endpoints.
type RedactionHandler struct{ svc *RedactionService }

// NewRedactionHandler builds the handler.
func NewRedactionHandler(svc *RedactionService) *RedactionHandler { return &RedactionHandler{svc: svc} }

// GetPolicy handles GET /tenant/ai/redaction — the effective policy for the tenant.
func (h *RedactionHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	httpx.JSON(w, http.StatusOK, h.svc.GetPolicy(r.Context(), p))
}

type setPolicyReq struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
}

// SetPolicy handles PUT /tenant/ai/redaction — upsert the tenant's own policy.
func (h *RedactionHandler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in setPolicyReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetPolicy(r.Context(), p, in.Enabled, in.Mode)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// ListPatterns handles GET /tenant/ai/redaction/patterns — own + global patterns.
func (h *RedactionHandler) ListPatterns(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pats, err := h.svc.ListPatterns(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"patterns": pats})
}

type addPatternReq struct {
	Name        string `json:"name"`
	Regex       string `json:"regex"`
	Placeholder string `json:"placeholder"`
}

// AddPattern handles POST /tenant/ai/redaction/patterns — add a config-extensible masking pattern (validated +
// compiled server-side). This is how a jurisdiction identifier (e.g. Ghana Card) is added without a code change.
func (h *RedactionHandler) AddPattern(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in addPatternReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	id, err := h.svc.AddPattern(r.Context(), p, in.Name, in.Regex, in.Placeholder)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"id": id})
}

// DeletePattern handles DELETE /tenant/ai/redaction/patterns/{id} — remove a tenant-own pattern.
func (h *RedactionHandler) DeletePattern(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid pattern id"))
		return
	}
	if err := h.svc.DeletePattern(r.Context(), p, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}
