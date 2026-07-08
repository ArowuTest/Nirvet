package correlation

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes correlation (risk-ranked alert clusters) endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// List handles GET /correlations?status=open — risk-ranked clusters.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.List(r.Context(), p.TenantID, r.URL.Query().Get("status"))
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list correlations"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"correlations": xs})
}

// Get handles GET /correlations/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid correlation id"))
		return
	}
	c, err := h.svc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

// Explain handles GET /correlations/{id}/explain — the risk-factor breakdown (COR-006).
func (h *Handler) Explain(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid correlation id"))
		return
	}
	c, factors, err := h.svc.Explain(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"correlation":        c,
		"factors":            factors,
		"effective_risk":     c.EffectiveRisk(),
		"effective_severity": c.EffectiveSeverity(),
	})
}

// Override handles PUT /correlations/{id}/override — analyst severity/risk override (COR-009).
func (h *Handler) Override(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid correlation id"))
		return
	}
	var in OverrideInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.Override(r.Context(), p.TenantID, id, p.UserID, in); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "overridden"})
}
