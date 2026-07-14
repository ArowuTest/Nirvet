package riskscore

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler serves the provider-side risk score (own tenant) + the admin config endpoints.
type Handler struct {
	svc *Service
	cfg *Store
}

// NewHandler builds the handler.
func NewHandler(svc *Service, cfg *Store) *Handler { return &Handler{svc: svc, cfg: cfg} }

// Get handles GET /risk-score — the current composite score for the caller's tenant, with its component breakdown.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	score, err := h.svc.Compute(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not compute risk score"))
		return
	}
	httpx.JSON(w, http.StatusOK, score)
}

// GetConfig handles GET /admin/risk-config — the caller tenant's effective (row-or-seeded-default) configuration.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	cfg, err := h.cfg.Resolve(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not load risk-score config"))
		return
	}
	httpx.JSON(w, http.StatusOK, cfg)
}

// SetConfig handles PUT /admin/risk-config — validate + upsert the caller tenant's weights/bands/model params.
func (h *Handler) SetConfig(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in Config
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.cfg.Set(r.Context(), p, p.TenantID, in); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
