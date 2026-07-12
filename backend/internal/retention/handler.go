package retention

// §6.14 #188 HEAVY-3 — the tenant-admin surface: view/set the retention policy (enabled + optional tighten-only
// window) and read the sweep log (what WAS or WOULD BE deleted). Tenant-scoped (RLS).

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler serves the retention endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// GetPolicy handles GET /retention — the effective retention view.
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	httpx.JSON(w, http.StatusOK, h.svc.GetPolicy(r.Context(), p))
}

type setReq struct {
	Enabled    bool `json:"enabled"`
	WindowDays *int `json:"window_days"`
}

// SetPolicy handles PUT /retention — enable/disable live deletion + optional tighten-only window.
func (h *Handler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in setReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.SetPolicy(r.Context(), p, in.Enabled, in.WindowDays)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// ListSweeps handles GET /retention/sweeps — the sweep log (dry-run + live).
func (h *Handler) ListSweeps(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rows, err := h.svc.ListSweeps(r.Context(), p, 50)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sweeps": rows})
}
