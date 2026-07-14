package platformhealth

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler serves the aggregated health snapshot. Route gating (padmin) is applied at the mux in main.go.
type Handler struct{ svc *Service }

// NewHandler builds the health handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Get handles GET /admin/health — the operator's platform-health snapshot.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, h.svc.Snapshot(r.Context()))
}
