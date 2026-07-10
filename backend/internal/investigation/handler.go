package investigation

// §6.9 #124 I-1 — the investigation HTTP surface. Thin: decode → service → JSON. The routes are provider-gated
// (analyst_t1+) in the router; the allow-list/role/cost/audit controls live in the service.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes the investigation query endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// RunHunt handles POST /investigation/run-hunt-query and PATCH /investigation/search-events (same allow-listed engine).
func (h *Handler) RunHunt(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var q HuntQuery
	if err := httpx.Decode(r, &q); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.RunHunt(r.Context(), p, q)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}
