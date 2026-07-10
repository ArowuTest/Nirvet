package posture

// The vendor posture oversight HTTP surface — metadata only, by construction. The route is role-gated to the
// vendor seat (platform_admin) in the router, AND the scope-resolver independently fail-closes any non-vendor
// principal to an empty scope (defense in depth). There is no tenant/scope parameter a caller can supply.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler is the posture oversight HTTP surface.
type Handler struct{ svc *Service }

// NewHandler wires the posture handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Fleet handles GET /posture/fleet — the vendor's fleet-wide, metadata-only posture. Scope is derived from the
// authenticated principal (never a query/body param); a non-vendor principal sees nothing.
func (h *Handler) Fleet(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rows, err := h.svc.Fleet(r.Context(), p)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read fleet posture"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"posture": rows, "count": len(rows)})
}
