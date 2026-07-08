package entitygraph

import (
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes the entity-graph endpoint.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Graph handles GET /entities/graph?ref=<entity-ref>. The ref is a query parameter
// (not a path segment) because entity refs contain ':' and '@' (host:FIN-01,
// user:jane@acme.com) which are awkward to encode in a path.
func (h *Handler) Graph(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	g, err := h.svc.Build(r.Context(), p.TenantID, ref)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, g)
}
