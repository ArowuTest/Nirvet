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
