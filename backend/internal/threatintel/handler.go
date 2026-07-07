package threatintel

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes watchlist endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Add handles POST /threat-intel.
func (h *Handler) Add(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in AddInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	ind, err := h.svc.Add(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, ind)
}

// List handles GET /threat-intel.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	inds, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list indicators"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"indicators": inds})
}
