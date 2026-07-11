package branding

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler is the branding HTTP surface: a PUBLIC read (the login page needs it pre-auth) and a padmin write.
type Handler struct{ svc *Service }

// NewHandler wires the branding handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Get handles GET /branding — PUBLIC (unauthenticated). Returns only presentation config; no sensitive data.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	b, err := h.svc.Get(r.Context())
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read branding"))
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// Set handles PUT /admin/branding — padmin-only (route-gated; the padmin chain audits the mutation).
func (h *Handler) Set(w http.ResponseWriter, r *http.Request) {
	var in Input
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	b, err := h.svc.Set(r.Context(), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}
