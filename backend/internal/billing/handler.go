package billing

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes entitlement endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Get handles GET /billing/entitlements.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	e, err := h.svc.Get(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read entitlements"))
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

// Set handles PUT /billing/entitlements.
func (h *Handler) Set(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in Entitlements
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	e, err := h.svc.Set(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}
