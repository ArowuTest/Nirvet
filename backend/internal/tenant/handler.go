package tenant

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes tenant HTTP endpoints. Route registration + RBAC is applied in
// cmd/api (platform_admin only).
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Create handles POST /admin/tenants.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	t, err := h.svc.Create(r.Context(), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, t)
}

// List handles GET /admin/tenants.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	ts, err := h.svc.List(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"tenants": ts})
}

// Get handles GET /admin/tenants/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	t, err := h.svc.Get(r.Context(), id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}
