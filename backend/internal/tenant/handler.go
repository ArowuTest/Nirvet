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

type batchReq struct {
	Tenants []BatchRow `json:"tenants"`
}

// CreateBatch handles POST /admin/tenants/batch — bulk-onboard tenants (padmin-gated in the router). Each row
// goes through the same secure atomic create path; the response is a per-row report (created / skipped_duplicate
// / failed) so a partial batch is actionable and a retry converges (idempotent on external_ref).
func (h *Handler) CreateBatch(w http.ResponseWriter, r *http.Request) {
	var in batchReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	res, err := h.svc.CreateBatch(r.Context(), in.Tenants)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
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
