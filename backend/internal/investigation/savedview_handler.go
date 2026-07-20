package investigation

// HTTP surface for saved views (§6.9 slice B). All routes are provider-gated (analyst_t1+) and per-analyst private.
// Run executes through the same allow-list-compiled RunHunt path (re-validated for the running actor).

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CreateSavedView handles POST /investigation/saved-views.
func (h *Handler) CreateSavedView(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SavedViewInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	sv, err := h.svc.CreateSavedView(r.Context(), p, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, sv)
}

// ListSavedViews handles GET /investigation/saved-views.
func (h *Handler) ListSavedViews(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	vs, err := h.svc.ListSavedViews(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"saved_views": vs})
}

// GetSavedView handles GET /investigation/saved-views/{id}.
func (h *Handler) GetSavedView(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid saved view id"))
		return
	}
	sv, err := h.svc.GetSavedView(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, sv)
}

// DeleteSavedView handles DELETE /investigation/saved-views/{id}.
func (h *Handler) DeleteSavedView(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid saved view id"))
		return
	}
	if err := h.svc.DeleteSavedView(r.Context(), p, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RunSavedView handles POST /investigation/saved-views/{id}/run — re-runs the view now-relative (re-validated + audited).
func (h *Handler) RunSavedView(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid saved view id"))
		return
	}
	res, err := h.svc.RunSavedView(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}
