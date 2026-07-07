package incident

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes incident endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// PromoteFromAlert handles POST /alerts/{id}/promote.
func (h *Handler) PromoteFromAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	inc, err := h.svc.CreateFromAlert(r.Context(), p, alertID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, inc)
}

// List handles GET /incidents.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incidents": xs})
}

// Get handles GET /incidents/{id} (includes timeline).
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	inc, err := h.svc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	tl, _ := h.svc.Timeline(r.Context(), p.TenantID, id)
	httpx.JSON(w, http.StatusOK, map[string]any{"incident": inc, "timeline": tl})
}

// AddNote handles POST /incidents/{id}/notes.
func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AddNote(r.Context(), p, id, in.Note); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"status": "note_added"})
}

// Close handles POST /incidents/{id}/close.
func (h *Handler) Close(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Note string `json:"note"`
	}
	_ = httpx.Decode(r, &in)
	if err := h.svc.Close(r.Context(), p, id, in.Note); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "closed"})
}
