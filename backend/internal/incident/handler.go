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

// AtRisk handles GET /incidents/at-risk — open incidents breaching/near-breaching SLA.
func (h *Handler) AtRisk(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	xs, err := h.svc.AtRisk(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"incidents": xs})
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

// Assign handles POST /incidents/{id}/assign — hand the case to an analyst.
func (h *Handler) Assign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		AssigneeID string `json:"assignee_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	assignee, err := uuid.Parse(in.AssigneeID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid assignee_id"))
		return
	}
	if err := h.svc.Assign(r.Context(), p, id, assignee); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

// AddNote handles POST /incidents/{id}/notes with optional {"visibility":"internal|customer"}.
func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Note       string `json:"note"`
		Visibility string `json:"visibility"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AddNote(r.Context(), p, id, in.Note, in.Visibility); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"status": "note_added"})
}

// CustomerTimeline handles GET /incidents/{id}/customer-timeline — customer-visible entries only.
func (h *Handler) CustomerTimeline(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	tl, err := h.svc.CustomerTimeline(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"timeline": tl})
}

// Transition handles POST /incidents/{id}/transition with {"stage":"...","note":"..."} (CASE-002).
func (h *Handler) Transition(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Stage string `json:"stage"`
		Note  string `json:"note"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inc, err := h.svc.Transition(r.Context(), p, id, Stage(in.Stage), in.Note)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inc)
}

// Close handles POST /incidents/{id}/close with the CASE-009 closure criteria.
func (h *Handler) Close(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in ClosureInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	inc, err := h.svc.Close(r.Context(), p, id, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inc)
}
