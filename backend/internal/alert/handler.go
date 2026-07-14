package alert

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes alert endpoints (provider SOC roles).
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// List handles GET /alerts?status= or GET /alerts?ref= — the triage queue, optionally filtered to a single
// entity (actor_ref/target_ref) for the related-alerts panels (Bucket-2 thin route).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if ref := r.URL.Query().Get("ref"); ref != "" {
		alerts, err := h.svc.ListByRef(r.Context(), p.TenantID, ref)
		if err != nil {
			httpx.Error(w, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"alerts": alerts})
		return
	}
	alerts, err := h.svc.List(r.Context(), p.TenantID, r.URL.Query().Get("status"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// ByIncident handles GET /incidents/{id}/alerts — the alerts promoted into an incident (linked-alerts panel).
func (h *Handler) ByIncident(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	alerts, err := h.svc.ListByIncident(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// Get handles GET /alerts/{id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	a, err := h.svc.Get(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, a)
}

// Assign handles POST /alerts/{id}/assign. Body may specify assignee_id; default
// is self-assign.
func (h *Handler) Assign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	var in struct {
		AssigneeID string `json:"assignee_id"`
	}
	_ = httpx.Decode(r, &in)
	assignee := p.UserID
	if in.AssigneeID != "" {
		if aid, err := uuid.Parse(in.AssigneeID); err == nil {
			assignee = aid
		}
	}
	if err := h.svc.Assign(r.Context(), p.TenantID, id, assignee); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

// Disposition handles POST /alerts/{id}/disposition with {"disposition":"...","reason":"..."} — the
// analyst verdict that closes the alert and feeds detection tuning (DET-007).
func (h *Handler) Disposition(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	var in struct {
		Disposition string `json:"disposition"`
		Reason      string `json:"reason"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.Disposition(r.Context(), p.TenantID, id, in.Disposition, in.Reason, p.UserID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "closed", "disposition": in.Disposition})
}
