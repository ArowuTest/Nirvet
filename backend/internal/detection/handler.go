package detection

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes detection-rule management (detection engineers).
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// List handles GET /detections.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rules, err := h.svc.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list rules"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// Create handles POST /detections.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CreateInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	rule, err := h.svc.Create(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, rule)
}

// SetEnabled handles POST /detections/{id}/enabled with body {"enabled":bool}.
func (h *Handler) SetEnabled(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetEnabled(r.Context(), p.TenantID, id, in.Enabled); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"enabled": in.Enabled})
}
