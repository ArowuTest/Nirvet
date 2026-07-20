package airesponse

// HTTP surface for the AI-response accept (promote-to-run) step. The route is guarded at the destructive-approval
// floor (soarApprover: platform_admin/soc_manager) at the mux, and Accept re-enforces soc_manager+ in-service.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler is the HTTP handler for AI-response promotion.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Accept handles POST /ai/proposals/{id}/accept with body {playbook_id} — a senior promotes a pending AI proposal into
// a run through the existing soar pipeline.
func (h *Handler) Accept(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid proposal id"))
		return
	}
	var in struct {
		PlaybookID string `json:"playbook_id"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	playbookID, err := uuid.Parse(in.PlaybookID)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("playbook_id is required"))
		return
	}
	res, err := h.svc.Accept(r.Context(), p, id, playbookID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, res)
}
