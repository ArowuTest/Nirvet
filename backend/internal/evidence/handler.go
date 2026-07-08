package evidence

import (
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes the evidence-pack endpoint.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Pack handles GET /incidents/{id}/evidence-pack — returns the incident's full,
// checksummed evidence bundle as a downloadable JSON document.
func (h *Handler) Pack(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, httpx.ErrUnauthorized("not authenticated"))
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	pack, err := h.svc.Build(r.Context(), p, id, time.Now())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-`+id.String()+`.json"`)
	httpx.JSON(w, http.StatusOK, pack)
}
