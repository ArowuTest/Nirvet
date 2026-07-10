package fleet

// The fleet console HTTP surface. Operator/oversight roles only — the route is role-gated to providers in the
// router, AND the resolver independently returns an empty scope for any non-provider (defense in depth). The
// scope is ALWAYS derived from the authenticated principal; there is no tenant/scope parameter a caller can
// supply to widen the read.

import (
	"net/http"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler is the fleet console HTTP surface.
type Handler struct{ svc *Service }

// NewHandler wires the fleet console handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Alerts handles GET /fleet/alerts?status=&limit= — the operator's cross-tenant alert queue. Scope is derived
// from the authenticated principal (never a query/body param); a non-oversight principal sees nothing.
func (h *Handler) Alerts(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	alerts, err := h.svc.Alerts(r.Context(), p, r.URL.Query().Get("status"), limit)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read fleet alerts"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"alerts": alerts, "count": len(alerts)})
}

type assignReq struct {
	Assignee uuid.UUID `json:"assignee"`
}

// AssignAlert handles POST /fleet/alerts/{id}/assign — assign a cross-tenant alert. The target tenant is
// resolved from the alert (never from input); the mutation + audit land in that target tenant.
func (h *Handler) AssignAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	var in assignReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AssignAlert(r.Context(), p, alertID, in.Assignee); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

type dispositionReq struct {
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

// DispositionAlert handles POST /fleet/alerts/{id}/disposition — close a cross-tenant alert with a verdict.
func (h *Handler) DispositionAlert(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	var in dispositionReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.DispositionAlert(r.Context(), p, alertID, in.Disposition, in.Reason); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "dispositioned"})
}
