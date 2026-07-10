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

type containReq struct {
	PlaybookID uuid.UUID  `json:"playbook_id"`
	IncidentID *uuid.UUID `json:"incident_id"`
}

// FireContainment handles POST /fleet/alerts/{id}/contain — fire a SOAR containment playbook on another
// tenant's alert. The target tenant is resolved from the alert; the per-target destructive authority is
// re-evaluated in the target's context and the effect + audit land durably in the target (via the SOAR
// supervisor). The playbook id refers to the TARGET tenant's own playbook.
func (h *Handler) FireContainment(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	var in containReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	runID, status, err := h.svc.FireContainment(r.Context(), p, alertID, in.PlaybookID, in.IncidentID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"run_id": runID, "status": status})
}

// ApproveContainment handles POST /fleet/alerts/{id}/contain/{runID}/approve — approve a pending cross-tenant
// containment. The alert id re-resolves the target at approval time (fire-time re-check); four-eyes + the
// target's approver floor are enforced in the SOAR service.
func (h *Handler) ApproveContainment(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	runID, err := uuid.Parse(r.PathValue("runID"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	rID, status, err := h.svc.ApproveContainment(r.Context(), p, alertID, runID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"run_id": rID, "status": status})
}

// RejectContainment handles POST /fleet/alerts/{id}/contain/{runID}/reject — cancel a pending cross-tenant
// containment (fail-safe; no effect fires). Same fleet gate as fire/approve.
func (h *Handler) RejectContainment(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid alert id"))
		return
	}
	runID, err := uuid.Parse(r.PathValue("runID"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	rID, status, err := h.svc.RejectContainment(r.Context(), p, alertID, runID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"run_id": rID, "status": status})
}
