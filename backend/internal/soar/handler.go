package soar

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Handler exposes SOAR endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SetAuthority handles POST /soar/authority with {"mode":"observe|approval|pre_authorised|emergency"}.
func (h *Handler) SetAuthority(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Mode string `json:"mode"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetAuthority(r.Context(), p.TenantID, AuthorityMode(in.Mode)); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"authority_mode": in.Mode})
}

// ListPlaybooks handles GET /playbooks.
func (h *Handler) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pbs, err := h.svc.ListPlaybooks(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list playbooks"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"playbooks": pbs})
}

// Run handles POST /playbooks/{id}/run with optional {"incident_id": "..."}.
func (h *Handler) Run(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid playbook id"))
		return
	}
	var in struct {
		IncidentID string `json:"incident_id"`
	}
	_ = httpx.Decode(r, &in)
	var incidentID *uuid.UUID
	if in.IncidentID != "" {
		if iid, err := uuid.Parse(in.IncidentID); err == nil {
			incidentID = &iid
		}
	}
	run, err := h.svc.Run(r.Context(), p, id, incidentID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, run)
}

// ListRuns handles GET /soar/runs.
func (h *Handler) ListRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	runs, err := h.svc.ListRuns(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list runs"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"runs": runs})
}

// GetRun handles GET /soar/runs/{id}.
func (h *Handler) GetRun(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	run, err := h.svc.GetRun(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// Approve handles POST /soar/runs/{id}/approve.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) { h.decision(w, r, true) }

// Reject handles POST /soar/runs/{id}/reject.
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) { h.decision(w, r, false) }

func (h *Handler) decision(w http.ResponseWriter, r *http.Request, approve bool) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	var run *PlaybookRun
	if approve {
		run, err = h.svc.Approve(r.Context(), p, id)
	} else {
		run, err = h.svc.Reject(r.Context(), p, id)
	}
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}
