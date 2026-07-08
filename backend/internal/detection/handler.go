package detection

import (
	"io"
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

// ImportSigma handles POST /detections/import/sigma with a raw Sigma YAML body.
func (h *Handler) ImportSigma(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not read body"))
		return
	}
	rule, err := h.svc.ImportSigma(r.Context(), p.TenantID, body)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, rule)
}

// CreateCEL handles POST /detections/cel — create a CEL expression rule.
func (h *Handler) CreateCEL(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in CELRuleInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	rule, err := h.svc.CreateCELRule(r.Context(), p.TenantID, in)
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

// Transition handles POST /detections/{id}/transition with {"stage":"...","note":"...","emergency":bool}
// (DET-006/010 §9.4 lifecycle).
func (h *Handler) Transition(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in struct {
		Stage     string `json:"stage"`
		Note      string `json:"note"`
		Emergency bool   `json:"emergency"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	// Emergency deploy (bypass to production) is restricted to senior roles.
	if in.Emergency && !auth.IsSenior(p.Role) {
		httpx.Error(w, httpx.ErrForbidden("emergency deploy requires a senior role"))
		return
	}
	to := in.Stage
	if in.Emergency {
		to = StageProduction
	}
	if err := h.svc.Transition(r.Context(), p.TenantID, id, to, in.Note, p.UserID, in.Emergency); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"stage": to, "emergency": in.Emergency})
}

// SetMetadata handles PUT /detections/{id}/metadata with {"owner_id":"...","source_dependencies":[...]}.
func (h *Handler) SetMetadata(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in struct {
		OwnerID            string   `json:"owner_id"`
		SourceDependencies []string `json:"source_dependencies"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	var owner *uuid.UUID
	if in.OwnerID != "" {
		o, perr := uuid.Parse(in.OwnerID)
		if perr != nil {
			httpx.Error(w, httpx.ErrBadRequest("invalid owner_id"))
			return
		}
		owner = &o
	}
	if err := h.svc.SetMetadata(r.Context(), p.TenantID, id, owner, in.SourceDependencies); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// Versions handles GET /detections/{id}/versions (DET-001 history).
func (h *Handler) Versions(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	vs, err := h.svc.Versions(r.Context(), p.TenantID, id)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list versions"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"versions": vs})
}

// Rollback handles POST /detections/{id}/rollback with {"version":N} (DET-001).
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in struct {
		Version int `json:"version"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.Rollback(r.Context(), p.TenantID, id, in.Version, p.UserID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}
