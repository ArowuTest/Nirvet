package compliance

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Handler exposes compliance endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Frameworks handles GET /compliance/frameworks.
func (h *Handler) Frameworks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	fws, err := h.svc.ListFrameworks(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list frameworks"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"frameworks": fws})
}

// Controls handles GET /compliance/controls?framework=.
func (h *Handler) Controls(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	fw := frameworkParam(r)
	ctrls, err := h.svc.ListControls(r.Context(), p.TenantID, fw)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list controls"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"framework": fw, "controls": ctrls})
}

// Coverage handles GET /compliance/coverage?framework= — the real, tenant-scoped assessment.
func (h *Handler) Coverage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	cov, err := h.svc.Assess(r.Context(), p.TenantID, frameworkParam(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, cov)
}

// SetStatus handles PUT /compliance/status — a manual control-status override.
func (h *Handler) SetStatus(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in SetStatusInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetControlStatus(r.Context(), p.TenantID, in, p.UserID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// frameworkParam reads ?framework=, defaulting to NIST CSF 2.0.
func frameworkParam(r *http.Request) string {
	if fw := r.URL.Query().Get("framework"); fw != "" {
		return fw
	}
	return "nist_csf_2_0"
}

// CreateFramework handles POST /compliance/frameworks — author a tenant-custom framework (COMP-002).
func (h *Handler) CreateFramework(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in FrameworkInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	f, err := h.svc.CreateFramework(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, f)
}

// UpdateFramework handles PUT /compliance/frameworks/{key} — edit an own framework's metadata/enabled.
func (h *Handler) UpdateFramework(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in FrameworkInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	f, err := h.svc.UpdateFramework(r.Context(), p.TenantID, r.PathValue("key"), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, f)
}

// DeleteFramework handles DELETE /compliance/frameworks/{key} — remove an own framework + its controls/statuses.
func (h *Handler) DeleteFramework(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if err := h.svc.DeleteFramework(r.Context(), p.TenantID, r.PathValue("key")); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// UpsertControl handles POST /compliance/controls — add/update a tenant-custom control (refinement).
func (h *Handler) UpsertControl(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in ControlInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	c, err := h.svc.UpsertControl(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

// DeleteControl handles DELETE /compliance/controls?framework=&ref= — remove a tenant-custom control.
func (h *Handler) DeleteControl(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if err := h.svc.DeleteControl(r.Context(), p.TenantID, r.URL.Query().Get("framework"), r.URL.Query().Get("ref")); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// AuditPack handles GET /compliance/audit-pack?framework= — the auditor-facing readiness artifact.
func (h *Handler) AuditPack(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pack, err := h.svc.BuildAuditPack(r.Context(), p.TenantID, frameworkParam(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, pack)
}
