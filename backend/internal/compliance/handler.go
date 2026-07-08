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
