// Package compliance maps platform capabilities to control frameworks and
// produces regulatory evidence (SRS §6.14, §11). Scaffold returns a capability
// coverage view for NIST CSF 2.0; production adds tenant-specific control status,
// evidence-pack export, and requires privacy/regulatory review.
package compliance

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// ControlStatus is coverage for one control/function.
type ControlStatus struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Status    string `json:"status"` // met | partial | gap
	Note      string `json:"note"`
}

// nistCSF is the platform's coverage of NIST CSF 2.0 functions, derived from
// which Nirvet capabilities are implemented.
func nistCSF() []ControlStatus {
	const f = "nist_csf_2_0"
	return []ControlStatus{
		{f, "GOVERN", "partial", "RBAC, immutable audit, authority-to-act policy; governance reporting evolving."},
		{f, "IDENTIFY", "partial", "Tenant/asset/identity context and connector inventory."},
		{f, "PROTECT", "partial", "Tenant isolation (RLS), credential vault, least-privilege scopes."},
		{f, "DETECT", "met", "Detection engine + rule catalogue, normalized events, alerting."},
		{f, "RESPOND", "met", "Incident case management, SOAR playbooks with approval, notifications."},
		{f, "RECOVER", "gap", "Recovery/continuity tracking not yet implemented in-platform."},
	}
}

// Handler exposes compliance endpoints.
type Handler struct{}

// NewHandler builds the handler.
func NewHandler() *Handler { return &Handler{} }

// Coverage handles GET /compliance/coverage?framework=nist_csf_2_0.
func (h *Handler) Coverage(w http.ResponseWriter, r *http.Request) {
	fw := r.URL.Query().Get("framework")
	if fw == "" {
		fw = "nist_csf_2_0"
	}
	if fw != "nist_csf_2_0" {
		httpx.Error(w, httpx.ErrBadRequest("only nist_csf_2_0 is available in this build"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"framework": fw, "coverage": nistCSF()})
}
