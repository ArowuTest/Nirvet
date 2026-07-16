package soar

// HTTP surface for the D5 arm-gate decision + attestation. Read is provider (an analyst should be able to see
// whether this tenant is armed with a net or without one); write is padmin, because the attestation is what
// unlocks arming destructive response.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// GetProtectedDecision handles GET /soar/protected-targets-decision.
func (h *Handler) GetProtectedDecision(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	d, err := h.svc.ProtectedDecision(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// AckProtectedTargets handles POST /soar/protected-targets-decision/ack (platform-admin).
func (h *Handler) AckProtectedTargets(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		ConfirmedWith string `json:"confirmed_with"`
		Note          string `json:"note"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	a, err := h.svc.AckProtectedTargets(r.Context(), p, in.ConfirmedWith, in.Note)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, a)
}

// WithdrawProtectedAck handles DELETE /soar/protected-targets-decision/ack (platform-admin). Withdrawing
// re-blocks a future arm; it does not disarm an already-armed tenant.
func (h *Handler) WithdrawProtectedAck(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if err := h.svc.WithdrawProtectedTargetsAck(r.Context(), p); err != nil {
		httpx.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
