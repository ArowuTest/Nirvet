package ai

// HTTP surface for AI response proposals (S2b i3). Propose/list/reject are analyst-usable (aiProvider tier) — they
// only write/read DATA. The ACCEPT route (which promotes a proposal into a soar run) lives OUTSIDE this package
// (internal/airesponse) and is guarded at the destructive-approval floor; it cannot live here because it imports soar
// and would break check-ai-no-direct-execution.sh.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CreateProposal handles POST /ai/proposals — an analyst records an AI-recommended response as a pending data record.
func (h *Handler) CreateProposal(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		IncidentRef       string   `json:"incident_ref"`
		RecommendedAction string   `json:"recommended_action"`
		ConnectorKey      string   `json:"connector_key"`
		Rationale         string   `json:"rationale"`
		EvidenceCitations []string `json:"evidence_citations"`
		RiskClass         string   `json:"risk_class"`
		Reversible        bool     `json:"reversible"`
		ExpectedImpact    string   `json:"expected_impact"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	incidentRef, err := uuid.Parse(in.IncidentRef)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident_ref"))
		return
	}
	prop, err := h.svc.CreateProposal(r.Context(), p, ProposalInput{
		IncidentRef:       incidentRef,
		RecommendedAction: in.RecommendedAction,
		ConnectorKey:      in.ConnectorKey,
		Rationale:         in.Rationale,
		EvidenceCitations: in.EvidenceCitations,
		RiskClass:         in.RiskClass,
		Reversible:        in.Reversible,
		ExpectedImpact:    in.ExpectedImpact,
	})
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, prop)
}

// ListProposals handles GET /ai/proposals?incident_ref=... — an incident's proposals, newest first.
func (h *Handler) ListProposals(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	incidentRef, err := uuid.Parse(r.URL.Query().Get("incident_ref"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("incident_ref query parameter is required"))
		return
	}
	props, err := h.svc.ListProposalsByIncident(r.Context(), p, incidentRef)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"proposals": props})
}

// RejectProposal handles POST /ai/proposals/{id}/reject — an analyst dismisses a pending proposal (runs nothing).
func (h *Handler) RejectProposal(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid proposal id"))
		return
	}
	prop, err := h.svc.RejectProposal(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, prop)
}
