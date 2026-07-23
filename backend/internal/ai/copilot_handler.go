package ai

// HTTP surface for the AI copilot workspace (B1). All routes are analyst-usable (aiProvider tier) and the message
// route is AI-rate-limited at the mux. Sessions are private to the caller (enforced in the service via user_id).

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// CreateCopilotSession handles POST /ai/copilot/sessions.
func (h *Handler) CreateCopilotSession(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in struct {
		Title       string  `json:"title"`
		IncidentRef *string `json:"incident_ref"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	var ref *uuid.UUID
	if in.IncidentRef != nil && *in.IncidentRef != "" {
		id, err := uuid.Parse(*in.IncidentRef)
		if err != nil {
			httpx.Error(w, httpx.ErrBadRequest("invalid incident_ref"))
			return
		}
		ref = &id
	}
	sess, err := h.svc.StartCopilotSession(r.Context(), p, in.Title, ref)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, sess)
}

// ListCopilotSessions handles GET /ai/copilot/sessions.
func (h *Handler) ListCopilotSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	sessions, err := h.svc.ListCopilotSessions(r.Context(), p)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// GetCopilotSession handles GET /ai/copilot/sessions/{id}.
func (h *Handler) GetCopilotSession(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid session id"))
		return
	}
	sess, turns, err := h.svc.GetCopilotSession(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"session": sess, "turns": turns})
}

// PostCopilotMessage handles POST /ai/copilot/sessions/{id}/messages.
func (h *Handler) PostCopilotMessage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid session id"))
		return
	}
	var in struct {
		Message string `json:"message"`
		Recall  bool   `json:"recall"` // incr3 RAG: ground the answer on the most similar PAST cases (per-tenant, redacted)
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	turn, err := h.svc.Ask(r.Context(), p, id, in.Message, in.Recall)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, turn)
}

// PostCopilotAgenticMessage handles POST /ai/copilot/sessions/{id}/agentic-messages — the READ-agency turn (copilot
// completion incr2). The copilot may run up to a hard cap of bounded hunts AS the analyst to gather evidence, then
// answers. Same session/ownership + persistence + redaction chokepoint as the plain message; adds a bounded tool loop.
func (h *Handler) PostCopilotAgenticMessage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid session id"))
		return
	}
	var in struct {
		Message string `json:"message"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	turn, err := h.svc.AgenticAsk(r.Context(), p, id, in.Message)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, turn)
}

// IndexCase handles POST /ai/incidents/{id}/index-case — analyst-triggered indexing of an incident-history chunk into
// the per-tenant RAG store (copilot completion incr3). The chunk is embedded LOCALLY (no egress) and stored WithTenant
// (RLS-confined). min_role sets the field-visibility floor for later recall. Analyst-initiated, not an autonomous
// indexer (gate 2f).
func (h *Handler) IndexCase(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	var in struct {
		Chunk   string `json:"chunk"`
		MinRole string `json:"min_role"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.IndexCase(r.Context(), p, id, in.Chunk, in.MinRole); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"indexed": true})
}

// PurgeCaseEmbeddings handles DELETE /ai/incidents/{id}/case-embeddings — retention age-out / re-index of an incident's
// recall memory (copilot completion incr3). WithTenant → RLS confines the purge. Incident HARD-deletion already cascades
// (mig 0143 FK ON DELETE CASCADE); this covers the age-out case where the incident row remains.
func (h *Handler) PurgeCaseEmbeddings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid incident id"))
		return
	}
	n, err := h.svc.PurgeCaseEmbeddings(r.Context(), p, id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"purged": n})
}
