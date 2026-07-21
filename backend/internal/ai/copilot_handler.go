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
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	turn, err := h.svc.Ask(r.Context(), p, id, in.Message)
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
