package ai

// §6.12 AI Governance slice A — HTTP handlers. Prompt/eval routes are padmin-gated (platform content); feedback
// routes are tenant analyst routes (own tenant, RLS). Gating is applied in the router; enforcement (closed sets,
// atomic activation) lives in the service.

import (
	"net/http"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// GovernanceHandler exposes the AI-governance endpoints.
type GovernanceHandler struct{ svc *GovernanceService }

// NewGovernanceHandler builds the handler.
func NewGovernanceHandler(svc *GovernanceService) *GovernanceHandler {
	return &GovernanceHandler{svc: svc}
}

func actor(r *http.Request) *uuid.UUID {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.UserID == uuid.Nil {
		return nil
	}
	id := p.UserID
	return &id
}

// --- padmin: prompts ---

// ListPrompts handles GET /admin/ai/prompts.
func (h *GovernanceHandler) ListPrompts(w http.ResponseWriter, r *http.Request) {
	ps, err := h.svc.ListPrompts(r.Context())
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"prompts": ps})
}

// CreatePrompt handles POST /admin/ai/prompts.
func (h *GovernanceHandler) CreatePrompt(w http.ResponseWriter, r *http.Request) {
	var in PromptInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	id, err := h.svc.CreatePrompt(r.Context(), in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"id": id})
}

// ListVersions handles GET /admin/ai/prompts/{key}/versions.
func (h *GovernanceHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	vs, err := h.svc.ListVersions(r.Context(), r.PathValue("key"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"versions": vs})
}

// AddVersion handles POST /admin/ai/prompts/{key}/versions.
func (h *GovernanceHandler) AddVersion(w http.ResponseWriter, r *http.Request) {
	var in VersionInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	v, err := h.svc.AddVersion(r.Context(), r.PathValue("key"), in, actor(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, v)
}

// ActivateVersion handles POST /admin/ai/prompts/{key}/versions/{version}/activate.
func (h *GovernanceHandler) ActivateVersion(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version <= 0 {
		httpx.Error(w, httpx.ErrBadRequest("invalid version"))
		return
	}
	if err := h.svc.ActivateVersion(r.Context(), r.PathValue("key"), version); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "active", "version": version})
}

// --- padmin: eval ---

// ListCases handles GET /admin/ai/eval/cases.
func (h *GovernanceHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	cs, err := h.svc.ListCases(r.Context(), r.URL.Query().Get("suite"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"cases": cs})
}

// RunEval handles POST /admin/ai/eval/runs.
func (h *GovernanceHandler) RunEval(w http.ResponseWriter, r *http.Request) {
	var in RunInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	run, err := h.svc.RunSuite(r.Context(), in, actor(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, run)
}

// ListRuns handles GET /admin/ai/eval/runs.
func (h *GovernanceHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := h.svc.ListRuns(r.Context(), limit)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"runs": runs})
}

// GetRun handles GET /admin/ai/eval/runs/{id}.
func (h *GovernanceHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid run id"))
		return
	}
	run, err := h.svc.GetRun(r.Context(), id)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// --- tenant: feedback ---

// SubmitFeedback handles POST /ai/outputs/{ref}/feedback.
func (h *GovernanceHandler) SubmitFeedback(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in FeedbackInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	f, err := h.svc.SubmitFeedback(r.Context(), p.TenantID, r.PathValue("ref"), in, actor(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, f)
}

// ListFeedback handles GET /ai/outputs/{ref}/feedback.
func (h *GovernanceHandler) ListFeedback(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	fs, err := h.svc.ListFeedback(r.Context(), p.TenantID, r.PathValue("ref"))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"feedback": fs})
}
