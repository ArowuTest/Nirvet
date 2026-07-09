package detection

// §6.6 slice C HTTP: test cases + runner (DET-005), feedback stats + tuning (DET-007),
// coverage (DET-009), settings.

import (
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// AddTestCase handles POST /detections/{id}/tests.
func (h *Handler) AddTestCase(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in AddTestCaseInput
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	tc, err := h.svc.AddTestCase(r.Context(), p.TenantID, ruleID, in, p.UserID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, tc)
}

// ListTestCases handles GET /detections/{id}/tests.
func (h *Handler) ListTestCases(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	cases, err := h.svc.ListTestCases(r.Context(), p.TenantID, ruleID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list test cases"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"test_cases": cases})
}

// DeleteTestCase handles DELETE /detections/tests/{tid}.
func (h *Handler) DeleteTestCase(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("tid"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid test case id"))
		return
	}
	if err := h.svc.DeleteTestCase(r.Context(), p.TenantID, id); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// RunTests handles POST /detections/{id}/tests/run — evaluate a rule against its stored tests.
func (h *Handler) RunTests(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	run, err := h.svc.RunTests(r.Context(), p.TenantID, ruleID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// RunSamples handles POST /detections/{id}/tests/samples with {"samples":[{name,sample,expected_match}]}
// — ad-hoc evaluation against inline samples (nothing persisted).
func (h *Handler) RunSamples(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	var in struct {
		Samples []TestCase `json:"samples"`
	}
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if len(in.Samples) == 0 {
		httpx.Error(w, httpx.ErrBadRequest("at least one sample is required"))
		return
	}
	run, err := h.svc.RunSamples(r.Context(), p.TenantID, ruleID, in.Samples)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, run)
}

// FeedbackStats handles GET /detections/{id}/feedback (DET-007 per-rule tuning stats).
func (h *Handler) FeedbackStats(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	ruleID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid rule id"))
		return
	}
	stats, err := h.svc.RuleFeedbackStats(r.Context(), p.TenantID, ruleID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, stats)
}

// Tuning handles GET /detections/tuning — rules whose FP rate crosses the configured threshold.
func (h *Handler) Tuning(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	view, err := h.svc.TuningView(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"needs_tuning": view})
}

// Coverage handles GET /detections/coverage (DET-009 data-source-dependency gaps).
func (h *Handler) Coverage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	gaps, err := h.svc.CoverageGaps(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"gaps": gaps})
}

// GetSettings handles GET /detections/settings.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	set, err := h.svc.Settings(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}

// SetSettings handles PUT /detections/settings.
func (h *Handler) SetSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in Settings
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	set, err := h.svc.SetSettings(r.Context(), p.TenantID, in)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, set)
}
