package ai

// §6.12 AI Governance slice A — orchestration: prompt lifecycle, eval-suite execution, feedback. Validation is the
// spine (purpose/label closed sets; activation archives the prior active atomically in the repo). The auditMut
// middleware records every mutation, so this layer does not hand-roll change-audit rows (same as ConfigService).

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/google/uuid"
)

// GovernanceService owns the AI-governance surface.
type GovernanceService struct {
	repo      *GovRepo
	judge     Judge
	responder Responder // slice-A default: grounded reference responder (hermetic)
	llm       Responder // dormant until a provider is wired (slice B)
}

// NewGovernanceService builds the service with the deterministic, hermetic defaults.
func NewGovernanceService(repo *GovRepo) *GovernanceService {
	return &GovernanceService{
		repo:      repo,
		judge:     DeterministicJudge{},
		responder: groundedReferenceResponder{},
		llm:       unavailableResponder{},
	}
}

// --- prompts ---

// ListPrompts returns the prompt catalogue with active-version numbers.
func (s *GovernanceService) ListPrompts(ctx context.Context) ([]Prompt, error) {
	return s.repo.ListPrompts(ctx)
}

// ListVersions returns a prompt's versions.
func (s *GovernanceService) ListVersions(ctx context.Context, key string) ([]PromptVersion, error) {
	vs, err := s.repo.ListVersions(ctx, key)
	if err == errGovNotFound {
		return nil, httpx.ErrNotFound("prompt not found")
	}
	return vs, err
}

// PromptInput is the create-prompt request.
type PromptInput struct {
	Key         string        `json:"key"`
	Title       string        `json:"title"`
	Purpose     PromptPurpose `json:"purpose"`
	Description string        `json:"description"`
}

// CreatePrompt validates and upserts a prompt.
func (s *GovernanceService) CreatePrompt(ctx context.Context, in PromptInput) (uuid.UUID, error) {
	if in.Key == "" || in.Title == "" {
		return uuid.Nil, httpx.ErrBadRequest("key and title are required")
	}
	if !PromptPurposes[in.Purpose] {
		return uuid.Nil, httpx.ErrBadRequest("unknown prompt purpose")
	}
	return s.repo.CreatePrompt(ctx, in.Key, in.Title, in.Purpose, in.Description)
}

// VersionInput is the add-version request.
type VersionInput struct {
	Body  string `json:"body"`
	Model string `json:"model"`
	Notes string `json:"notes"`
}

// AddVersion adds a draft version to a prompt.
func (s *GovernanceService) AddVersion(ctx context.Context, key string, in VersionInput, by *uuid.UUID) (PromptVersion, error) {
	if in.Body == "" {
		return PromptVersion{}, httpx.ErrBadRequest("version body is required")
	}
	v, err := s.repo.AddVersion(ctx, key, in.Body, in.Model, in.Notes, by)
	if err == errGovNotFound {
		return PromptVersion{}, httpx.ErrNotFound("prompt not found")
	}
	return v, err
}

// ActivateVersion makes a version the active one (archiving the previous active atomically).
func (s *GovernanceService) ActivateVersion(ctx context.Context, key string, version int) error {
	err := s.repo.ActivateVersion(ctx, key, version)
	if err == errGovNotFound {
		return httpx.ErrNotFound("prompt or version not found")
	}
	return err
}

// --- eval ---

// ListCases returns the enabled cases in a suite (default 'core').
func (s *GovernanceService) ListCases(ctx context.Context, suite string) ([]EvalCase, error) {
	if suite == "" {
		suite = "core"
	}
	return s.repo.ListCases(ctx, suite)
}

// RunInput selects what to evaluate.
type RunInput struct {
	Suite     string `json:"suite"`
	PromptKey string `json:"prompt_key"` // optional — pin the run to a prompt's active version
	Judge     string `json:"judge"`      // deterministic (default) | llm (dormant)
}

// RunSuite executes the suite with the chosen judge/responder, persists the run + per-case results, updates
// metrics, and returns the completed run. The deterministic judge is hermetic; 'llm' is refused until slice B.
func (s *GovernanceService) RunSuite(ctx context.Context, in RunInput, by *uuid.UUID) (EvalRun, error) {
	suite := in.Suite
	if suite == "" {
		suite = "core"
	}
	judgeKind := in.Judge
	if judgeKind == "" {
		judgeKind = "deterministic"
	}
	responder := s.responder
	if judgeKind == "llm" {
		// Dormant: make the unavailable path explicit rather than a hidden live call.
		responder = s.llm
	} else if judgeKind != "deterministic" {
		return EvalRun{}, httpx.ErrBadRequest("unknown judge (use deterministic or llm)")
	}

	cases, err := s.repo.ListCases(ctx, suite)
	if err != nil {
		return EvalRun{}, err
	}
	if len(cases) == 0 {
		return EvalRun{}, httpx.ErrBadRequest("eval suite has no enabled cases")
	}

	run := EvalRun{Suite: suite, Judge: judgeKind, StartedAt: time.Now(), CreatedBy: by, Total: len(cases)}

	// Optional prompt pin.
	var promptBody string
	if in.PromptKey != "" {
		pid, ver, body, ok, err := s.repo.ActivePrompt(ctx, in.PromptKey)
		if err != nil {
			return EvalRun{}, err
		}
		if !ok {
			return EvalRun{}, httpx.ErrBadRequest("prompt has no active version to evaluate")
		}
		run.PromptID = &pid
		run.PromptVersion = &ver
		promptBody = body
	}

	groundingFails := 0
	for _, c := range cases {
		answer, err := responder.Respond(ctx, promptBody, c)
		if err != nil {
			// The only expected error here is the dormant llm path — surface it as unavailable, don't persist.
			return EvalRun{}, httpx.ErrUnavailable("llm judge not available; configure a provider (slice B) or use judge=deterministic")
		}
		passed, score, rationale := s.judge.Grade(answer, c)
		if passed {
			run.Passed++
		} else {
			run.Failed++
			if c.Category == CatGrounding || c.Category == CatUnsupportedClaim {
				groundingFails++
			}
		}
		run.Results = append(run.Results, EvalResult{
			CaseID: c.ID, Name: c.Name, Category: c.Category, Passed: passed, Score: score, Rationale: rationale,
		})
	}
	run.PassRate = float64(run.Passed) / float64(run.Total)
	run.FinishedAt = nowPtr()

	id, err := s.repo.SaveRun(ctx, run)
	if err != nil {
		return EvalRun{}, err
	}
	run.ID = id

	metrics.AIEvalRunsTotal.Inc()
	metrics.AIEvalPassRate.Set(run.PassRate)
	if groundingFails > 0 {
		metrics.AIGroundingFailuresTotal.Add(float64(groundingFails))
	}
	return run, nil
}

// ListRuns returns recent run headers.
func (s *GovernanceService) ListRuns(ctx context.Context, limit int) ([]EvalRun, error) {
	return s.repo.ListRuns(ctx, limit)
}

// GetRun returns a run + results.
func (s *GovernanceService) GetRun(ctx context.Context, id uuid.UUID) (EvalRun, error) {
	run, ok, err := s.repo.GetRun(ctx, id)
	if err != nil {
		return EvalRun{}, err
	}
	if !ok {
		return EvalRun{}, httpx.ErrNotFound("eval run not found")
	}
	return run, nil
}

// --- feedback ---

// FeedbackInput is the submit-feedback request.
type FeedbackInput struct {
	Label FeedbackLabel `json:"label"`
	Note  string        `json:"note"`
}

// SubmitFeedback records a §11 label on a copilot output (tenant-scoped).
func (s *GovernanceService) SubmitFeedback(ctx context.Context, tenantID uuid.UUID, outputRef string, in FeedbackInput, by *uuid.UUID) (Feedback, error) {
	if outputRef == "" {
		return Feedback{}, httpx.ErrBadRequest("output reference is required")
	}
	if !FeedbackLabels[in.Label] {
		return Feedback{}, httpx.ErrBadRequest("unknown feedback label")
	}
	f, err := s.repo.AddFeedback(ctx, tenantID, outputRef, in.Label, in.Note, by)
	if err != nil {
		return Feedback{}, err
	}
	metrics.AIFeedbackTotal.WithLabelValues(string(in.Label)).Inc()
	return f, nil
}

// ListFeedback returns feedback for an output (own tenant).
func (s *GovernanceService) ListFeedback(ctx context.Context, tenantID uuid.UUID, outputRef string) ([]Feedback, error) {
	if outputRef == "" {
		return nil, httpx.ErrBadRequest("output reference is required")
	}
	return s.repo.ListFeedback(ctx, tenantID, outputRef)
}
