package detection

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// Engine evaluates events against the tenant's active rule catalogue. Rules are
// cached per tenant with a short TTL so detection does NOT hit the database on
// every event (efficiency: the hot path stays in memory).
type Engine struct {
	repo  *Repository
	ttl   time.Duration
	log   *slog.Logger // optional; set via WithLogger for stateful-eval + reaper diagnostics
	mu    sync.Mutex
	cache map[uuid.UUID]cacheEntry
	progs map[string]cel.Program // compiled CEL programs, keyed by expression
}

type cacheEntry struct {
	rules   []Rule
	expires time.Time
}

// NewEngine builds the detection engine.
func NewEngine(repo *Repository) *Engine {
	return &Engine{repo: repo, ttl: 30 * time.Second, cache: map[uuid.UUID]cacheEntry{}, progs: map[string]cel.Program{}}
}

// Evaluate returns the rules that fire for an event.
func (e *Engine) Evaluate(ctx context.Context, tenantID uuid.UUID, ev eventstore.NormalizedEvent) ([]Match, error) {
	rules, err := e.rulesFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, r := range rules {
		fired := false
		if r.Expression != "" {
			// CEL expression rule (compiled once, cached).
			if prog := e.programFor(r.Expression); prog != nil {
				fired = EvalCEL(prog, ev)
			}
		} else {
			fired = r.Condition.Matches(ev)
		}
		if fired {
			matches = append(matches, Match{
				RuleID: r.ID, RuleName: r.Name, Severity: r.Severity,
				Confidence: r.Confidence, MITRE: r.MITRE,
			})
		}
	}
	return matches, nil
}

// programFor returns a compiled CEL program for an expression, compiling and
// caching it on first use. Returns nil on a compile error (rules are validated at
// create time, so this is a defensive skip, never a hot-path panic).
func (e *Engine) programFor(expr string) cel.Program {
	e.mu.Lock()
	if p, ok := e.progs[expr]; ok {
		e.mu.Unlock()
		return p
	}
	e.mu.Unlock()
	p, err := CompileCEL(expr)
	if err != nil {
		return nil
	}
	e.mu.Lock()
	e.progs[expr] = p
	e.mu.Unlock()
	return p
}

func (e *Engine) rulesFor(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	e.mu.Lock()
	ent, ok := e.cache[tenantID]
	e.mu.Unlock()
	if ok && time.Now().Before(ent.expires) {
		return ent.rules, nil
	}
	rules, err := e.repo.ListActive(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.cache[tenantID] = cacheEntry{rules: rules, expires: time.Now().Add(e.ttl)}
	e.mu.Unlock()
	return rules, nil
}

func (e *Engine) invalidate(tenantID uuid.UUID) {
	e.mu.Lock()
	delete(e.cache, tenantID)
	e.mu.Unlock()
}

// --- management service ---

// Service manages the rule catalogue (detection engineers).
type Service struct {
	repo   *Repository
	engine *Engine
}

// NewService builds the management service. It shares the engine so cache
// invalidation is immediate on rule changes.
func NewService(repo *Repository, engine *Engine) *Service {
	return &Service{repo: repo, engine: engine}
}

// List returns the rules visible to the tenant.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	return s.repo.List(ctx, tenantID)
}

// CreateInput creates a rule.
type CreateInput struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Confidence  int       `json:"confidence"`
	MITRE       []string  `json:"mitre"`
	Condition   Condition `json:"condition"`
	Stage       string    `json:"stage"` // optional: "draft" to author into the lifecycle; default "production"
}

// createStage validates the requested creation stage. Only draft (enter the §9.4 lifecycle) or
// production (default, immediately active — backward-compatible) may be set at creation; other stages
// are reached via Transition. Returns the resolved stage or an error.
func createStage(s string) (string, error) {
	switch s {
	case "", StageProduction:
		return StageProduction, nil
	case StageDraft:
		return StageDraft, nil
	default:
		return "", httpx.ErrBadRequest("rules may only be created in draft or production; use transitions for other stages")
	}
}

// Create validates and stores a tenant rule.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*Rule, error) {
	if in.Name == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if !ValidSeverity(in.Severity) {
		return nil, httpx.ErrBadRequest("invalid severity")
	}
	if len(in.Condition.All) == 0 && len(in.Condition.Any) == 0 {
		return nil, httpx.ErrBadRequest("condition must have at least one predicate")
	}
	// Reject (and pre-warm) regex predicates now, so a bad pattern never reaches the
	// detection hot path where it would silently never match (R3 L3).
	if err := validateCondition(in.Condition); err != nil {
		return nil, httpx.ErrBadRequest(err.Error())
	}
	stage, err := createStage(in.Stage)
	if err != nil {
		return nil, err
	}
	rule := &Rule{
		ID: uuid.New(), Name: in.Name, Description: in.Description,
		Severity: in.Severity, Confidence: in.Confidence, MITRE: in.MITRE,
		Condition: in.Condition, Enabled: true, Stage: stage,
	}
	if err := s.repo.Create(ctx, tenantID, rule); err != nil {
		return nil, httpx.ErrInternal("could not create rule")
	}
	s.engine.invalidate(tenantID)
	return rule, nil
}

// CELRuleInput creates a CEL expression rule.
type CELRuleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	MITRE       []string `json:"mitre"`
	Expression  string   `json:"expression"`
	Stage       string   `json:"stage"` // optional: "draft" or "production" (default)
}

// CreateCELRule validates that the CEL expression compiles (and yields a bool),
// then stores it as a tenant rule. A bad expression is rejected here so it never
// reaches the detection hot path (SRS §6.6, pluggable DSLs).
func (s *Service) CreateCELRule(ctx context.Context, tenantID uuid.UUID, in CELRuleInput) (*Rule, error) {
	if in.Name == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if !ValidSeverity(in.Severity) {
		return nil, httpx.ErrBadRequest("invalid severity")
	}
	if _, err := CompileCEL(in.Expression); err != nil {
		return nil, httpx.ErrBadRequest("invalid CEL expression: " + err.Error())
	}
	if in.MITRE == nil {
		in.MITRE = []string{}
	}
	stage, err := createStage(in.Stage)
	if err != nil {
		return nil, err
	}
	rule := &Rule{
		ID: uuid.New(), Name: in.Name, Description: in.Description,
		Severity: in.Severity, Confidence: in.Confidence, MITRE: in.MITRE,
		Expression: in.Expression, Enabled: true, Stage: stage,
	}
	if err := s.repo.Create(ctx, tenantID, rule); err != nil {
		return nil, httpx.ErrInternal("could not create rule")
	}
	s.engine.invalidate(tenantID)
	return rule, nil
}

// ImportSigma translates a Sigma rule (YAML) into the native Condition model and
// stores it as a tenant rule — customers bring their own detections (SRS §6.6).
func (s *Service) ImportSigma(ctx context.Context, tenantID uuid.UUID, sigmaYAML []byte) (*Rule, error) {
	in, err := ImportSigma(sigmaYAML)
	if err != nil {
		return nil, httpx.ErrBadRequest(err.Error())
	}
	return s.Create(ctx, tenantID, in)
}

// SetEnabled enables/disables a tenant rule.
func (s *Service) SetEnabled(ctx context.Context, tenantID, id uuid.UUID, enabled bool) error {
	if err := s.repo.SetEnabled(ctx, tenantID, id, enabled); err != nil {
		return httpx.ErrNotFound("rule not found")
	}
	s.engine.invalidate(tenantID)
	return nil
}
