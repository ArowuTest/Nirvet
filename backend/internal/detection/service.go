package detection

import (
	"context"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Engine evaluates events against the tenant's active rule catalogue. Rules are
// cached per tenant with a short TTL so detection does NOT hit the database on
// every event (efficiency: the hot path stays in memory).
type Engine struct {
	repo  *Repository
	ttl   time.Duration
	mu    sync.Mutex
	cache map[uuid.UUID]cacheEntry
}

type cacheEntry struct {
	rules   []Rule
	expires time.Time
}

// NewEngine builds the detection engine.
func NewEngine(repo *Repository) *Engine {
	return &Engine{repo: repo, ttl: 30 * time.Second, cache: map[uuid.UUID]cacheEntry{}}
}

// Evaluate returns the rules that fire for an event.
func (e *Engine) Evaluate(ctx context.Context, tenantID uuid.UUID, ev eventstore.NormalizedEvent) ([]Match, error) {
	rules, err := e.rulesFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, r := range rules {
		if r.Condition.Matches(ev) {
			matches = append(matches, Match{
				RuleID: r.ID, RuleName: r.Name, Severity: r.Severity,
				Confidence: r.Confidence, MITRE: r.MITRE,
			})
		}
	}
	return matches, nil
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
	rule := &Rule{
		ID: uuid.New(), Name: in.Name, Description: in.Description,
		Severity: in.Severity, Confidence: in.Confidence, MITRE: in.MITRE,
		Condition: in.Condition, Enabled: true,
	}
	if err := s.repo.Create(ctx, tenantID, rule); err != nil {
		return nil, httpx.ErrInternal("could not create rule")
	}
	s.engine.invalidate(tenantID)
	return rule, nil
}

// SetEnabled enables/disables a tenant rule.
func (s *Service) SetEnabled(ctx context.Context, tenantID, id uuid.UUID, enabled bool) error {
	if err := s.repo.SetEnabled(ctx, tenantID, id, enabled); err != nil {
		return httpx.ErrNotFound("rule not found")
	}
	s.engine.invalidate(tenantID)
	return nil
}
