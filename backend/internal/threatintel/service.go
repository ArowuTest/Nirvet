package threatintel

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Match is a watchlist hit against an event entity.
type Match struct {
	Value string
	Score int
	Tags  []string
	TLP   string
}

// Enricher matches event entities against the tenant watchlist. Indicators are
// cached per tenant (short TTL) so enrichment does not hit the DB per event.
type Enricher struct {
	repo  *Repository
	ttl   time.Duration
	mu    sync.Mutex
	cache map[uuid.UUID]entry
}

type entry struct {
	inds    []Indicator
	expires time.Time
}

// NewEnricher builds the enricher.
func NewEnricher(repo *Repository) *Enricher {
	return &Enricher{repo: repo, ttl: 30 * time.Second, cache: map[uuid.UUID]entry{}}
}

// Enrich returns watchlist matches for the given candidate strings (entities).
func (e *Enricher) Enrich(ctx context.Context, tenantID uuid.UUID, candidates []string) ([]Match, error) {
	inds, err := e.indicators(ctx, tenantID)
	if err != nil || len(inds) == 0 {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Match
	for _, ind := range inds {
		lv := strings.ToLower(ind.Value)
		for _, c := range candidates {
			if c == "" {
				continue
			}
			if strings.Contains(strings.ToLower(c), lv) {
				if !seen[ind.Value] {
					seen[ind.Value] = true
					out = append(out, Match{Value: ind.Value, Score: ind.Score, Tags: ind.Tags, TLP: ind.TLP})
				}
				break
			}
		}
	}
	return out, nil
}

func (e *Enricher) indicators(ctx context.Context, tenantID uuid.UUID) ([]Indicator, error) {
	e.mu.Lock()
	ent, ok := e.cache[tenantID]
	e.mu.Unlock()
	if ok && time.Now().Before(ent.expires) {
		return ent.inds, nil
	}
	inds, err := e.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.cache[tenantID] = entry{inds: inds, expires: time.Now().Add(e.ttl)}
	e.mu.Unlock()
	return inds, nil
}

func (e *Enricher) invalidate(tenantID uuid.UUID) {
	e.mu.Lock()
	delete(e.cache, tenantID)
	e.mu.Unlock()
}

// Service manages the watchlist.
type Service struct {
	repo *Repository
	enr  *Enricher
}

// NewService builds the service (shares the enricher for cache invalidation).
func NewService(repo *Repository, enr *Enricher) *Service { return &Service{repo: repo, enr: enr} }

// AddInput adds an indicator.
type AddInput struct {
	Type  string   `json:"type"`
	Value string   `json:"value"`
	TLP   string   `json:"tlp"`
	Score int      `json:"score"`
	Tags  []string `json:"tags"`
}

// Add validates and stores an indicator.
func (s *Service) Add(ctx context.Context, tenantID uuid.UUID, in AddInput) (*Indicator, error) {
	if in.Type == "" || in.Value == "" {
		return nil, httpx.ErrBadRequest("type and value are required")
	}
	if in.TLP == "" {
		in.TLP = "amber"
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	ind := &Indicator{ID: uuid.New(), TenantID: tenantID, Type: in.Type, Value: in.Value, TLP: in.TLP, Score: in.Score, Tags: in.Tags}
	if err := s.repo.Add(ctx, ind); err != nil {
		return nil, httpx.ErrInternal("could not add indicator")
	}
	s.enr.invalidate(tenantID)
	return ind, nil
}

// List returns the watchlist.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Indicator, error) {
	return s.repo.List(ctx, tenantID)
}
