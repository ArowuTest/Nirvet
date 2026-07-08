package tenant

import (
	"context"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Service holds tenant business logic.
type Service struct {
	repo  *Repository
	cache *policyCache // memoises SLA + correlation policy for the per-alert/per-incident hot paths
}

// NewService builds the service.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo, cache: newPolicyCache(30 * time.Second)}
}

// CreateInput is the payload to create a tenant.
type CreateInput struct {
	Name          string        `json:"name"`
	Sector        string        `json:"sector"`
	Country       string        `json:"country"`
	ServiceTier   ServiceTier   `json:"service_tier"`
	IsolationTier IsolationTier `json:"isolation_tier"`
}

// Create validates and persists a new tenant (defaults: standard/pooled/onboarding).
func (s *Service) Create(ctx context.Context, in CreateInput) (*Tenant, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if in.ServiceTier == "" {
		in.ServiceTier = TierStandard
	}
	if in.IsolationTier == "" {
		in.IsolationTier = IsolationPooled
	}
	t := &Tenant{
		ID:            uuid.New(),
		Name:          in.Name,
		Sector:        in.Sector,
		Country:       in.Country,
		ServiceTier:   in.ServiceTier,
		IsolationTier: in.IsolationTier,
		Status:        StatusOnboarding,
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, err
	}
	// Seed the tenant's default governance config (profile + fail-closed catch-all authority
	// policy) so no tenant is ever unconfigured (TEN-006). Best-effort: GetProfile and
	// ResolveAuthority both lazily self-heal / fall back fail-closed if this did not land.
	_ = s.repo.SeedGovernance(ctx, t.ID)
	return t, nil
}

// List returns all tenants.
func (s *Service) List(ctx context.Context) ([]Tenant, error) { return s.repo.List(ctx) }

// Get returns a tenant by id.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	t, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, httpx.ErrNotFound("tenant not found")
	}
	return t, nil
}
