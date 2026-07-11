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

// Create validates and persists a new tenant (defaults: standard/pooled/onboarding) together with its
// fail-closed default governance, atomically (CreateSeeded) — never half-provisioned.
func (s *Service) Create(ctx context.Context, in CreateInput) (*Tenant, error) {
	t, err := s.build(in, "")
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateSeeded(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// build validates a CreateInput (defaults + fail-closed enum validation) and constructs the Tenant with an
// optional external_ref (the batch idempotency key). Shared by Create and CreateBatch so single-create and the
// batch path validate, default, and shape a tenant identically — the secure defaults cannot drift.
func (s *Service) build(in CreateInput, externalRef string) (*Tenant, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, httpx.ErrBadRequest("name is required")
	}
	if in.ServiceTier == "" {
		in.ServiceTier = TierStandard
	}
	if in.IsolationTier == "" {
		in.IsolationTier = IsolationPooled
	}
	// R6: validate the tier enums so a typo (e.g. isolation_tier:"banana") can't silently misconfigure
	// the deployment model — there is no DB CHECK on these columns.
	if !validServiceTier[in.ServiceTier] {
		return nil, httpx.ErrBadRequest("invalid service_tier")
	}
	if !validIsolationTier[in.IsolationTier] {
		return nil, httpx.ErrBadRequest("invalid isolation_tier")
	}
	return &Tenant{
		ID:            uuid.New(),
		Name:          strings.TrimSpace(in.Name),
		Sector:        in.Sector,
		Country:       in.Country,
		ServiceTier:   in.ServiceTier,
		IsolationTier: in.IsolationTier,
		Status:        StatusOnboarding,
		ExternalRef:   strings.TrimSpace(externalRef),
	}, nil
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
