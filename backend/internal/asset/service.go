package asset

import (
	"context"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

var validKinds = map[string]bool{
	"host": true, "user": true, "service": true, "cloud": true, "network": true, "other": true,
}
var validCriticality = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

// Service holds asset-inventory business logic.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// CreateInput registers (or updates) an asset.
type CreateInput struct {
	Ref         string   `json:"ref"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Criticality string   `json:"criticality"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
}

// Create validates and upserts an asset in the tenant (idempotent on ref).
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, in CreateInput) (*Asset, error) {
	in.Ref = strings.TrimSpace(in.Ref)
	in.Name = strings.TrimSpace(in.Name)
	if in.Ref == "" || in.Name == "" {
		return nil, httpx.ErrBadRequest("ref and name are required")
	}
	if in.Kind == "" {
		in.Kind = string(KindHost)
	}
	if !validKinds[in.Kind] {
		return nil, httpx.ErrBadRequest("invalid kind: host|user|service|cloud|network|other")
	}
	if in.Criticality == "" {
		in.Criticality = string(CritMedium)
	}
	if !validCriticality[in.Criticality] {
		return nil, httpx.ErrBadRequest("invalid criticality: low|medium|high|critical")
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	a := &Asset{
		ID: uuid.New(), TenantID: tenantID, Ref: in.Ref, Name: in.Name,
		Kind: in.Kind, Criticality: in.Criticality, Owner: in.Owner, Tags: in.Tags,
	}
	if err := s.repo.Upsert(ctx, a); err != nil {
		return nil, httpx.ErrInternal("could not save asset")
	}
	return a, nil
}

// List returns the tenant's assets.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Asset, error) {
	return s.repo.List(ctx, tenantID)
}

// Get returns one asset.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (*Asset, error) {
	a, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, httpx.ErrNotFound("asset not found")
	}
	return a, nil
}

// FindByRefs returns the assets matching the given refs (incident/evidence enrichment).
func (s *Service) FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]Asset, error) {
	return s.repo.FindByRefs(ctx, tenantID, refs)
}

var critRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// TopCriticalityForRefs returns the highest criticality (and its asset ref) among the
// assets matching refs, so the incident module can escalate on a critical asset. Found
// is false when no ref matches a known asset. Satisfies incident.AssetContext.
func (s *Service) TopCriticalityForRefs(ctx context.Context, tenantID uuid.UUID, refs []string) (string, string, bool) {
	assets, err := s.repo.FindByRefs(ctx, tenantID, refs)
	if err != nil || len(assets) == 0 {
		return "", "", false
	}
	best := assets[0]
	for _, a := range assets[1:] {
		if critRank[a.Criticality] > critRank[best.Criticality] {
			best = a
		}
	}
	return best.Criticality, best.Ref, true
}
