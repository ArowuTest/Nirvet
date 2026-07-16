package asset

import (
	"context"
	"errors"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/severity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var validKinds = map[string]bool{
	"host": true, "user": true, "service": true, "cloud": true, "network": true, "other": true,
}
var validCriticality = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

// Service holds asset-inventory business logic.
type Service struct {
	repo *Repository
	db   *database.DB // for the criticality-change audit (R3 M-D)
}

// NewService builds the service. db is used to audit criticality changes (may be nil in
// unit tests that don't exercise the audit path).
func NewService(repo *Repository, db *database.DB) *Service { return &Service{repo: repo, db: db} }

// CreateInput registers (or updates) an asset.
type CreateInput struct {
	Ref         string   `json:"ref"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Criticality string   `json:"criticality"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
}

// Create validates and upserts an asset (idempotent on ref), attributed to the caller.
// When the criticality is new or changed it writes an explicit audit entry capturing the
// before/after value, so an escalation-suppressing criticality edit is reconstructable
// (R3 M-D).
func (s *Service) Create(ctx context.Context, p auth.Principal, in CreateInput) (*Asset, error) {
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
		ID: uuid.New(), TenantID: p.TenantID, Ref: in.Ref, Name: in.Name,
		Kind: in.Kind, Criticality: in.Criticality, Owner: in.Owner, Tags: in.Tags,
	}
	// Upsert + criticality-change audit atomically: a failed audit rolls back the upsert (never a silently
	// unaudited criticality edit), and the retry re-reads the true prior value.
	if err := s.repo.UpsertWithCriticalityAudit(ctx, a, p); err != nil {
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
		// R6: only a genuine no-row is a 404; a DB/RLS error must surface as 500, not be
		// masked as "not found" (which would hide an outage and mislead the caller/on-call).
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, httpx.ErrNotFound("asset not found")
		}
		return nil, httpx.ErrInternal("could not load asset")
	}
	return a, nil
}

// FindByRefs returns the assets matching the given refs (incident/evidence enrichment).
func (s *Service) FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]Asset, error) {
	return s.repo.FindByRefs(ctx, tenantID, refs)
}

// TopCriticalityForRefs returns the highest criticality (and its asset ref) among the
// assets matching refs, so the incident module can escalate on a critical asset. Found
// is false when no ref matches a known asset. Satisfies incident.AssetContext. Asset
// criticality shares the canonical severity ordering (§10.2, internal/platform/severity).
func (s *Service) TopCriticalityForRefs(ctx context.Context, tenantID uuid.UUID, refs []string) (string, string, bool) {
	assets, err := s.repo.FindByRefs(ctx, tenantID, refs)
	if err != nil || len(assets) == 0 {
		return "", "", false
	}
	best := assets[0]
	for _, a := range assets[1:] {
		if severity.Rank(a.Criticality) > severity.Rank(best.Criticality) {
			best = a
		}
	}
	return best.Criticality, best.Ref, true
}
