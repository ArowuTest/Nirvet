// Package billing manages service tiers, entitlements and ingest quota
// enforcement (SRS §6.17, §15). It implements ingestion.QuotaChecker so the
// ingest path applies per-tenant backpressure (ADR-0003).
package billing

import (
	"context"
	"errors"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Entitlements are a tenant's contractual limits (doc 01 §7, doc 05 §3).
type Entitlements struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	Tier            string    `json:"tier"`
	EventsPerDay    int64     `json:"events_per_day"`
	MaxIntegrations int       `json:"max_integrations"`
	RetentionDays   int       `json:"retention_days"`
	IRHours         int       `json:"ir_hours"`
}

func defaults(tenantID uuid.UUID) *Entitlements {
	return &Entitlements{TenantID: tenantID, Tier: "standard", EventsPerDay: 100000, MaxIntegrations: 10, RetentionDays: 90}
}

// Repository persists entitlements and reads ingest counts (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Get returns the tenant's entitlements, or platform defaults if unset.
func (r *Repository) Get(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
	e := defaults(tenantID)
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		er := tx.QueryRow(ctx,
			`SELECT tier, events_per_day, max_integrations, retention_days, ir_hours
			   FROM entitlements WHERE tenant_id=$1`, tenantID,
		).Scan(&e.Tier, &e.EventsPerDay, &e.MaxIntegrations, &e.RetentionDays, &e.IRHours)
		if errors.Is(er, pgx.ErrNoRows) {
			return nil // keep defaults
		}
		return er
	})
	return e, err
}

// Set upserts the tenant's entitlements.
func (r *Repository) Set(ctx context.Context, e *Entitlements) error {
	return r.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO entitlements (tenant_id, tier, events_per_day, max_integrations, retention_days, ir_hours, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET tier=EXCLUDED.tier, events_per_day=EXCLUDED.events_per_day,
			   max_integrations=EXCLUDED.max_integrations, retention_days=EXCLUDED.retention_days,
			   ir_hours=EXCLUDED.ir_hours, updated_at=now()`,
			e.TenantID, e.Tier, e.EventsPerDay, e.MaxIntegrations, e.RetentionDays, e.IRHours)
		return err
	})
}

// RawCountToday counts raw events received today (the ingest meter).
func (r *Repository) RawCountToday(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM raw_events WHERE received_at >= date_trunc('day', now())`).Scan(&n)
	})
	return n, err
}

// Service is the billing/entitlements service and the ingest QuotaChecker.
type Service struct{ repo *Repository }

// NewService builds the service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// Get returns entitlements.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Entitlements, error) {
	return s.repo.Get(ctx, tenantID)
}

// Set updates entitlements.
func (s *Service) Set(ctx context.Context, tenantID uuid.UUID, in Entitlements) (*Entitlements, error) {
	in.TenantID = tenantID
	if in.EventsPerDay <= 0 {
		in.EventsPerDay = 100000
	}
	if err := s.repo.Set(ctx, &in); err != nil {
		return nil, httpx.ErrInternal("could not set entitlements")
	}
	return &in, nil
}

// WithinIngestQuota implements ingestion.QuotaChecker: today's raw count vs cap.
func (s *Service) WithinIngestQuota(ctx context.Context, tenantID uuid.UUID, addBytes int64) (bool, error) {
	ent, err := s.repo.Get(ctx, tenantID)
	if err != nil {
		return true, err // fail-open on error (availability) — logged upstream
	}
	n, err := s.repo.RawCountToday(ctx, tenantID)
	if err != nil {
		return true, err
	}
	return n < ent.EventsPerDay, nil
}
