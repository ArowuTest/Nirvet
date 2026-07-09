// Package billing manages service tiers, entitlements and ingest quota
// enforcement (SRS §6.17, §15). It implements ingestion.QuotaChecker so the
// ingest path applies per-tenant backpressure (ADR-0003).
package billing

import (
	"context"
	"errors"
	"sync"
	"time"

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
type Service struct {
	repo  *Repository
	mu    sync.Mutex
	quota map[uuid.UUID]*quotaEntry // per-tenant cached ingest meter (R6-P1)
}

// quotaEntry caches a tenant's daily raw count + cap so the ingest quota check does not run count(*)
// over raw_events on every event (R6-P1). The DB count is refreshed once per TTL window and per day;
// between refreshes admitted events increment the cached count locally, so the meter stays close to the
// true value without a per-event scan. Brief over-admission at a refresh boundary is acceptable
// backpressure behaviour.
type quotaEntry struct {
	cap     int64
	count   int64
	day     int // year-day the count belongs to (reset at midnight)
	expires time.Time
}

const quotaCacheTTL = 10 * time.Second

// NewService builds the service.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo, quota: map[uuid.UUID]*quotaEntry{}}
}

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
	// R6: invalidate the cached quota entry so a cap change takes effect immediately. The
	// entry caches the tenant's cap alongside the count; without this a tightened cap would
	// not bind until the TTL window elapsed (a raised cap would likewise stay throttled).
	s.mu.Lock()
	delete(s.quota, tenantID)
	s.mu.Unlock()
	return &in, nil
}

// WithinIngestQuota implements ingestion.QuotaChecker: today's raw count vs cap. It uses a short-TTL
// per-tenant cache (R6-P1) so the DB count(*) runs at most once per TTL window per tenant instead of on
// every event; between refreshes an admitted event increments the cached count. Fail-open on a DB error
// (availability) — logged upstream.
func (s *Service) WithinIngestQuota(ctx context.Context, tenantID uuid.UUID, addBytes int64) (bool, error) {
	now := time.Now()
	today := now.YearDay()

	s.mu.Lock()
	e := s.quota[tenantID]
	s.mu.Unlock()

	if e == nil || now.After(e.expires) || e.day != today {
		ent, err := s.repo.Get(ctx, tenantID)
		if err != nil {
			return true, err
		}
		n, err := s.repo.RawCountToday(ctx, tenantID)
		if err != nil {
			return true, err
		}
		e = &quotaEntry{cap: ent.EventsPerDay, count: n, day: today, expires: now.Add(quotaCacheTTL)}
		s.mu.Lock()
		s.quota[tenantID] = e
		s.mu.Unlock()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check the day under the lock in case a concurrent refresh rolled it over.
	if e.day != today {
		e.count, e.day, e.expires = 0, today, now.Add(quotaCacheTTL)
	}
	if e.count >= e.cap {
		return false, nil
	}
	e.count++ // this event is being admitted (and will be persisted)
	return true, nil
}
