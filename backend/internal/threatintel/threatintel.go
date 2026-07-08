// Package threatintel is IOC enrichment and watchlists (SRS §6.10; doc 01 §4).
// During ingestion the enricher matches event entities against the tenant's
// watchlist and annotates matching events (feeding detection). TLP marking per
// FIRST TLP 2.0. Tenant-scoped.
package threatintel

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Indicator is an IOC / watchlist entry.
type Indicator struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Type      string    `json:"type"` // ip|domain|url|hash|email|user|host
	Value     string    `json:"value"`
	TLP       string    `json:"tlp"`   // red|amber|green|clear
	Score     int       `json:"score"` // 0-100
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

// Repository persists indicators (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Add inserts (or updates) an indicator.
func (r *Repository) Add(ctx context.Context, i *Indicator) error {
	return r.db.WithTenant(ctx, i.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO threat_indicators (id, tenant_id, type, value, tlp, score, tags)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (tenant_id, type, value) DO UPDATE SET score=EXCLUDED.score, tlp=EXCLUDED.tlp, tags=EXCLUDED.tags
			 RETURNING created_at`,
			i.ID, i.TenantID, i.Type, i.Value, i.TLP, i.Score, i.Tags,
		).Scan(&i.CreatedAt)
	})
}

// List returns the tenant's watchlist.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Indicator, error) {
	return r.query(ctx, tenantID)
}

func (r *Repository) query(ctx context.Context, tenantID uuid.UUID) ([]Indicator, error) {
	var out []Indicator
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, type, value, tlp, score, tags, created_at
			   FROM threat_indicators ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Indicator
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Type, &i.Value, &i.TLP, &i.Score, &i.Tags, &i.CreatedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}
