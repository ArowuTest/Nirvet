package tenant

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists tenants. The tenants registry is platform-level, so it uses
// WithSystem (no tenant GUC); RBAC restricts callers to platform admins.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Create inserts a tenant.
func (r *Repository) Create(ctx context.Context, t *Tenant) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO tenants (id, name, sector, country, service_tier, isolation_tier, status)
			 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			t.ID, t.Name, t.Sector, t.Country, t.ServiceTier, t.IsolationTier, t.Status,
		).Scan(&t.CreatedAt)
	})
}

// List returns all tenants.
func (r *Repository) List(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, name, sector, country, service_tier, isolation_tier, status, created_at
			   FROM tenants ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Tenant
			if err := rows.Scan(&t.ID, &t.Name, &t.Sector, &t.Country, &t.ServiceTier,
				&t.IsolationTier, &t.Status, &t.CreatedAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one tenant by id.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	var t Tenant
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, name, sector, country, service_tier, isolation_tier, status, created_at
			   FROM tenants WHERE id=$1`, id,
		).Scan(&t.ID, &t.Name, &t.Sector, &t.Country, &t.ServiceTier, &t.IsolationTier, &t.Status, &t.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}
