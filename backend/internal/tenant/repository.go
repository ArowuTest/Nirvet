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
// insertTenantTx writes the tenants registry row (external_ref NULL when empty). tenants has no RLS, so it is
// safe under any tx context — WithSystem for the legacy single-write, WithTenant for the atomic seeded create.
func (r *Repository) insertTenantTx(ctx context.Context, tx pgx.Tx, t *Tenant) error {
	var ext any
	if t.ExternalRef != "" {
		ext = t.ExternalRef
	}
	return tx.QueryRow(ctx,
		`INSERT INTO tenants (id, name, sector, country, service_tier, isolation_tier, status, external_ref)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
		t.ID, t.Name, t.Sector, t.Country, t.ServiceTier, t.IsolationTier, t.Status, ext,
	).Scan(&t.CreatedAt)
}

// Create writes just the tenants row.
func (r *Repository) Create(ctx context.Context, t *Tenant) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return r.insertTenantTx(ctx, tx, t)
	})
}

// CreateSeeded writes the tenants row AND its fail-closed default governance in ONE per-tenant transaction
// (ONB-1): a new tenant is atomically created-and-configured or not created at all — never half-provisioned.
// Runs under WithTenant(t.ID) so the governance INSERTs pick up the tenant GUC; the tenants INSERT (no RLS) is
// unaffected. A duplicate external_ref raises a unique violation here (ONB-2 idempotency; the caller classifies
// it as a skipped duplicate). This is the single secure creation path shared by single-create and the batch.
func (r *Repository) CreateSeeded(ctx context.Context, t *Tenant) error {
	return r.db.WithTenant(ctx, t.ID, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.insertTenantTx(ctx, tx, t); err != nil {
			return err
		}
		return r.seedGovernanceTx(ctx, tx, t.ID)
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
