package asset

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const assetCols = `id, tenant_id, ref, name, kind, criticality, owner, tags, created_at`

// Repository persists assets (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Upsert creates or updates an asset, keyed on (tenant, ref) so re-registering the
// same ref updates its attributes rather than erroring. Returns the stored row.
func (r *Repository) Upsert(ctx context.Context, a *Asset) error {
	return r.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO assets (id, tenant_id, ref, name, kind, criticality, owner, tags)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			 ON CONFLICT (tenant_id, ref) DO UPDATE
			   SET name=EXCLUDED.name, kind=EXCLUDED.kind, criticality=EXCLUDED.criticality,
			       owner=EXCLUDED.owner, tags=EXCLUDED.tags
			 RETURNING id, created_at`,
			a.ID, a.TenantID, a.Ref, a.Name, a.Kind, a.Criticality, a.Owner, a.Tags,
		).Scan(&a.ID, &a.CreatedAt)
	})
}

// List returns a tenant's assets, newest first.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Asset, error) {
	var out []Asset
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets ORDER BY created_at DESC LIMIT 500`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Asset
			if err := scan(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one asset.
func (r *Repository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Asset, error) {
	var a Asset
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scan(tx.QueryRow(ctx, `SELECT `+assetCols+` FROM assets WHERE id=$1`, id), &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetByRef returns the asset with the given ref, or (nil, nil) if none — used to
// capture the before-value when a write changes criticality (R3 M-D audit).
func (r *Repository) GetByRef(ctx context.Context, tenantID uuid.UUID, ref string) (*Asset, error) {
	var a Asset
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scan(tx.QueryRow(ctx, `SELECT `+assetCols+` FROM assets WHERE ref=$1`, ref), &a)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// FindByRefs returns the tenant's assets whose ref is in refs (incident enrichment).
func (r *Repository) FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]Asset, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var out []Asset
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// R6: rank by criticality SEMANTICALLY — a lexical `criticality DESC` sorts
		// medium>low>high>critical, surfacing the least-critical assets first to triage/AI.
		rows, err := tx.Query(ctx, `SELECT `+assetCols+` FROM assets WHERE ref = ANY($1)
			ORDER BY CASE criticality
				WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
				ref ASC`, refs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Asset
			if err := scan(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scan(s rowScanner, a *Asset) error {
	return s.Scan(&a.ID, &a.TenantID, &a.Ref, &a.Name, &a.Kind, &a.Criticality, &a.Owner, &a.Tags, &a.CreatedAt)
}
