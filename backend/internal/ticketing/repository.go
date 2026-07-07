package ticketing

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists ticketing connections (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Create inserts a connection within the tenant's RLS context.
func (r *Repository) Create(ctx context.Context, c *Connection) error {
	cfg, _ := json.Marshal(c.Config)
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO ticketing_connections
			   (id, tenant_id, provider, base_url, auth_user, credential, config, enabled)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			c.ID, c.TenantID, c.Provider, c.BaseURL, c.AuthUser, c.Credential, cfg, c.Enabled,
		).Scan(&c.CreatedAt)
	})
}

// List returns a tenant's connections (credential omitted on serialise).
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	var out []Connection
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, provider, base_url, auth_user, config, enabled, created_at
			   FROM ticketing_connections ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Connection
			var cfg []byte
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Provider, &c.BaseURL, &c.AuthUser, &cfg, &c.Enabled, &c.CreatedAt); err != nil {
				return err
			}
			_ = json.Unmarshal(cfg, &c.Config)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a connection.
func (r *Repository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM ticketing_connections WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// EnabledForTenant returns the tenant's first enabled connection (with credential),
// or (nil, nil) if none is configured. Runs in the tenant's RLS context.
func (r *Repository) EnabledForTenant(ctx context.Context, tenantID uuid.UUID) (*Connection, error) {
	var c Connection
	var cfg []byte
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, provider, base_url, auth_user, credential, config, enabled, created_at
			   FROM ticketing_connections WHERE enabled ORDER BY created_at ASC LIMIT 1`,
		).Scan(&c.ID, &c.TenantID, &c.Provider, &c.BaseURL, &c.AuthUser, &c.Credential, &cfg, &c.Enabled, &c.CreatedAt)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(cfg, &c.Config)
	return &c, nil
}
