package sso

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists SSO connections (tenant-scoped) and resolves them for the
// unauthenticated callback via SECURITY DEFINER functions.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Create inserts a connection within the tenant's RLS context.
func (r *Repository) Create(ctx context.Context, c *Connection) error {
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO sso_connections
			   (id, tenant_id, protocol, issuer, client_id, client_secret, redirect_uri, default_role, email_domain, enabled)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`,
			c.ID, c.TenantID, c.Protocol, c.Issuer, c.ClientID, c.ClientSecret,
			c.RedirectURI, c.DefaultRole, c.EmailDomain, c.Enabled,
		).Scan(&c.CreatedAt)
	})
}

// List returns a tenant's connections (secret omitted by the caller on serialise).
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	var out []Connection
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, protocol, issuer, client_id, redirect_uri, default_role, email_domain, enabled, created_at
			   FROM sso_connections ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Connection
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Protocol, &c.Issuer, &c.ClientID,
				&c.RedirectURI, &c.DefaultRole, &c.EmailDomain, &c.Enabled, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a connection.
func (r *Repository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM sso_connections WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// GetForCallback resolves an enabled connection (and its tenant) by id without a
// tenant context — the controlled cross-tenant read for the unauthenticated
// OIDC callback (SECURITY DEFINER sso_get_connection).
func (r *Repository) GetForCallback(ctx context.Context, id uuid.UUID) (*Connection, error) {
	var c Connection
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, protocol, issuer, client_id, client_secret, redirect_uri, default_role, email_domain, enabled
			   FROM sso_get_connection($1)`, id,
		).Scan(&c.ID, &c.TenantID, &c.Protocol, &c.Issuer, &c.ClientID, &c.ClientSecret,
			&c.RedirectURI, &c.DefaultRole, &c.EmailDomain, &c.Enabled)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindByDomain resolves an enabled connection id by email domain (login start).
func (r *Repository) FindByDomain(ctx context.Context, domain string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM sso_find_by_domain($1)`, domain).Scan(&id)
	})
	return id, err
}
