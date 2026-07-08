package sso

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SAMLRepository persists SAML connections (tenant-scoped) and resolves them for
// the unauthenticated ACS via a SECURITY DEFINER function.
type SAMLRepository struct{ db *database.DB }

// NewSAMLRepository builds the repository.
func NewSAMLRepository(db *database.DB) *SAMLRepository { return &SAMLRepository{db: db} }

// Create inserts a connection within the tenant's RLS context.
func (r *SAMLRepository) Create(ctx context.Context, c *SAMLConnection) error {
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO saml_connections
			   (id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, acs_url,
			    email_attribute, default_role, email_domain, enabled)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at`,
			c.ID, c.TenantID, c.IDPEntityID, c.IDPSSOURL, c.IDPCertificate, c.SPEntityID, c.ACSURL,
			c.EmailAttribute, c.DefaultRole, c.EmailDomain, c.Enabled,
		).Scan(&c.CreatedAt)
	})
}

// List returns a tenant's connections.
func (r *SAMLRepository) List(ctx context.Context, tenantID uuid.UUID) ([]SAMLConnection, error) {
	var out []SAMLConnection
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, acs_url,
			        email_attribute, default_role, email_domain, enabled, created_at
			   FROM saml_connections ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c SAMLConnection
			if err := rows.Scan(&c.ID, &c.TenantID, &c.IDPEntityID, &c.IDPSSOURL, &c.IDPCertificate,
				&c.SPEntityID, &c.ACSURL, &c.EmailAttribute, &c.DefaultRole, &c.EmailDomain, &c.Enabled, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a connection.
func (r *SAMLRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM saml_connections WHERE id=$1`, id)
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
// tenant context — the controlled cross-tenant read for the unauthenticated ACS.
func (r *SAMLRepository) GetForCallback(ctx context.Context, id uuid.UUID) (*SAMLConnection, error) {
	var c SAMLConnection
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, acs_url,
			        email_attribute, default_role, email_domain, enabled
			   FROM saml_get_connection($1)`, id,
		).Scan(&c.ID, &c.TenantID, &c.IDPEntityID, &c.IDPSSOURL, &c.IDPCertificate,
			&c.SPEntityID, &c.ACSURL, &c.EmailAttribute, &c.DefaultRole, &c.EmailDomain, &c.Enabled)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindByDomain resolves an enabled connection id by email domain.
func (r *SAMLRepository) FindByDomain(ctx context.Context, domain string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM saml_find_by_domain($1)`, domain).Scan(&id)
	})
	return id, err
}
