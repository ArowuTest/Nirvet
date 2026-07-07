package iam

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists users.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Create inserts a user within the tenant's RLS context.
func (r *Repository) Create(ctx context.Context, u *User) error {
	return r.db.WithTenant(ctx, u.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO users (id, tenant_id, email, password_hash, role, status)
			 VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
			u.ID, u.TenantID, u.Email, u.PasswordHash, u.Role, u.Status,
		).Scan(&u.CreatedAt)
	})
}

// FindForAuth looks up a user by email across tenants using a SECURITY DEFINER
// function — the single controlled hole in RLS, used only for authentication.
func (r *Repository) FindForAuth(ctx context.Context, email string) (*User, error) {
	var u User
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, password_hash, role, status
			   FROM auth_find_user_by_email($1)`, email,
		).Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Role, &u.Status)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetByID returns a user within the tenant context.
func (r *Repository) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*User, error) {
	var u User
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, password_hash, role, status, created_at
			   FROM users WHERE id=$1`, id,
		).Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}
