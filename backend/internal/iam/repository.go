package iam

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists users.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// CreateTx inserts a user using an existing tenant-scoped transaction, so callers that must
// create a user atomically with other writes (e.g. AcceptInvitation claiming the invite + audit
// in one tx) share the single INSERT definition. The tx MUST already be in the user's tenant RLS
// context.
func (r *Repository) CreateTx(ctx context.Context, tx pgx.Tx, u *User) error {
	return tx.QueryRow(ctx,
		`INSERT INTO users (id, tenant_id, email, password_hash, role, status)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
		u.ID, u.TenantID, u.Email, u.PasswordHash, u.Role, u.Status,
	).Scan(&u.CreatedAt)
}

// Create inserts a user within the tenant's RLS context (standalone transaction).
func (r *Repository) Create(ctx context.Context, u *User) error {
	return r.db.WithTenant(ctx, u.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return r.CreateTx(ctx, tx, u)
	})
}

// FindForAuth looks up a user by email across tenants using a SECURITY DEFINER
// function — the single controlled hole in RLS, used only for authentication.
func (r *Repository) FindForAuth(ctx context.Context, email string) (*User, error) {
	var u User
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, password_hash, role, status, mfa_enabled, mfa_secret,
			        failed_login_attempts, locked_until
			   FROM auth_find_user_by_email($1)`, email,
		).Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.MFAEnabled, &u.MFASecret,
			&u.FailedLoginAttempts, &u.LockedUntil)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// SetMFAPending stages a (vault-encrypted) TOTP secret WITHOUT touching the active mfa_secret/mfa_enabled
// (M4). The active second factor is only replaced once the user proves possession via ActivateMFA.
func (r *Repository) SetMFAPending(ctx context.Context, tenantID, userID uuid.UUID, secret []byte) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET mfa_pending_secret=$2 WHERE id=$1`, userID, secret)
		return err
	})
}

// GetMFAPending returns the staged (not-yet-activated) TOTP secret, or nil if none is pending.
func (r *Repository) GetMFAPending(ctx context.Context, tenantID, userID uuid.UUID) ([]byte, error) {
	var secret []byte
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mfa_pending_secret FROM users WHERE id=$1`, userID).Scan(&secret)
	})
	return secret, err
}

// PromoteMFAPending atomically promotes the staged secret to the active one and enables MFA, clearing the
// staging column (M4). RowsAffected==0 means there was no pending secret to promote.
func (r *Repository) PromoteMFAPending(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	var ok bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE users SET mfa_secret=mfa_pending_secret, mfa_enabled=true, mfa_pending_secret=NULL
			 WHERE id=$1 AND mfa_pending_secret IS NOT NULL`, userID)
		ok = ct.RowsAffected() == 1
		return e
	})
	return ok, err
}

// SetMFAEnabled toggles MFA; disabling also clears the active AND any staged secret.
func (r *Repository) SetMFAEnabled(ctx context.Context, tenantID, userID uuid.UUID, enabled bool) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if enabled {
			_, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled=true WHERE id=$1`, userID)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled=false, mfa_secret=NULL, mfa_pending_secret=NULL WHERE id=$1`, userID)
		return err
	})
}

// RecordLoginFailure increments the account's failed-attempt counter and, once it
// reaches threshold, locks the account for lockFor. Runs in the user's tenant context
// (the caller learned tenant_id from FindForAuth). Durable + instance-independent, so
// it holds across API replicas and Redis outages (migration 0019).
func (r *Repository) RecordLoginFailure(ctx context.Context, tenantID, userID uuid.UUID, threshold int, lockFor time.Duration) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE users
			    SET failed_login_attempts = failed_login_attempts + 1,
			        locked_until = CASE WHEN failed_login_attempts + 1 >= $2
			                            THEN now() + make_interval(secs => $3)
			                            ELSE locked_until END
			  WHERE id = $1`,
			userID, threshold, int(lockFor.Seconds()))
		return err
	})
}

// ResetLoginFailures clears the failure counter and lock after a successful login.
func (r *Repository) ResetLoginFailures(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, userID)
		return err
	})
}

// UpdatePassword sets a new bcrypt hash for the user within the tenant context.
// Returns pgx.ErrNoRows if the user does not exist (or is not visible under RLS).
func (r *Repository) UpdatePassword(ctx context.Context, tenantID, userID uuid.UUID, hash string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, userID, hash)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// GetByID returns a user within the tenant context.
func (r *Repository) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*User, error) {
	var u User
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, password_hash, role, status, mfa_enabled, mfa_secret, created_at
			   FROM users WHERE id=$1`, id,
		).Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.MFAEnabled, &u.MFASecret, &u.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}
