package platformadmin

// §6.18 #122 P-3 — tenant lifecycle writes. Tenant-row writes run in the target tenant's context (WithTenant, like
// the §6.1 status machine); the uniform purge is a SECURITY DEFINER function (bypasses RLS by design).

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetLegalHold flips the tenant's legal_hold flag and records the action (append-only offboarding trail).
func (r *Repository) SetLegalHold(ctx context.Context, tenantID uuid.UUID, held bool, actorID uuid.UUID, reason, action string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE tenants SET legal_hold=$2 WHERE id=$1`, tenantID, held); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO tenant_offboarding (tenant_id, action, actor_id, reason) VALUES ($1,$2,$3,$4)`,
			tenantID, action, actorID, reason)
		return e
	})
}

// IsLegalHold reports whether a tenant is on hold.
func (r *Repository) IsLegalHold(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var held bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT legal_hold FROM tenants WHERE id=$1`, tenantID).Scan(&held)
	})
	return held, err
}

// OffboardPurge runs the uniform purge routine. Returns the number of tables purged; the function RAISES if the
// tenant is on legal hold (surfaced as an error the service maps to 403).
func (r *Repository) OffboardPurge(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_offboard_purge($1)`, tenantID).Scan(&n)
	})
	return n, err
}

// RecordDeletion marks the tenant deleted and appends the certificate of destruction.
func (r *Repository) RecordDeletion(ctx context.Context, tenantID uuid.UUID, tables int, cert string, actorID uuid.UUID, reason string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE tenants SET status='deleted' WHERE id=$1`, tenantID); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO tenant_offboarding (tenant_id, action, tables_purged, cert_sha256, actor_id, reason)
			VALUES ($1,'delete',$2,$3,$4,$5)`, tenantID, tables, cert, actorID, reason)
		return e
	})
}
