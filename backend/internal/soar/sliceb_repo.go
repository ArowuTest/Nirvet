package soar

// §6.11 slice B persistence — per-tenant destructive-action settings and the global platform flags
// (kill-switch / dry-run). Settings are tenant-scoped (RLS); the platform flags are a single global row
// read/written at the system level.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordAudit writes one immutable audit row under the given tenant context (used for slice-B config
// changes, which the generic mutation middleware also covers but which merit an explicit domain record).
func (r *Repository) recordAudit(ctx context.Context, tenantID uuid.UUID, e audit.Entry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, e)
	})
}

// GetSoarSettings returns a tenant's destructive-action settings, or the seeded defaults when unset.
func (r *Repository) GetSoarSettings(ctx context.Context, tenantID uuid.UUID) (SoarSettings, error) {
	s := DefaultSoarSettings()
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT destructive_enabled, dry_run, max_class3_per_hour, max_class4_per_hour
			   FROM soar_settings WHERE tenant_id=$1`, tenantID).
			Scan(&s.DestructiveEnabled, &s.DryRun, &s.MaxClass3PerHour, &s.MaxClass4PerHour)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return s, err
}

// SetSoarSettings upserts a tenant's destructive-action settings.
func (r *Repository) SetSoarSettings(ctx context.Context, tenantID uuid.UUID, s SoarSettings) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO soar_settings (tenant_id, destructive_enabled, dry_run, max_class3_per_hour, max_class4_per_hour, updated_at)
			 VALUES ($1,$2,$3,$4,$5, now())
			 ON CONFLICT (tenant_id) DO UPDATE SET destructive_enabled=$2, dry_run=$3,
			   max_class3_per_hour=$4, max_class4_per_hour=$5, updated_at=now()`,
			tenantID, s.DestructiveEnabled, s.DryRun, s.MaxClass3PerHour, s.MaxClass4PerHour)
		return err
	})
}

// GetPlatformFlags returns the global kill-switch + dry-run flags (system-level; single row).
func (r *Repository) GetPlatformFlags(ctx context.Context) (PlatformFlags, error) {
	var f PlatformFlags
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT kill_switch, dry_run FROM soar_platform WHERE id=true`).
			Scan(&f.KillSwitch, &f.DryRun)
	})
	return f, err
}

// SetPlatformFlags updates the global kill-switch + dry-run flags (platform-admin gated in the service).
func (r *Repository) SetPlatformFlags(ctx context.Context, f PlatformFlags) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE soar_platform SET kill_switch=$1, dry_run=$2, updated_at=now() WHERE id=true`,
			f.KillSwitch, f.DryRun)
		return err
	})
}
