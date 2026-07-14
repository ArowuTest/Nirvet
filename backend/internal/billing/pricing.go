package billing

// §6.17 #126 B-3 — pricing config (packages + per-metric rates) + tenant assignment. Pricing is PLATFORM config:
// these are written ONLY from the padmin-gated route (a tenant has no path here), and every change is audited (the
// §6.18 protected-class posture applied to money). All money is integer minor-units.

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Rate is a per-metric price line in a package.
type Rate struct {
	Metric       Metric `json:"metric"`
	IncludedQty  int64  `json:"included_qty"`
	OverageMinor int64  `json:"overage_minor"` // price per unit over, integer minor-units
}

// Package is a commercial package with its per-metric rate lines (read model for the padmin billing screen).
type Package struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Currency string    `json:"currency"`
	Rates    []Rate    `json:"rates"`
}

// --- repository (global config via WithSystem; tenant assignment via WithTenant) ---

func (r *Repository) createPackage(ctx context.Context, name, currency string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO billing_package (name, currency) VALUES ($1,$2) RETURNING id`, name, currency).Scan(&id)
	})
	return id, err
}

func (r *Repository) setRate(ctx context.Context, packageID uuid.UUID, metric Metric, included, overageMinor int64) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO billing_rate (package_id, metric, included_qty, overage_minor, updated_at) VALUES ($1,$2,$3,$4,now())
			 ON CONFLICT (package_id, metric) DO UPDATE SET included_qty=EXCLUDED.included_qty, overage_minor=EXCLUDED.overage_minor, updated_at=now()`,
			packageID, string(metric), included, overageMinor)
		return e
	})
}

func (r *Repository) packageCurrency(ctx context.Context, packageID uuid.UUID) (string, error) {
	var cur string
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT currency FROM billing_package WHERE id=$1`, packageID).Scan(&cur)
	})
	return cur, err
}

func (r *Repository) rates(ctx context.Context, packageID uuid.UUID) ([]Rate, error) {
	var out []Rate
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT metric, included_qty, overage_minor FROM billing_rate WHERE package_id=$1 ORDER BY metric`, packageID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var rt Rate
			if e := rows.Scan(&rt.Metric, &rt.IncludedQty, &rt.OverageMinor); e != nil {
				return e
			}
			out = append(out, rt)
		}
		return rows.Err()
	})
	return out, err
}

// listPackages returns every commercial package with its rate lines (padmin billing read model). Global config,
// so WithSystem. Rate lines are loaded per package (N is small — the operator's own price book).
func (r *Repository) listPackages(ctx context.Context) ([]Package, error) {
	var out []Package
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, name, currency FROM billing_package ORDER BY name`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var p Package
			if e := rows.Scan(&p.ID, &p.Name, &p.Currency); e != nil {
				return e
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		rt, e := r.rates(ctx, out[i].ID)
		if e != nil {
			return nil, e
		}
		out[i].Rates = rt
	}
	return out, nil
}

// assignPackage writes the tenant's package + contract currency (M-4) under the tenant's own RLS context.
func (r *Repository) assignPackage(ctx context.Context, tenantID, packageID uuid.UUID, currency string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO tenant_billing (tenant_id, package_id, currency, updated_at) VALUES ($1,$2,$3,now())
			 ON CONFLICT (tenant_id) DO UPDATE SET package_id=EXCLUDED.package_id, currency=EXCLUDED.currency, updated_at=now()`,
			tenantID, packageID, currency)
		return e
	})
}

// tenantBilling reads a tenant's package assignment + contract currency (own RLS context).
func (r *Repository) tenantBilling(ctx context.Context, tenantID uuid.UUID) (*uuid.UUID, string, error) {
	var pkg *uuid.UUID
	var currency string
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT package_id, currency FROM tenant_billing WHERE tenant_id=$1`, tenantID).Scan(&pkg, &currency)
		if e == pgx.ErrNoRows {
			return nil // no assignment yet
		}
		return e
	})
	return pkg, currency, err
}

func (r *Repository) writeConfigAudit(ctx context.Context, actorID uuid.UUID, action, target string, detail any) error {
	dj, _ := json.Marshal(detail)
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO billing_config_audit (actor_id, action, target, detail) VALUES ($1,$2,$3,$4)`,
			actorID, action, target, dj)
		return e
	})
}

// --- service (called only from padmin-gated routes) ---

// ListPackages returns the operator's price book (padmin read). No audit (read-only).
func (s *Service) ListPackages(ctx context.Context) ([]Package, error) {
	return s.repo.listPackages(ctx)
}

// CreatePackage adds a commercial package (padmin). Audited.
func (s *Service) CreatePackage(ctx context.Context, actor auth.Principal, name, currency string) (uuid.UUID, error) {
	id, err := s.repo.createPackage(ctx, name, currency)
	if err != nil {
		return uuid.Nil, err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "create_package", name, map[string]string{"currency": currency})
	return id, nil
}

// SetRate sets a package's per-metric rate (padmin). Audited.
func (s *Service) SetRate(ctx context.Context, actor auth.Principal, packageID uuid.UUID, metric Metric, included, overageMinor int64) error {
	if err := s.repo.setRate(ctx, packageID, metric, included, overageMinor); err != nil {
		return err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "set_rate", packageID.String(),
		map[string]any{"metric": metric, "included_qty": included, "overage_minor": overageMinor})
	return nil
}

// AssignPackage puts a tenant on a package, pinning the tenant's contract currency to the package currency (M-4).
// Padmin-only; audited.
func (s *Service) AssignPackage(ctx context.Context, actor auth.Principal, tenantID, packageID uuid.UUID) error {
	currency, err := s.repo.packageCurrency(ctx, packageID)
	if err != nil {
		return err
	}
	if err := s.repo.assignPackage(ctx, tenantID, packageID, currency); err != nil {
		return err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "assign_package", tenantID.String(),
		map[string]string{"package_id": packageID.String(), "currency": currency})
	return nil
}
