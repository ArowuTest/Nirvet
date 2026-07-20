package billing

// §6.17 #174 Billing slice C — margin. Margin = billed revenue − operator cost, where revenue is the tenant's
// invoice total (the overage we actually bill) and cost = Σ(metered usage × the operator's per-metric cost rate).
// ALL money is integer minor-units; there is no float. Two honesty guards keep the number truthful:
//   - CostConfigured: if no cost rate is set (all seeded at 0), cost is 0 and margin == revenue — but the flag is
//     false so the UI shows "operator cost not configured", never a misleading 100% margin.
//   - MarginBps is nil when revenue is 0 (no div-by-zero, no misleading 0%).
// NOTE ON SCOPE: the package model bills OVERAGE only (no base subscription fee is modeled), so this is margin on
// metered/overage revenue. If the operator charges a flat package fee out-of-band, true margin is higher; that base
// fee is a future revenue-model addition, deliberately NOT fabricated here.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CostRate is the operator's internal cost per unit of a metric (integer minor-units).
type CostRate struct {
	Metric    Metric `json:"metric"`
	CostMinor int64  `json:"cost_minor"`
}

// Margin is the computed margin for a tenant or account over a period.
type Margin struct {
	Period         string `json:"period"`
	Currency       string `json:"currency"`
	RevenueMinor   int64  `json:"revenue_minor"`   // billed revenue (invoice total)
	CostMinor      int64  `json:"cost_minor"`      // Σ usage × cost_rate
	MarginMinor    int64  `json:"margin_minor"`    // revenue − cost (may be negative)
	MarginBps      *int64 `json:"margin_bps"`      // margin as basis points of revenue; nil when revenue is 0
	CostConfigured bool   `json:"cost_configured"` // false ⇒ no operator cost set → margin==revenue is NOT a real 100%
}

// --- repository (global cost config via WithSystem) ---

func (r *Repository) costRates(ctx context.Context) (map[Metric]int64, error) {
	out := map[Metric]int64{}
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT metric, cost_minor FROM billing_cost_rate ORDER BY metric`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m Metric
			var c int64
			if e := rows.Scan(&m, &c); e != nil {
				return e
			}
			out[m] = c
		}
		return rows.Err()
	})
	return out, err
}

func (r *Repository) setCostRate(ctx context.Context, metric Metric, costMinor int64) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO billing_cost_rate (metric, cost_minor, updated_at) VALUES ($1,$2,now())
			 ON CONFLICT (metric) DO UPDATE SET cost_minor=EXCLUDED.cost_minor, updated_at=now()`,
			string(metric), costMinor)
		return e
	})
}

// --- service (padmin-gated) ---

// ListCostRates returns the operator's per-metric cost book (padmin read).
func (s *Service) ListCostRates(ctx context.Context) ([]CostRate, error) {
	m, err := s.repo.costRates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]CostRate, 0, len(m))
	for k, v := range m {
		out = append(out, CostRate{Metric: k, CostMinor: v})
	}
	return out, nil
}

// SetCostRate sets a metric's operator cost (padmin). Audited via the shared billing config audit.
func (s *Service) SetCostRate(ctx context.Context, actor auth.Principal, metric Metric, costMinor int64) error {
	if err := s.repo.setCostRate(ctx, metric, costMinor); err != nil {
		return err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "set_cost_rate", string(metric),
		map[string]any{"metric": metric, "cost_minor": costMinor})
	return nil
}

// costFor sums the operator cost of a tenant's metered usage for a period from the cost book, and reports whether any
// cost rate is actually configured (nonzero). Pure integer arithmetic.
func (s *Service) costFor(ctx context.Context, tenantID uuid.UUID, period string, costs map[Metric]int64) (int64, error) {
	rollup, err := s.repo.Rollup(ctx, tenantID, period)
	if err != nil {
		return 0, err
	}
	var cost int64
	for _, mt := range rollup {
		cost += mt.Total * costs[mt.Metric] // 0 for an unconfigured metric
	}
	return cost, nil
}

// anyCostConfigured reports whether the operator has set any nonzero cost (the honesty flag's basis).
func anyCostConfigured(costs map[Metric]int64) bool {
	for _, c := range costs {
		if c > 0 {
			return true
		}
	}
	return false
}

// marginBps returns margin as basis points of revenue, or nil when revenue is 0 (no div-by-zero / misleading 0%).
func marginBps(revenue, margin int64) *int64 {
	if revenue == 0 {
		return nil
	}
	bps := margin * 10000 / revenue
	return &bps
}

// TenantMargin computes margin for one tenant over a period (padmin).
func (s *Service) TenantMargin(ctx context.Context, tenantID uuid.UUID, period string) (*Margin, error) {
	inv, err := s.ComputeInvoice(ctx, tenantID, period)
	if err != nil {
		return nil, err
	}
	costs, err := s.repo.costRates(ctx)
	if err != nil {
		return nil, err
	}
	cost, err := s.costFor(ctx, tenantID, period, costs)
	if err != nil {
		return nil, err
	}
	m := &Margin{
		Period: period, Currency: inv.Currency,
		RevenueMinor: inv.TotalMinor, CostMinor: cost, MarginMinor: inv.TotalMinor - cost,
		CostConfigured: anyCostConfigured(costs),
	}
	m.MarginBps = marginBps(m.RevenueMinor, m.MarginMinor)
	return m, nil
}

// AccountMargin sums revenue AND cost across an account's covered tenants, then computes margin on the totals. Reads
// ONLY the account's own tenants (accountTenants), mirroring ComputeAccountInvoice's scoping.
func (s *Service) AccountMargin(ctx context.Context, accountID uuid.UUID, period string) (*Margin, error) {
	acct, err := s.repo.getAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	tenants, _, err := s.repo.accountTenants(ctx, accountID)
	if err != nil {
		return nil, err
	}
	costs, err := s.repo.costRates(ctx)
	if err != nil {
		return nil, err
	}
	m := &Margin{Period: period, Currency: acct.Currency, CostConfigured: anyCostConfigured(costs)}
	for _, t := range tenants {
		inv, err := s.ComputeInvoice(ctx, t, period)
		if err != nil {
			return nil, err
		}
		cost, err := s.costFor(ctx, t, period, costs)
		if err != nil {
			return nil, err
		}
		m.RevenueMinor += inv.TotalMinor
		m.CostMinor += cost
	}
	m.MarginMinor = m.RevenueMinor - m.CostMinor
	m.MarginBps = marginBps(m.RevenueMinor, m.MarginMinor)
	return m, nil
}
