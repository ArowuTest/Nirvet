package billing

// §6.17 #126 B-4 — usage rollup → overage arithmetic. ALL money is integer minor-units (int64); there is no float
// anywhere in this path. The tenant's contract currency is the invoice currency, and the package currency must match
// it (M-4) — a mismatch is refused rather than silently summing mixed currencies.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// InvoiceLine is a per-metric billing line (all quantities/money integer).
type InvoiceLine struct {
	Metric       Metric `json:"metric"`
	Usage        int64  `json:"usage"`
	Included     int64  `json:"included"`
	OverageUnits int64  `json:"overage_units"`
	OverageMinor int64  `json:"overage_minor"` // rate per unit
	LineMinor    int64  `json:"line_minor"`    // overage_units * rate, integer minor-units
}

// Invoice is a tenant's computed charges for a period.
type Invoice struct {
	TenantID    uuid.UUID     `json:"tenant_id"`
	Period      string        `json:"period"`
	Currency    string        `json:"currency"`
	Lines       []InvoiceLine `json:"lines"`
	TotalMinor  int64         `json:"total_minor"` // sum of line_minor, integer minor-units
	OverMetrics []Metric      `json:"over_metrics"`
}

// ComputeInvoice derives the tenant's charges for a period from the metered usage and the assigned package rates.
// Pure integer arithmetic; refuses a package/tenant currency mismatch (M-4). No package assigned → an empty invoice.
func (s *Service) ComputeInvoice(ctx context.Context, tenantID uuid.UUID, period string) (*Invoice, error) {
	pkgID, currency, err := s.repo.tenantBilling(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	inv := &Invoice{TenantID: tenantID, Period: period, Currency: currency}
	if pkgID == nil {
		return inv, nil // no package → nothing billable
	}
	pkgCur, err := s.repo.packageCurrency(ctx, *pkgID)
	if err != nil {
		return nil, err
	}
	if pkgCur != currency {
		return nil, httpx.ErrConflict("billing currency mismatch: package " + pkgCur + " vs tenant " + currency) // M-4
	}
	rates, err := s.repo.rates(ctx, *pkgID)
	if err != nil {
		return nil, err
	}
	rollup, err := s.repo.Rollup(ctx, tenantID, period)
	if err != nil {
		return nil, err
	}
	usage := map[Metric]int64{}
	for _, mt := range rollup {
		usage[mt.Metric] = mt.Total
	}
	for _, rt := range rates {
		u := usage[rt.Metric]
		over := u - rt.IncludedQty
		if over < 0 {
			over = 0 // usage at/below the included quantity → no overage
		}
		line := over * rt.OverageMinor // integer minor-units
		inv.Lines = append(inv.Lines, InvoiceLine{
			Metric: rt.Metric, Usage: u, Included: rt.IncludedQty,
			OverageUnits: over, OverageMinor: rt.OverageMinor, LineMinor: line,
		})
		inv.TotalMinor += line
		if over > 0 {
			inv.OverMetrics = append(inv.OverMetrics, rt.Metric) // BILL-003 overage detection
		}
	}
	return inv, nil
}
