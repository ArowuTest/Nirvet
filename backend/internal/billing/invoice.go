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
	TenantID        uuid.UUID     `json:"tenant_id"`
	Period          string        `json:"period"`
	Currency        string        `json:"currency"`
	Mode            string        `json:"mode"`                        // direct | covered | comp
	BilledToAccount *uuid.UUID    `json:"billed_to_account,omitempty"` // set for covered — the payer account
	PayableByTenant bool          `json:"payable_by_tenant"`           // false for covered/comp
	Lines           []InvoiceLine `json:"lines"`
	TotalMinor      int64         `json:"total_minor"` // sum of line_minor, integer minor-units
	OverMetrics     []Metric      `json:"over_metrics"`
}

// ComputeInvoice derives the tenant's charges for a period from the metered usage and the assigned package rates.
// Pure integer arithmetic; refuses a package/tenant currency mismatch (M-4). Mode is applied HERE (not at metering):
// comp → metered but zero-charge; covered → computed but attributed to the payer account (not payable by the tenant);
// direct → payable by the tenant. No package → an empty invoice.
func (s *Service) ComputeInvoice(ctx context.Context, tenantID uuid.UUID, period string) (*Invoice, error) {
	tb, err := s.repo.readTenantBilling(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	inv := &Invoice{
		TenantID: tenantID, Period: period, Currency: tb.Currency, Mode: tb.Mode,
		BilledToAccount: tb.AccountID, PayableByTenant: tb.Mode == ModeDirect,
	}
	if tb.Mode == ModeComp {
		return inv, nil // comp: metered, zero-charge
	}
	if tb.PackageID == nil {
		return inv, nil // no package → nothing billable
	}
	pkgCur, err := s.repo.packageCurrency(ctx, *tb.PackageID)
	if err != nil {
		return nil, err
	}
	if pkgCur != tb.Currency {
		return nil, httpx.ErrConflict("billing currency mismatch: package " + pkgCur + " vs tenant " + tb.Currency) // M-4
	}
	rates, err := s.repo.rates(ctx, *tb.PackageID)
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

// AccountInvoice is the umbrella invoice: the summed charges of an account's covered tenants for a period.
type AccountInvoice struct {
	AccountID   uuid.UUID `json:"account_id"`
	Period      string    `json:"period"`
	Currency    string    `json:"currency"`
	TenantCount int       `json:"tenant_count"`
	TotalMinor  int64     `json:"total_minor"`
}

// ComputeAccountInvoice sums the overage of an account's COVERED tenants for a period. It reads ONLY the account's own
// tenants (via the account-scoped SECURITY DEFINER function) — never another account's, never all tenants — and
// refuses a covered tenant whose currency drifts from the account (no mixed-currency rollup, M-4 at the account level).
func (s *Service) ComputeAccountInvoice(ctx context.Context, accountID uuid.UUID, period string) (*AccountInvoice, error) {
	acct, err := s.repo.getAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	tenants, _, err := s.repo.accountTenants(ctx, accountID)
	if err != nil {
		return nil, err
	}
	ai := &AccountInvoice{AccountID: accountID, Period: period, Currency: acct.Currency, TenantCount: len(tenants)}
	for _, t := range tenants {
		inv, err := s.ComputeInvoice(ctx, t, period)
		if err != nil {
			return nil, err
		}
		if inv.Currency != acct.Currency {
			return nil, httpx.ErrConflict("account rollup currency mismatch for a covered tenant")
		}
		ai.TotalMinor += inv.TotalMinor
	}
	return ai, nil
}
