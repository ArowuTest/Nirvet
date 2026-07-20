package billing

// §6.17 #174 Billing slice C — finance export. A per-period roll of every billable tenant's charges for finance/AR
// reconciliation (padmin only). Each tenant's line is computed by the SAME ComputeInvoice used everywhere (so the
// export can never drift from the per-tenant invoice), under that tenant's OWN RLS context; the operator aggregates
// at this layer. Terminal tenants (exported/deleted) are excluded — a tenant that has left is not billed (mirrors the
// daily metering filter). All money is integer minor-units.

import (
	"context"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FinanceRow is one tenant's billed charges for the period.
type FinanceRow struct {
	TenantID        uuid.UUID  `json:"tenant_id"`
	Mode            string     `json:"mode"` // direct | covered | comp
	Currency        string     `json:"currency"`
	PayableByTenant bool       `json:"payable_by_tenant"`
	BilledToAccount *uuid.UUID `json:"billed_to_account,omitempty"`
	TotalMinor      int64      `json:"total_minor"`
	OverMetrics     []Metric   `json:"over_metrics,omitempty"`
}

// FinanceExport is the operator's period roll: every billable tenant plus currency-keyed totals. GrossByCurrency
// sums ALL billed charges; PayableByTenantByCurrency sums only tenant-payable charges (covered/comp are the payer
// account's, not the tenant's) — so finance can reconcile tenant-direct receivables separately from account rollups.
type FinanceExport struct {
	Period                  string           `json:"period"`
	Rows                    []FinanceRow     `json:"rows"`
	GrossByCurrency         map[string]int64 `json:"gross_by_currency"`
	PayableByTenantCurrency map[string]int64 `json:"payable_by_tenant_by_currency"`
	TenantCount             int              `json:"tenant_count"`
}

// enumerateBillableTenants lists non-terminal tenants (global; WithSystem). Excludes exported/deleted.
func (r *Repository) enumerateBillableTenants(ctx context.Context) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM tenants WHERE status NOT IN ('exported','deleted') ORDER BY id`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// ComputeFinanceExport builds the period roll across all billable tenants (padmin). Currency totals are kept per
// currency (never summed across currencies — the same M-4 discipline as the invoices).
func (s *Service) ComputeFinanceExport(ctx context.Context, period string) (*FinanceExport, error) {
	tenants, err := s.repo.enumerateBillableTenants(ctx)
	if err != nil {
		return nil, err
	}
	exp := &FinanceExport{
		Period: period, TenantCount: len(tenants),
		GrossByCurrency: map[string]int64{}, PayableByTenantCurrency: map[string]int64{},
	}
	for _, t := range tenants {
		inv, err := s.ComputeInvoice(ctx, t, period)
		if err != nil {
			return nil, err
		}
		exp.Rows = append(exp.Rows, FinanceRow{
			TenantID: t, Mode: inv.Mode, Currency: inv.Currency, PayableByTenant: inv.PayableByTenant,
			BilledToAccount: inv.BilledToAccount, TotalMinor: inv.TotalMinor, OverMetrics: inv.OverMetrics,
		})
		if inv.Currency != "" {
			exp.GrossByCurrency[inv.Currency] += inv.TotalMinor
			if inv.PayableByTenant {
				exp.PayableByTenantCurrency[inv.Currency] += inv.TotalMinor
			}
		}
	}
	return exp, nil
}

// FinanceCSV renders the export as CSV. Every column is a machine value (uuid / controlled enum / integer / bool),
// so there is no free-text field and thus no CSV-formula-injection surface. CRLF line endings per RFC 4180.
func FinanceCSV(exp *FinanceExport) []byte {
	var b strings.Builder
	b.WriteString("period,tenant_id,mode,currency,payable_by_tenant,billed_to_account,total_minor,over_metrics\r\n")
	for _, r := range exp.Rows {
		acct := ""
		if r.BilledToAccount != nil {
			acct = r.BilledToAccount.String()
		}
		over := make([]string, 0, len(r.OverMetrics))
		for _, m := range r.OverMetrics {
			over = append(over, string(m))
		}
		b.WriteString(strings.Join([]string{
			exp.Period, r.TenantID.String(), r.Mode, r.Currency,
			strconv.FormatBool(r.PayableByTenant), acct, strconv.FormatInt(r.TotalMinor, 10),
			strings.Join(over, ";"),
		}, ","))
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
