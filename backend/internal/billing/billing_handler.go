package billing

// §6.17 #126 B-3/B-4/B-5 — the billing HTTP surface. Pricing WRITES (packages/rates/assignment) are padmin-gated in
// the router (a tenant has no path to price). Usage/invoice READS are tenant-scoped and role-gated (manager tier) in
// the router. There is deliberately NO endpoint to write usage — metering is server-derived only.

import (
	"net/http"
	"regexp"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

type createPackageReq struct {
	Name     string `json:"name"`
	Currency string `json:"currency"`
}

// CreatePackage handles POST /admin/billing/packages (padmin).
func (h *Handler) CreatePackage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in createPackageReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if in.Name == "" || in.Currency == "" {
		httpx.Error(w, httpx.ErrBadRequest("name and currency are required"))
		return
	}
	id, err := h.svc.CreatePackage(r.Context(), p, in.Name, in.Currency)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not create package (duplicate name?)"))
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

type setRateReq struct {
	Metric       string `json:"metric"`
	IncludedQty  int64  `json:"included_qty"`
	OverageMinor int64  `json:"overage_minor"`
}

// SetRate handles POST /admin/billing/packages/{id}/rates (padmin).
func (h *Handler) SetRate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	pkgID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid package id"))
		return
	}
	var in setRateReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if !IsMetric(Metric(in.Metric)) {
		httpx.Error(w, httpx.ErrBadRequest("unknown metric: "+in.Metric))
		return
	}
	if in.IncludedQty < 0 || in.OverageMinor < 0 {
		httpx.Error(w, httpx.ErrBadRequest("included_qty and overage_minor must be non-negative"))
		return
	}
	if err := h.svc.SetRate(r.Context(), p, pkgID, Metric(in.Metric), in.IncludedQty, in.OverageMinor); err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not set rate"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "rate_set"})
}

type assignReq struct {
	PackageID uuid.UUID `json:"package_id"`
}

// AssignPackage handles PUT /admin/tenants/{id}/billing-package (padmin).
func (h *Handler) AssignPackage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	var in assignReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.AssignPackage(r.Context(), p, tid, in.PackageID); err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not assign package"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func periodParam(r *http.Request) string {
	if v := r.URL.Query().Get("period"); v != "" {
		return v
	}
	return time.Now().UTC().Format("2006-01")
}

// validPeriod accepts a YYYY-MM period. Metering stores/queries period as a bound parameter (no injection risk), but
// a malformed period should be a clean 400 rather than a silently-empty roll.
var periodRE = regexp.MustCompile(`^\d{4}-\d{2}$`)

func validPeriod(p string) bool { return periodRE.MatchString(p) }

// Usage handles GET /billing/usage?period= — the caller's own metered usage (tenant-scoped, manager-gated).
func (h *Handler) Usage(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	roll, err := h.svc.Rollup(r.Context(), p.TenantID, periodParam(r))
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not read usage"))
		return
	}
	httpx.JSON(w, http.StatusOK, roll)
}

// ListPackages handles GET /admin/billing/packages (padmin) — the operator price book (packages + rates).
func (h *Handler) ListPackages(w http.ResponseWriter, r *http.Request) {
	pkgs, err := h.svc.ListPackages(r.Context())
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list packages"))
		return
	}
	if pkgs == nil {
		pkgs = []Package{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"packages": pkgs})
}

// ListAccounts handles GET /admin/billing/accounts (padmin) — umbrella billing accounts.
func (h *Handler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	accts, err := h.svc.ListAccounts(r.Context())
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list accounts"))
		return
	}
	if accts == nil {
		accts = []Account{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"accounts": accts})
}

// Invoice handles GET /billing/invoice?period= — the caller's own computed charges (tenant-scoped, manager-gated).
func (h *Handler) Invoice(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	inv, err := h.svc.ComputeInvoice(r.Context(), p.TenantID, periodParam(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inv)
}

// --- §6.17 slice B: umbrella accounts / modes / suspension (padmin) ---

type createAccountReq struct {
	Name               string `json:"name"`
	Currency           string `json:"currency"`
	ContractValueMinor int64  `json:"contract_value_minor"`
}

// CreateAccount handles POST /admin/billing/accounts (padmin).
func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in createAccountReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if in.Name == "" || in.Currency == "" {
		httpx.Error(w, httpx.ErrBadRequest("name and currency are required"))
		return
	}
	id, err := h.svc.CreateAccount(r.Context(), p, in.Name, in.Currency, in.ContractValueMinor)
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not create account (duplicate name?)"))
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

type setModeReq struct {
	Mode      string     `json:"mode"`
	AccountID *uuid.UUID `json:"account_id"`
}

// SetMode handles PUT /admin/tenants/{id}/billing-mode (padmin).
func (h *Handler) SetMode(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	var in setModeReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SetMode(r.Context(), p, tid, in.Mode, in.AccountID); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "mode_set"})
}

type suspendReq struct {
	Reason  string `json:"reason"`
	Suspend bool   `json:"suspend"`
}

// SuspendTenant handles POST /admin/tenants/{id}/billing-suspend (padmin).
func (h *Handler) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	tid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	var in suspendReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if err := h.svc.SuspendTenant(r.Context(), p, tid, in.Reason, in.Suspend); err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]bool{"suspended": in.Suspend})
}

// SuspendAccount handles POST /admin/billing/accounts/{id}/suspend (padmin; service requires senior + HIGH alert).
func (h *Handler) SuspendAccount(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	aid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid account id"))
		return
	}
	var in suspendReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	n, err := h.svc.SuspendAccount(r.Context(), p, aid, in.Reason, in.Suspend)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"suspended": in.Suspend, "tenants_affected": n})
}

// AccountInvoice handles GET /admin/billing/accounts/{id}/invoice?period= (manager/padmin) — the umbrella rollup.
func (h *Handler) AccountInvoice(w http.ResponseWriter, r *http.Request) {
	aid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid account id"))
		return
	}
	inv, err := h.svc.ComputeAccountInvoice(r.Context(), aid, periodParam(r))
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, inv)
}

// --- §6.17 slice C: finance export + margin (padmin) ---

// FinanceExport handles GET /admin/billing/finance-export?period=&format=csv — the per-period roll of every billable
// tenant for finance/AR reconciliation. JSON by default; ?format=csv streams a hardened text/csv attachment.
func (h *Handler) FinanceExport(w http.ResponseWriter, r *http.Request) {
	period := periodParam(r)
	if !validPeriod(period) {
		httpx.Error(w, httpx.ErrBadRequest("period must be YYYY-MM"))
		return
	}
	exp, err := h.svc.ComputeFinanceExport(r.Context(), period)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="finance-`+period+`.csv"`) // period is YYYY-MM (CRLF-safe)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(FinanceCSV(exp))
		return
	}
	httpx.JSON(w, http.StatusOK, exp)
}

// ListCostRates handles GET /admin/billing/cost-rates (padmin) — the operator's per-metric cost book.
func (h *Handler) ListCostRates(w http.ResponseWriter, r *http.Request) {
	rates, err := h.svc.ListCostRates(r.Context())
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not list cost rates"))
		return
	}
	if rates == nil {
		rates = []CostRate{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"cost_rates": rates})
}

type setCostRateReq struct {
	Metric    string `json:"metric"`
	CostMinor int64  `json:"cost_minor"`
}

// SetCostRate handles POST /admin/billing/cost-rates (padmin) — set a metric's operator cost. Audited in the service.
func (h *Handler) SetCostRate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	var in setCostRateReq
	if err := httpx.Decode(r, &in); err != nil {
		httpx.Error(w, err)
		return
	}
	if !IsMetric(Metric(in.Metric)) {
		httpx.Error(w, httpx.ErrBadRequest("unknown metric: "+in.Metric))
		return
	}
	if in.CostMinor < 0 {
		httpx.Error(w, httpx.ErrBadRequest("cost_minor must be non-negative"))
		return
	}
	if err := h.svc.SetCostRate(r.Context(), p, Metric(in.Metric), in.CostMinor); err != nil {
		httpx.Error(w, httpx.ErrBadRequest("could not set cost rate"))
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "cost_rate_set"})
}

// TenantMargin handles GET /admin/billing/tenants/{id}/margin?period= (padmin).
func (h *Handler) TenantMargin(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid tenant id"))
		return
	}
	period := periodParam(r)
	if !validPeriod(period) {
		httpx.Error(w, httpx.ErrBadRequest("period must be YYYY-MM"))
		return
	}
	m, err := h.svc.TenantMargin(r.Context(), tid, period)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, m)
}

// AccountMargin handles GET /admin/billing/accounts/{id}/margin?period= (padmin).
func (h *Handler) AccountMargin(w http.ResponseWriter, r *http.Request) {
	aid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, httpx.ErrBadRequest("invalid account id"))
		return
	}
	period := periodParam(r)
	if !validPeriod(period) {
		httpx.Error(w, httpx.ErrBadRequest("period must be YYYY-MM"))
		return
	}
	m, err := h.svc.AccountMargin(r.Context(), aid, period)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, m)
}
