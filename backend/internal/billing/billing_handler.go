package billing

// §6.17 #126 B-3/B-4/B-5 — the billing HTTP surface. Pricing WRITES (packages/rates/assignment) are padmin-gated in
// the router (a tenant has no path to price). Usage/invoice READS are tenant-scoped and role-gated (manager tier) in
// the router. There is deliberately NO endpoint to write usage — metering is server-derived only.

import (
	"net/http"
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
