package billing

// §6.17 slice B — umbrella billing: payer accounts, billing modes, suspension, and the account-scoped rollup.
//
// Security posture:
//   - billing_mode + billing_account_id are written ONLY from padmin routes, audited (a tenant can't self-mark
//     covered/comp or re-parent — the fraud paths).
//   - The meter is untouched (RecordUsage never sees mode) — covered/comp tenants are metered identically.
//   - Suspension restricts ACCESS only (an auth-middleware gate); ingest/detection/alerting never consult it — we do
//     not turn off a customer's monitoring for non-payment.
//   - Account-level suspend is high-blast-radius: senior + reason + a HIGH alert + audit, reversible.
//   - The account rollup reads across the account's covered tenants via a SECURITY DEFINER function scoped to ONE
//     account — a payer sees only its own umbrella, never all tenants.

import (
	"context"
	"net/http"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccessGate is the suspension enforcement point (SB-4): it blocks a billing-suspended tenant's INTERACTIVE HUMAN
// users at the authenticated API. Suspension restricts human access, it does NOT go dark — so a suspended tenant KEEPS
// being protected. Two exemptions, both structural (not chain-dependent), keep that guarantee true wherever this gate
// is mounted:
//   - Platform-management (platform_admin/soc_manager) — provider SOC staff who must still manage the suspended tenant.
//   - SERVICE ACCOUNTS (p.ServiceAccount) — non-human/telemetry principals (agents, connectors, API pushes). Their
//     traffic (e.g. POST /ingest) MUST keep flowing regardless of which chain carries it, or the tenant would stop
//     being monitored — the exact keep-protecting invariant (spine #1). A machine principal is never "interactive
//     human access", so suspension does not apply to it. (Ingest also normally rides a chain, but exempting here means
//     the guarantee holds even if a future route puts an ingest handler on any gated chain — H: aiProvider/authed M-1.)
//
// Fail-open on a lookup error (a transient DB blip must not lock out a paying customer).
func AccessGate(svc *Service) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := auth.PrincipalFrom(r.Context()); ok &&
				!p.ServiceAccount && // machine/telemetry principals always flow (keep-protecting)
				p.Role != auth.RolePlatformAdmin && p.Role != auth.RoleSOCManager &&
				svc.IsAccessSuspended(r.Context(), p.TenantID) {
				httpx.Error(w, httpx.ErrForbidden("account access suspended (billing) — monitoring continues; contact billing to reinstate"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Alerter raises the HIGH alert on a high-blast-radius account suspension. *alert.Service satisfies it structurally.
type Alerter interface {
	RaisePlatform(ctx context.Context, tenantID uuid.UUID, dedupeKey, title, severity, targetRef, source string) (bool, error)
}

// WithAlerter wires the platform alerter (optional).
func (s *Service) WithAlerter(a Alerter) *Service { s.alerter = a; return s }

// BillingMode values.
const (
	ModeDirect  = "direct"
	ModeCovered = "covered"
	ModeComp    = "comp"
)

// Account is a payer / umbrella contract holder.
type Account struct {
	ID                 uuid.UUID `json:"id"`
	Name               string    `json:"name"`
	Currency           string    `json:"currency"`
	ContractValueMinor int64     `json:"contract_value_minor"`
	PaymentStatus      string    `json:"payment_status"`
	AccountStatus      string    `json:"account_status"`
}

// TenantBilling is a tenant's full billing config (package + mode + covering account + suspension).
type TenantBilling struct {
	PackageID       *uuid.UUID
	Currency        string
	Mode            string
	AccountID       *uuid.UUID
	AccessSuspended bool
}

// --- repository ---

func (r *Repository) createAccount(ctx context.Context, name, currency string, contractValue int64) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO billing_account (name, currency, contract_value_minor) VALUES ($1,$2,$3) RETURNING id`,
			name, currency, contractValue).Scan(&id)
	})
	return id, err
}

func (r *Repository) getAccount(ctx context.Context, id uuid.UUID) (*Account, error) {
	var a Account
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, name, currency, contract_value_minor, payment_status, account_status FROM billing_account WHERE id=$1`, id).
			Scan(&a.ID, &a.Name, &a.Currency, &a.ContractValueMinor, &a.PaymentStatus, &a.AccountStatus)
	})
	if err == pgx.ErrNoRows {
		return nil, httpx.ErrNotFound("billing account not found")
	}
	return &a, err
}

// setAccountStatus updates payment/account status (padmin). Empty string leaves a field unchanged.
func (r *Repository) setAccountStatus(ctx context.Context, id uuid.UUID, accountStatus, paymentStatus string) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE billing_account SET
			account_status = COALESCE(NULLIF($2,''), account_status),
			payment_status = COALESCE(NULLIF($3,''), payment_status), updated_at=now() WHERE id=$1`, id, accountStatus, paymentStatus)
		return e
	})
}

// setMode writes a tenant's billing mode + covering account + currency (padmin path, under the tenant's RLS context).
func (r *Repository) setMode(ctx context.Context, tenantID uuid.UUID, mode string, accountID *uuid.UUID, currency string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO tenant_billing (tenant_id, billing_mode, billing_account_id, currency, updated_at) VALUES ($1,$2,$3,$4,now())
			 ON CONFLICT (tenant_id) DO UPDATE SET billing_mode=EXCLUDED.billing_mode, billing_account_id=EXCLUDED.billing_account_id, currency=EXCLUDED.currency, updated_at=now()`,
			tenantID, mode, accountID, currency)
		return e
	})
}

// setSuspended flips a tenant's ACCESS suspension (does not touch ingest/detection).
func (r *Repository) setSuspended(ctx context.Context, tenantID uuid.UUID, suspended bool, reason string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO tenant_billing (tenant_id, access_suspended, suspend_reason, updated_at) VALUES ($1,$2,$3,now())
			 ON CONFLICT (tenant_id) DO UPDATE SET access_suspended=EXCLUDED.access_suspended, suspend_reason=EXCLUDED.suspend_reason, updated_at=now()`,
			tenantID, suspended, reason)
		return e
	})
}

// readTenantBilling reads a tenant's full billing config (own RLS context; defaults for an unset tenant).
func (r *Repository) readTenantBilling(ctx context.Context, tenantID uuid.UUID) (TenantBilling, error) {
	tb := TenantBilling{Currency: "NGN", Mode: ModeDirect}
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT package_id, currency, billing_mode, billing_account_id, access_suspended FROM tenant_billing WHERE tenant_id=$1`, tenantID).
			Scan(&tb.PackageID, &tb.Currency, &tb.Mode, &tb.AccountID, &tb.AccessSuspended)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return tb, err
}

// accountTenants returns ONLY the covered tenants of one account (via the account-scoped SECURITY DEFINER function —
// the one deliberate cross-tenant read; it can never return another account's tenants).
func (r *Repository) accountTenants(ctx context.Context, accountID uuid.UUID) ([]uuid.UUID, string, error) {
	var out []uuid.UUID
	var currency string
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT tenant_id, currency FROM billing_account_tenants($1)`, accountID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var t uuid.UUID
			var cur string
			if e := rows.Scan(&t, &cur); e != nil {
				return e
			}
			out = append(out, t)
			currency = cur
		}
		return rows.Err()
	})
	return out, currency, err
}

// --- service (padmin/manager routes) ---

// CreateAccount adds an umbrella payer account (padmin). Audited.
func (s *Service) CreateAccount(ctx context.Context, actor auth.Principal, name, currency string, contractValue int64) (uuid.UUID, error) {
	id, err := s.repo.createAccount(ctx, name, currency, contractValue)
	if err != nil {
		return uuid.Nil, err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "create_account", name, map[string]any{"currency": currency, "contract_value_minor": contractValue})
	return id, nil
}

// SetMode sets a tenant's billing mode (padmin). A covered tenant is pinned to its account's currency (M-4). Audited.
func (s *Service) SetMode(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, mode string, accountID *uuid.UUID) error {
	switch mode {
	case ModeDirect, ModeComp:
		accountID = nil // no covering account
		tb, _ := s.repo.readTenantBilling(ctx, tenantID)
		if err := s.repo.setMode(ctx, tenantID, mode, nil, tb.Currency); err != nil {
			return err
		}
	case ModeCovered:
		if accountID == nil {
			return httpx.ErrBadRequest("covered mode requires a billing account")
		}
		acct, err := s.repo.getAccount(ctx, *accountID)
		if err != nil {
			return err
		}
		if err := s.repo.setMode(ctx, tenantID, mode, accountID, acct.Currency); err != nil { // pin currency to account (M-4)
			return err
		}
	default:
		return httpx.ErrBadRequest("unknown billing mode: " + mode)
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "set_mode", tenantID.String(), map[string]any{"mode": mode, "account_id": accountID})
	return nil
}

// SuspendTenant / ReinstateTenant flip a single tenant's ACCESS (padmin). Ingest/detection continue.
func (s *Service) SuspendTenant(ctx context.Context, actor auth.Principal, tenantID uuid.UUID, reason string, suspend bool) error {
	if err := s.repo.setSuspended(ctx, tenantID, suspend, reason); err != nil {
		return err
	}
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "suspend_tenant", tenantID.String(), map[string]any{"suspend": suspend, "reason": reason})
	return nil
}

// SuspendAccount suspends/reinstates a whole umbrella — HIGH blast-radius (it restricts many tenants at once), so it
// requires a senior actor + reason + a HIGH alert. It restricts ACCESS for every covered tenant; it never stops their
// monitoring. Reversible.
func (s *Service) SuspendAccount(ctx context.Context, actor auth.Principal, accountID uuid.UUID, reason string, suspend bool) (int, error) {
	if !auth.IsSenior(actor.Role) {
		return 0, httpx.ErrForbidden("account-level suspension requires a senior admin")
	}
	if reason == "" {
		return 0, httpx.ErrBadRequest("a reason is required for account suspension")
	}
	tenants, _, err := s.repo.accountTenants(ctx, accountID)
	if err != nil {
		return 0, err
	}
	for _, t := range tenants {
		_ = s.repo.setSuspended(ctx, t, suspend, reason)
	}
	status := "suspended"
	if !suspend {
		status = "active"
	}
	_ = s.repo.setAccountStatus(ctx, accountID, status, "")
	_ = s.repo.writeConfigAudit(ctx, actor.UserID, "suspend_account", accountID.String(), map[string]any{"suspend": suspend, "reason": reason, "tenant_count": len(tenants)})
	if s.alerter != nil {
		verb := "SUSPENDED"
		if !suspend {
			verb = "REINSTATED"
		}
		_, _ = s.alerter.RaisePlatform(ctx, uuid.Nil, "billing-account-suspend:"+accountID.String(),
			"Umbrella account "+verb+" ("+reason+") — restricted access for covered tenants; monitoring continues",
			"high", "billing_account:"+accountID.String(), "billing")
	}
	return len(tenants), nil
}

// IsAccessSuspended reports whether a tenant's authenticated API access is suspended (the auth-middleware gate). Any
// error → NOT suspended (fail-open on access is safer than locking a paying customer out on a transient DB blip).
func (s *Service) IsAccessSuspended(ctx context.Context, tenantID uuid.UUID) bool {
	tb, err := s.repo.readTenantBilling(ctx, tenantID)
	if err != nil {
		return false
	}
	return tb.AccessSuspended
}
