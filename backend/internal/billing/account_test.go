package billing

// §6.17 slice B integration + adversarial — billing modes, comp/covered invoicing, account-scoped rollup (BOLA),
// account suspension (senior + cascade + HIGH alert), and the access gate (restrict-access-keep-protecting).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

type mockAlerter struct{ n int }

func (m *mockAlerter) RaisePlatform(context.Context, uuid.UUID, string, string, string, string, string) (bool, error) {
	m.n++
	return true, nil
}

func admin() auth.Principal {
	return auth.Principal{UserID: uuid.New(), Role: auth.RolePlatformAdmin, Email: "padmin@bill"}
}

// comp = metered but zero-charge; covered = computed but attributed to the account, not payable by the tenant.
func TestModes_CompZeroAndCoveredAttributed(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	a := admin()
	ctx := context.Background()
	now := time.Now()

	pkg, _ := svc.CreatePackage(ctx, a, "m-"+uuid.NewString(), "NGN")
	_ = svc.SetRate(ctx, a, pkg, MetricAPIUsage, 0, 1) // ₦0.01/unit over

	// comp tenant: metered, but invoice total 0.
	comp := billTenant(t, db)
	_ = svc.AssignPackage(ctx, a, comp, pkg)
	if err := svc.SetMode(ctx, a, comp, ModeComp, nil); err != nil {
		t.Fatalf("set comp: %v", err)
	}
	if _, err := svc.RecordUsage(ctx, comp, MetricAPIUsage, 500, "api:comp", "test", now); err != nil {
		t.Fatalf("record: %v", err)
	}
	inv, _ := svc.ComputeInvoice(ctx, comp, CurrentPeriod())
	if inv.TotalMinor != 0 || inv.PayableByTenant {
		t.Fatalf("comp must be zero-charge + not payable, got total=%d payable=%v", inv.TotalMinor, inv.PayableByTenant)
	}

	// covered tenant: computed, attributed to the account, not payable by the tenant.
	acct, _ := svc.CreateAccount(ctx, a, "FG-"+uuid.NewString(), "NGN", 0)
	cov := billTenant(t, db)
	_ = svc.AssignPackage(ctx, a, cov, pkg)
	if err := svc.SetMode(ctx, a, cov, ModeCovered, &acct); err != nil {
		t.Fatalf("set covered: %v", err)
	}
	_, _ = svc.RecordUsage(ctx, cov, MetricAPIUsage, 500, "api:cov", "test", now)
	inv, _ = svc.ComputeInvoice(ctx, cov, CurrentPeriod())
	if inv.TotalMinor != 500 || inv.PayableByTenant || inv.BilledToAccount == nil || *inv.BilledToAccount != acct {
		t.Fatalf("covered must compute (500), attribute to account, not payable: %+v", inv)
	}
}

// The account rollup reads ONLY the account's own covered tenants — never another account's (the BOLA surface).
func TestAccountInvoice_ScopedToOwnTenants(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	a := admin()
	ctx := context.Background()
	now := time.Now()
	pkg, _ := svc.CreatePackage(ctx, a, "acc-"+uuid.NewString(), "NGN")
	_ = svc.SetRate(ctx, a, pkg, MetricAPIUsage, 0, 1)

	acctA, _ := svc.CreateAccount(ctx, a, "A-"+uuid.NewString(), "NGN", 0)
	acctB, _ := svc.CreateAccount(ctx, a, "B-"+uuid.NewString(), "NGN", 0)
	mk := func(acct uuid.UUID, qty int64, key string) {
		tid := billTenant(t, db)
		_ = svc.AssignPackage(ctx, a, tid, pkg)
		_ = svc.SetMode(ctx, a, tid, ModeCovered, &acct)
		_, _ = svc.RecordUsage(ctx, tid, MetricAPIUsage, qty, key, "test", now)
	}
	mk(acctA, 100, "a1")
	mk(acctA, 200, "a2")
	mk(acctB, 999, "b1")

	inv, err := svc.ComputeAccountInvoice(ctx, acctA, CurrentPeriod())
	if err != nil {
		t.Fatalf("account invoice: %v", err)
	}
	if inv.TenantCount != 2 || inv.TotalMinor != 300 {
		t.Fatalf("account A rollup must sum ONLY its own tenants (2, 300), got count=%d total=%d", inv.TenantCount, inv.TotalMinor)
	}
}

// Account suspension: requires senior, cascades access-suspend to covered tenants, raises a HIGH alert; reversible.
func TestSuspendAccount_SeniorCascadeAlert(t *testing.T) {
	db := billDB(t)
	al := &mockAlerter{}
	svc := NewService(NewRepository(db)).WithAlerter(al)
	a := admin()
	ctx := context.Background()
	acct, _ := svc.CreateAccount(ctx, a, "s-"+uuid.NewString(), "NGN", 0)
	t1 := billTenant(t, db)
	t2 := billTenant(t, db)
	_ = svc.SetMode(ctx, a, t1, ModeCovered, &acct)
	_ = svc.SetMode(ctx, a, t2, ModeCovered, &acct)

	// A non-senior actor cannot suspend an account.
	junior := auth.Principal{UserID: uuid.New(), Role: auth.RoleAnalystT1}
	if _, err := svc.SuspendAccount(ctx, junior, acct, "nonpay", true); err == nil {
		t.Fatal("account suspension must require a senior admin")
	}
	n, err := svc.SuspendAccount(ctx, a, acct, "non-payment", true)
	if err != nil || n != 2 {
		t.Fatalf("suspend should cascade to both covered tenants: n=%d err=%v", n, err)
	}
	if !svc.IsAccessSuspended(ctx, t1) || !svc.IsAccessSuspended(ctx, t2) {
		t.Fatal("covered tenants must be access-suspended after account suspend")
	}
	if al.n < 1 {
		t.Fatal("account suspension must raise a HIGH alert (high blast radius)")
	}
	// Metering still works while suspended (we keep protecting — the meter is mode/suspension-agnostic).
	if _, err := svc.RecordUsage(ctx, t1, MetricAlertCount, 1, "still:metering", "detect", time.Now()); err != nil {
		t.Fatalf("a suspended tenant must still be metered: %v", err)
	}
	// Reinstate lifts the suspension.
	if _, err := svc.SuspendAccount(ctx, a, acct, "paid", false); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if svc.IsAccessSuspended(ctx, t1) {
		t.Fatal("reinstate must clear the suspension")
	}
}

// The access gate blocks a suspended tenant's non-platform users, exempts platform staff, and never sees the ingest path.
func TestAccessGate(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	_ = svc.SuspendTenant(context.Background(), admin(), tid, "nonpay", true)

	gate := AccessGate(svc)
	final := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	call := func(role auth.Role) int {
		req := httptest.NewRequest("GET", "/x", nil).
			WithContext(auth.WithPrincipal(context.Background(), auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role}))
		rec := httptest.NewRecorder()
		final.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(auth.RoleAnalystT1); got != http.StatusForbidden {
		t.Fatalf("a suspended tenant's analyst must be blocked (403), got %d", got)
	}
	if got := call(auth.RolePlatformAdmin); got != http.StatusOK {
		t.Fatalf("platform staff must NOT be blocked by a tenant suspension, got %d", got)
	}
}

// M-1 regression: the suspension gate must sit BEFORE the role gate in a real interactive chain (the shape every
// non-padmin chain — provider, aiProvider, manager, … — is now built from). A provider analyst of a suspended
// tenant must be blocked even though the role gate would otherwise admit them; platform-management passes through.
// (The original M-1 bug was the aiProvider chain omitting the gate entirely — this proves the composed order works.)
func TestAccessGate_ComposedBeforeRoleGate(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	_ = svc.SuspendTenant(context.Background(), admin(), tid, "nonpay", true)

	providerRoles := []auth.Role{auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleAnalystT1, auth.RoleAnalystT2, auth.RoleAnalystT3, auth.RoleDetectionEng}
	// Mirror the interactive factory: gate THEN role gate (no rate limiter needed for the assertion).
	chain := httpx.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		AccessGate(svc), auth.RequireRole(providerRoles...),
	)
	call := func(role auth.Role) int {
		req := httptest.NewRequest("GET", "/x", nil).
			WithContext(auth.WithPrincipal(context.Background(), auth.Principal{UserID: uuid.New(), TenantID: tid, Role: role}))
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(auth.RoleAnalystT1); got != http.StatusForbidden {
		t.Fatalf("suspended tenant's analyst must be blocked by the gate before the role gate admits them, got %d", got)
	}
	if got := call(auth.RolePlatformAdmin); got != http.StatusOK {
		t.Fatalf("platform-management must pass the composed chain, got %d", got)
	}
}

// High regression (reviewer pass-1, follow-on): suspension must block INTERACTIVE HUMAN access only — a suspended
// tenant's SERVICE ACCOUNT (agent/connector/API telemetry, e.g. POST /ingest) must KEEP FLOWING so the tenant keeps
// being monitored (spine #1 keep-protecting). This is the invariant the M-1 chain-collapse endangered by putting the
// gate on `authed` (which carries /ingest). The exemption is structural (p.ServiceAccount), so it holds on ANY chain.
func TestAccessGate_ServiceAccountKeepsFlowing(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	_ = svc.SuspendTenant(context.Background(), admin(), tid, "nonpay", true)

	gate := AccessGate(svc)
	final := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(p auth.Principal) int {
		req := httptest.NewRequest("POST", "/ingest", nil).WithContext(auth.WithPrincipal(context.Background(), p))
		rec := httptest.NewRecorder()
		final.ServeHTTP(rec, req)
		return rec.Code
	}
	// A service account carries an ordinary role (here analyst_t1) — the machine marker, not the role, is what exempts
	// it. Same suspended tenant, same role: the machine principal flows, the human is blocked.
	sa := auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleAnalystT1, ServiceAccount: true, Email: "svc:x"}
	human := auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleAnalystT1}
	if got := call(sa); got != http.StatusOK {
		t.Fatalf("suspended tenant's SERVICE ACCOUNT ingest must keep flowing (keep-protecting), got %d", got)
	}
	if got := call(human); got != http.StatusForbidden {
		t.Fatalf("suspended tenant's HUMAN user must be blocked, got %d", got)
	}
}
